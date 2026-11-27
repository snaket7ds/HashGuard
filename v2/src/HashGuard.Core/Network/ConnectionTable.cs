using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace HashGuard.Core;

/// <summary>Where a remote address lives, as far as the Network Monitor cares.</summary>
public enum RemoteScope
{
    Unspecified,
    Loopback,
    Lan,
    Internet,
}

/// <summary>One row of the Windows TCP table, with the owning process id.</summary>
public sealed record TcpConnection(
    int Pid,
    IPAddress LocalAddress,
    int LocalPort,
    IPAddress RemoteAddress,
    int RemotePort,
    TcpState State)
{
    /// <summary>Identifies one connection across polls (a new key = a new connection).</summary>
    public string Key => $"{Pid}|{LocalAddress}|{LocalPort}|{RemoteAddress}|{RemotePort}";
}

/// <summary>MIB_TCP_STATE values.</summary>
public enum TcpState
{
    Closed = 1,
    Listen = 2,
    SynSent = 3,
    SynReceived = 4,
    Established = 5,
    FinWait1 = 6,
    FinWait2 = 7,
    CloseWait = 8,
    Closing = 9,
    LastAck = 10,
    TimeWait = 11,
    DeleteTcb = 12,
}

/// <summary>
/// Reads the system TCP connection table (iphlpapi GetExtendedTcpTable, owner-PID rows) for
/// IPv4 and IPv6. Parsing is split from the P/Invoke so it can be tested on any OS.
/// </summary>
public static class ConnectionTable
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const uint ErrorInsufficientBuffer = 122;
    private const int Tcp4RowSize = 24;
    private const int Tcp6RowSize = 56;

    /// <summary>All TCP connections on the machine; empty when not on Windows or the call fails.</summary>
    public static List<TcpConnection> ReadTcp()
    {
        var connections = new List<TcpConnection>();
        if (!OperatingSystem.IsWindows())
        {
            return connections;
        }

        var v4 = ReadTable(AfInet);
        if (v4 is not null)
        {
            connections.AddRange(ParseTcp4(v4));
        }

        var v6 = ReadTable(AfInet6);
        if (v6 is not null)
        {
            connections.AddRange(ParseTcp6(v6));
        }

        return connections;
    }

    /// <summary>
    /// True for rows the monitor shows: a real remote peer (not a listener, not loopback,
    /// not 0.0.0.0) owned by a real process (PID 0 holds TIME_WAIT leftovers).
    /// </summary>
    public static bool IsOutboundCandidate(TcpConnection connection) =>
        connection.Pid > 0
        && connection.State is not (TcpState.Listen or TcpState.Closed or TcpState.DeleteTcb or TcpState.TimeWait)
        && connection.RemotePort > 0
        && Classify(connection.RemoteAddress) is RemoteScope.Lan or RemoteScope.Internet;

    /// <summary>MIB_TCPTABLE_OWNER_PID: DWORD count, then 24-byte MIB_TCPROW_OWNER_PID rows.</summary>
    public static List<TcpConnection> ParseTcp4(ReadOnlySpan<byte> buffer)
    {
        var rows = new List<TcpConnection>();
        if (buffer.Length < 4)
        {
            return rows;
        }

        var count = BinaryPrimitives.ReadUInt32LittleEndian(buffer);
        var available = (buffer.Length - 4) / Tcp4RowSize;
        var total = (int)Math.Min(count, (uint)available);
        for (var index = 0; index < total; index++)
        {
            var row = buffer.Slice(4 + index * Tcp4RowSize, Tcp4RowSize);
            rows.Add(new TcpConnection(
                Pid: (int)BinaryPrimitives.ReadUInt32LittleEndian(row[20..]),
                LocalAddress: new IPAddress(row.Slice(4, 4)),
                LocalPort: ReadPort(row.Slice(8, 4)),
                RemoteAddress: new IPAddress(row.Slice(12, 4)),
                RemotePort: ReadPort(row.Slice(16, 4)),
                State: (TcpState)BinaryPrimitives.ReadUInt32LittleEndian(row)));
        }

        return rows;
    }

    /// <summary>
    /// MIB_TCP6TABLE_OWNER_PID: DWORD count, then 56-byte rows of local addr[16], scope, port,
    /// remote addr[16], scope, port, state, pid.
    /// </summary>
    public static List<TcpConnection> ParseTcp6(ReadOnlySpan<byte> buffer)
    {
        var rows = new List<TcpConnection>();
        if (buffer.Length < 4)
        {
            return rows;
        }

        var count = BinaryPrimitives.ReadUInt32LittleEndian(buffer);
        var available = (buffer.Length - 4) / Tcp6RowSize;
        var total = (int)Math.Min(count, (uint)available);
        for (var index = 0; index < total; index++)
        {
            var row = buffer.Slice(4 + index * Tcp6RowSize, Tcp6RowSize);
            rows.Add(new TcpConnection(
                Pid: (int)BinaryPrimitives.ReadUInt32LittleEndian(row[52..]),
                LocalAddress: new IPAddress(row[..16], BinaryPrimitives.ReadUInt32LittleEndian(row[16..])),
                LocalPort: ReadPort(row.Slice(20, 4)),
                RemoteAddress: new IPAddress(row.Slice(24, 16), BinaryPrimitives.ReadUInt32LittleEndian(row[40..])),
                RemotePort: ReadPort(row.Slice(44, 4)),
                State: (TcpState)BinaryPrimitives.ReadUInt32LittleEndian(row[48..])));
        }

        return rows;
    }

    /// <summary>The port is in network byte order in the low two bytes of the DWORD.</summary>
    private static int ReadPort(ReadOnlySpan<byte> dword) => (dword[0] << 8) | dword[1];

    public static RemoteScope Classify(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
        {
            return RemoteScope.Unspecified;
        }

        if (IPAddress.IsLoopback(address))
        {
            return RemoteScope.Loopback;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            var isLan = b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127) // carrier-grade NAT
                || b[0] >= 224; // multicast and reserved
            return isLan ? RemoteScope.Lan : RemoteScope.Internet;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6UniqueLocal || address.IsIPv6Multicast
                ? RemoteScope.Lan
                : RemoteScope.Internet;
        }

        return RemoteScope.Unspecified;
    }

    /// <summary>
    /// Full image path of a process, or null. QueryFullProcessImageName with
    /// PROCESS_QUERY_LIMITED_INFORMATION works for more processes than Process.MainModule
    /// (protected and other-bitness processes), and elevated HashGuard can read services too.
    /// </summary>
    public static string? TryGetProcessImagePath(int pid)
    {
        if (!OperatingSystem.IsWindows() || pid <= 0)
        {
            return null;
        }

        if (pid == 4)
        {
            return "System";
        }

        var handle = OpenProcess(0x1000, false, pid);
        if (handle == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var builder = new StringBuilder(1024);
            var size = builder.Capacity;
            return QueryFullProcessImageName(handle, 0, builder, ref size) ? builder.ToString(0, size) : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static byte[]? ReadTable(int addressFamily)
    {
        var size = 0;
        for (var attempt = 0; attempt < 4; attempt++)
        {
            var buffer = size > 0 ? Marshal.AllocHGlobal(size) : IntPtr.Zero;
            try
            {
                var result = GetExtendedTcpTable(buffer, ref size, false, addressFamily, TcpTableOwnerPidAll, 0);
                if (result == 0 && buffer != IntPtr.Zero)
                {
                    var bytes = new byte[size];
                    Marshal.Copy(buffer, bytes, 0, size);
                    return bytes;
                }

                if (result != ErrorInsufficientBuffer)
                {
                    return null;
                }

                // The table grew between calls; ask again with headroom.
                size += 4096;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }

        return null;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr tcpTable, ref int size, bool sort, int ipVersion, int tableClass, uint reserved);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder exeName, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
