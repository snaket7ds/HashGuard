using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace HashGuard.Core;

/// <summary>
/// One HashGuard per Windows user. The first copy owns a mutex and listens on a named pipe; a
/// later launch sends its <see cref="LaunchRequest"/> down the pipe and exits. Works when one copy
/// runs as administrator and the other doesn't: the pipe allows the user's own account, and a
/// mutex the other copy can't open counts as "already running".
/// </summary>
public sealed partial class SingleInstance : IDisposable
{
    private readonly Mutex mutex;
    private readonly string pipeName;
    private readonly CancellationTokenSource stop = new();

    private SingleInstance(Mutex mutex, string pipeName)
    {
        this.mutex = mutex;
        this.pipeName = pipeName;
    }

    /// <summary>"HashGuard.v2.{user SID}": per user, so two people signed in each get their own.</summary>
    public static string DefaultName
    {
        get
        {
            using var identity = WindowsIdentity.GetCurrent();
            return $"HashGuard.v2.{identity.User?.Value ?? Environment.UserName}";
        }
    }

    /// <summary>Becomes the running copy, or returns null when another copy already is.</summary>
    public static SingleInstance? TryClaim(string? name = null)
    {
        name ??= DefaultName;
        Mutex mutex;
        try
        {
            mutex = new Mutex(initiallyOwned: false, $"Local\\{name}", out var createdNew);
            if (!createdNew)
            {
                mutex.Dispose();
                return null;
            }
        }
        catch (UnauthorizedAccessException)
        {
            return null; // Held by a copy running as administrator.
        }

        return new SingleInstance(mutex, name);
    }

    /// <summary>
    /// Hands <paramref name="request"/> to the running copy and lets it bring its window to the
    /// front. Waits up to <paramref name="timeout"/> for a copy that is still starting.
    /// </summary>
    public static bool TrySend(LaunchRequest request, string? name = null, TimeSpan? timeout = null)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", name ?? DefaultName, PipeDirection.Out, PipeOptions.None);
            pipe.Connect(timeout ?? TimeSpan.FromSeconds(5));
            if (GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var serverPid))
            {
                // This launch was started by the user, so it may give the foreground away.
                AllowSetForegroundWindow(serverPid);
            }

            using var writer = new StreamWriter(pipe, new UTF8Encoding(false)) { AutoFlush = true };
            writer.WriteLine(request.ToMessage());
            pipe.WaitForPipeDrain();
            return true;
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Calls <paramref name="onRequest"/> (on a worker thread) for each launch that is handed over.</summary>
    public void Listen(Action<LaunchRequest> onRequest) => _ = Task.Run(() => ListenAsync(onRequest, stop.Token));

    private async Task ListenAsync(Action<LaunchRequest> onRequest, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = CreatePipe();
                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                using var reader = new StreamReader(pipe, Encoding.UTF8);
                using var readTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                readTimeout.CancelAfter(TimeSpan.FromSeconds(2));
                var line = await reader.ReadLineAsync(readTimeout.Token).ConfigureAwait(false);
                if (LaunchRequest.FromMessage(line) is { } request)
                {
                    onRequest(request);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or UnauthorizedAccessException)
            {
                // A client that hung up or stalled; wait for the next one.
                await Task.Delay(100, CancellationToken.None).ConfigureAwait(false);
            }
        }
    }

    private NamedPipeServerStream CreatePipe()
    {
        var security = new PipeSecurity();
        using var identity = WindowsIdentity.GetCurrent();
        security.AddAccessRule(new PipeAccessRule(identity.User!, PipeAccessRights.FullControl, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, security);
    }

    public void Dispose()
    {
        // The mutex is never owned: its existence is the claim, and disposing the last handle ends it.
        stop.Cancel();
        mutex.Dispose();
        stop.Dispose();
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeServerProcessId(nint pipe, out uint serverProcessId);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AllowSetForegroundWindow(uint processId);
}
