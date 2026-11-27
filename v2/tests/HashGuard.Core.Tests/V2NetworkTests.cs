using System.Net;
using HashGuard.Core;

/// <summary>Tests for v2's network monitor, with a fake firewall and fake connections.</summary>
internal static class V2NetworkTests
{
    public static (string Name, Action Test)[] All =>
    [
        ("Network: programs already online at first start are recorded quietly; later ones alert", () => WithTemp(dir =>
        {
            var first = Write(dir, "first.exe");
            var later = Write(dir, "later.exe");
            var connections = new List<(string, TcpConnection)> { (first, Conn(10, 443)) };
            var (monitor, _) = Monitor(dir, () => connections, mode: NetworkNotifyModes.NewApps);
            var alerts = new List<string>();
            monitor.NewAppsOnline += apps => alerts.AddRange(apps.Select(a => a.Name));

            monitor.Poll();
            Equal(0, alerts.Count);

            connections.Add((later, Conn(11, 80)));
            monitor.Poll();
            Equal("later.exe", alerts.Single());

            var view = monitor.Snapshot().Single(v => v.Name == "later.exe");
            True(view.Online);
            Equal(1, view.CurrentConnections);
            Equal("203.0.113.11:80", view.Endpoints.Single().Display.Replace("[", "").Replace("]", ""));
        })),
        ("Network: 'untrusted only' skips signed trusted programs and alerts on unsigned ones", () => WithTemp(dir =>
        {
            var notepad = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "notepad.exe");
            var unsigned = Write(dir, "tool.exe");
            var connections = new List<(string, TcpConnection)> { (Write(dir, "seed.exe"), Conn(1, 443)) };
            var (monitor, _) = Monitor(dir, () => connections, mode: NetworkNotifyModes.Untrusted);
            var alerts = new List<string>();
            monitor.NewAppsOnline += apps => alerts.AddRange(apps.Select(a => a.Name));
            monitor.Poll(); // baseline

            connections.Add((notepad, Conn(2, 443)));
            connections.Add((unsigned, Conn(3, 443)));
            monitor.Poll();
            Equal("tool.exe", alerts.Single());
        })),
        ("Network: blocking needs administrator; elevated block and unblock use the HashGuard rules", () => WithTemp(dir =>
        {
            var app = Write(dir, "app.exe");
            var connections = new List<(string, TcpConnection)> { (app, Conn(5, 443)) };
            var (plain, _) = Monitor(dir, () => connections);
            Throws<UnauthorizedAccessException>(() => plain.Block(app, alsoInbound: false));

            var exceptions = new List<string>();
            var (monitor, firewall) = Monitor(dir, () => connections, elevated: true, exceptions: exceptions);
            monitor.Poll();
            monitor.Block(app, alsoInbound: false);
            True(firewall.Blocked.Contains(app));
            True(monitor.Snapshot().Single().Blocked);

            Equal(1, monitor.Unblock(app));
            False(monitor.Snapshot().Single().Blocked);
            True(exceptions.Single().StartsWith(HashGuardLogic.AutoBlockExceptionKey(app, ""), StringComparison.Ordinal));
            True(File.ReadAllText(Path.Combine(dir, "actions.log")).Contains("Unblocked"));
        })),
        ("Network: a program scanned as malicious is shown as such and auto-blocked once", () => WithTemp(dir =>
        {
            var bad = Write(dir, "bad.exe");
            var cache = new HashCache();
            cache.Set(new ScanResult(bad, "bad.exe", "7") { Sha256 = new string('a', 64), Status = "malicious", Malicious = 12 });
            var connections = new List<(string, TcpConnection)> { (Write(dir, "seed.exe"), Conn(1, 443)) };
            var (monitor, firewall) = Monitor(dir, () => connections, elevated: true, cache: cache);
            var autoBlocked = new List<string>();
            monitor.AutoBlocked += view => autoBlocked.Add(view.Name);
            monitor.Poll();

            connections.Add((bad, Conn(7, 443)));
            monitor.Poll();
            monitor.Poll();
            Equal(NetworkVerdictKind.Malicious, monitor.View(bad).Verdict.Kind);
            Equal("bad.exe", autoBlocked.Single());
            Equal(1, firewall.BlockCalls);
        })),
        ("Network: auto-block leaves a file alone after you unblocked it", () => WithTemp(dir =>
        {
            var bad = Write(dir, "bad.exe");
            var sha = new string('b', 64);
            var cache = new HashCache();
            cache.Set(new ScanResult(bad, "bad.exe", "7") { Sha256 = sha, Status = "malicious", Malicious = 3 });
            var connections = new List<(string, TcpConnection)> { (bad, Conn(7, 443)) };
            var exceptions = new List<string> { HashGuardLogic.AutoBlockExceptionKey(bad, sha) };
            var (monitor, firewall) = Monitor(dir, () => connections, elevated: true, cache: cache, exceptions: exceptions);
            monitor.Poll();
            Equal(0, firewall.BlockCalls);
        })),
    ];

    private static (NetworkMonitor Monitor, FakeFirewall Firewall) Monitor(
        string dir,
        Func<List<(string, TcpConnection)>> connections,
        string mode = NetworkNotifyModes.Untrusted,
        bool elevated = false,
        HashCache? cache = null,
        List<string>? exceptions = null)
    {
        exceptions ??= [];
        var firewall = new FakeFirewall();
        var settings = () => new NetworkMonitorSettings(true, mode, AutoBlockMalicious: true, exceptions, ["Microsoft Windows", "Microsoft Corporation"]);
        var monitor = new NetworkMonitor(
            cache ?? new HashCache(),
            settings,
            exceptions.Add,
            prefix => exceptions.RemoveAll(e => e.StartsWith(prefix, StringComparison.Ordinal)),
            firewall,
            Path.Combine(dir, "network-apps.json"),
            Path.Combine(dir, "actions.log"),
            Path.Combine(dir, "HashGuard.exe"))
        {
            ReadConnections = () => connections().Select(c => (c.Item1, c.Item2)).ToList(),
            IsElevated = elevated,
        };
        return (monitor, firewall);
    }

    private static TcpConnection Conn(int pid, int port) =>
        new(pid, IPAddress.Parse("192.168.1.10"), 50000 + pid, IPAddress.Parse($"203.0.113.{pid}"), port, TcpState.Established);

    private static string Write(string dir, string name)
    {
        var path = Path.Combine(dir, name);
        File.WriteAllText(path, name);
        return path;
    }

    private sealed class FakeFirewall : IFirewall
    {
        public HashSet<string> Blocked { get; } = new(StringComparer.OrdinalIgnoreCase);

        public int BlockCalls { get; private set; }

        public IReadOnlyList<HashGuardFirewallRule> ListRules() =>
            [.. Blocked.Select(path => new HashGuardFirewallRule(FirewallRules.RuleName(path, false), path, false, true))];

        public void Block(string path, bool alsoInbound)
        {
            BlockCalls++;
            Blocked.Add(path);
        }

        public int Unblock(string path) => Blocked.Remove(path) ? 1 : 0;

        public int RemoveAll()
        {
            var count = Blocked.Count;
            Blocked.Clear();
            return count;
        }

        public FirewallProfileState ProfileState() => new(true, "Windows Firewall is on.");
    }

    private static void WithTemp(Action<string> test)
    {
        var dir = Directory.CreateTempSubdirectory("hg-net").FullName;
        try
        {
            test(dir);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static void Throws<T>(Action action) where T : Exception
    {
        try
        {
            action();
        }
        catch (T)
        {
            return;
        }

        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }

    private static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected <{expected}> but got <{actual}>.");
        }
    }

    private static void True(bool value)
    {
        if (!value)
        {
            throw new InvalidOperationException("Expected true.");
        }
    }

    private static void False(bool value) => True(!value);
}
