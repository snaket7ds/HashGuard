using System.Collections.Concurrent;
using System.Net;
using System.Security.Principal;

namespace HashGuard.Core;

/// <summary>The monitor's settings, read before every poll.</summary>
public sealed record NetworkMonitorSettings(
    bool Enabled,
    string NotifyMode,
    bool AutoBlockMalicious,
    IReadOnlyList<string> AutoBlockExceptions,
    IReadOnlyList<string> TrustedPublishers);

/// <summary>One place a program connected to.</summary>
public sealed record NetworkEndpointView(string Address, string Host, int Port, RemoteScope Scope, DateTimeOffset FirstSeenUtc, DateTimeOffset LastSeenUtc)
{
    public string Display => NetworkEndpoint.FormatEndpoint(Host.Length > 0 ? Host : Address, Port);
}

/// <summary>A program on the Firewall page: where it connects, what HashGuard knows about it, whether it's blocked.</summary>
public sealed record NetworkAppView(
    string Path,
    string Name,
    NetworkVerdict Verdict,
    string Signer,
    bool Signed,
    bool TrustedPublisher,
    bool Online,
    bool Blocked,
    int CurrentConnections,
    int TotalConnections,
    DateTimeOffset? LastSeenUtc,
    IReadOnlyList<NetworkEndpointView> Endpoints)
{
    public bool Untrusted => NetworkVerdict.IsUntrusted(Verdict.Kind, Signed, TrustedPublisher);
}

/// <summary>Windows Firewall as the monitor uses it; replaceable in tests.</summary>
public interface IFirewall
{
    IReadOnlyList<HashGuardFirewallRule> ListRules();

    void Block(string path, bool alsoInbound);

    int Unblock(string path);

    int RemoveAll();

    FirewallProfileState ProfileState();
}

/// <summary>The real Windows Firewall, through <see cref="FirewallRules"/>.</summary>
public sealed class WindowsFirewall : IFirewall
{
    public IReadOnlyList<HashGuardFirewallRule> ListRules() => FirewallRules.ListHashGuardRules();

    public void Block(string path, bool alsoInbound) => FirewallRules.Block(path, alsoInbound);

    public int Unblock(string path) => FirewallRules.Unblock(path);

    public int RemoveAll() => FirewallRules.RemoveAllHashGuardRules();

    public FirewallProfileState ProfileState() => FirewallRules.GetProfileState();
}

/// <summary>
/// Watches which programs connect where (the TCP table, every 5 s in the background, every second
/// while the Firewall page is open), tells about programs going online for the first time, and
/// blocks or unblocks programs with Windows Firewall rules in the "HashGuard" group. Monitor only:
/// traffic is allowed unless a program is blocked. Shares v1's files (network-apps.json,
/// network-actions.log) and rule group, so either version sees the other's blocks.
/// </summary>
/// <remarks>
/// Changing firewall rules needs administrator rights; without them the monitor still watches and
/// reports, and <see cref="Block"/>/<see cref="Unblock"/> say so.
/// </remarks>
public sealed class NetworkMonitor : IDisposable
{
    private static readonly TimeSpan BackgroundInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan PageInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan PidPathTtl = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan AssessmentTtl = TimeSpan.FromSeconds(10);

    private readonly Lock gate = new();
    private readonly HashCache hashCache;
    private readonly Func<NetworkMonitorSettings> readSettings;
    private readonly Action<string> addAutoBlockException;
    private readonly Action<string> removeAutoBlockExceptions;
    private readonly IFirewall firewall;
    private readonly string seenAppsPath;
    private readonly string actionLogPath;
    private readonly string ownExecutable;
    private readonly Dictionary<int, (string Path, DateTime ExpiresUtc)> pidPaths = [];
    private readonly Dictionary<string, (Assessment Value, DateTime ExpiresUtc)> assessments = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> autoBlockAttempted = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> hostNames = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> hostLookups = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim dnsGate = new(4, 4);
    private readonly CancellationTokenSource stop = new();
    private NetworkActivityTracker? tracker;
    private HashSet<string> blockedPaths = new(StringComparer.OrdinalIgnoreCase);
    private bool baselinePending;
    private DateTime lastSeenSaveUtc = DateTime.MinValue;
    private volatile bool pageOpen;
    private Task? loop;

    public NetworkMonitor(
        HashCache hashCache,
        Func<NetworkMonitorSettings> readSettings,
        Action<string> addAutoBlockException,
        Action<string> removeAutoBlockExceptions,
        IFirewall? firewall = null,
        string? seenAppsPath = null,
        string? actionLogPath = null,
        string? ownExecutable = null)
    {
        this.hashCache = hashCache;
        this.readSettings = readSettings;
        this.addAutoBlockException = addAutoBlockException;
        this.removeAutoBlockExceptions = removeAutoBlockExceptions;
        this.firewall = firewall ?? new WindowsFirewall();
        this.seenAppsPath = seenAppsPath ?? AppPaths.GetNetworkAppsPath();
        this.actionLogPath = actionLogPath ?? AppPaths.GetNetworkActionLogPath();
        this.ownExecutable = ownExecutable ?? Environment.ProcessPath ?? "";
    }

    /// <summary>The TCP table with each connection's program path; replaceable in tests.</summary>
    internal Func<List<(string Path, TcpConnection Connection)>>? ReadConnections { get; init; }

    /// <summary>Whether this copy runs as administrator, which blocking needs; replaceable in tests.</summary>
    public bool IsElevated { get; init; } = CheckElevated();

    /// <summary>After every poll (on a worker thread).</summary>
    public event Action? Polled;

    /// <summary>Programs that went online for the first time ever, filtered by the alert setting.</summary>
    public event Action<IReadOnlyList<NetworkAppView>>? NewAppsOnline;

    /// <summary>A program HashGuard blocked by itself because of a malicious verdict.</summary>
    public event Action<NetworkAppView>? AutoBlocked;

    /// <summary>Polls every second while the Firewall page is open, even when background watching is off.</summary>
    public bool PageOpen
    {
        get => pageOpen;
        set => pageOpen = value;
    }

    public void Start() => loop ??= Task.Run(() => RunAsync(stop.Token));

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var enabled = PageOpen || readSettings().Enabled;
            if (enabled)
            {
                try
                {
                    Poll();
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // One failed poll (a COM hiccup, a vanished process) must not stop the monitor.
                }
            }

            try
            {
                await Task.Delay(PageOpen ? PageInterval : BackgroundInterval, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    /// <summary>One poll: read connections, update the picture, alert, auto-block.</summary>
    internal void Poll()
    {
        var connections = (ReadConnections ?? CollectConnections)();
        var nowUtc = DateTimeOffset.UtcNow;
        var settings = readSettings();
        NetworkUpdateResult result;
        bool baseline;
        lock (gate)
        {
            if (tracker is null)
            {
                var seen = NetworkActivityTracker.LoadSeenApps(seenAppsPath);
                // First run: every program already online would look new. Record them quietly once.
                baselinePending = seen.Count == 0;
                tracker = new NetworkActivityTracker(seen);
                ReloadBlockedLocked();
            }

            result = tracker.Update(connections, nowUtc);
            baseline = baselinePending;
            baselinePending = false;
            if (result.SeenAppsChanged && (result.FirstEverSeen.Count > 0 || DateTime.UtcNow - lastSeenSaveUtc > TimeSpan.FromMinutes(5)))
            {
                try
                {
                    tracker.SaveSeenApps(seenAppsPath);
                    lastSeenSaveUtc = DateTime.UtcNow;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // Not fatal: those programs may be reported as new once more next time.
                }
            }
        }

        QueueHostLookups(nowUtc);

        if (!baseline && result.FirstEverSeen.Count > 0)
        {
            var mode = NetworkNotifyModes.Normalize(settings.NotifyMode);
            var alerts = mode == NetworkNotifyModes.Never
                ? []
                : result.FirstEverSeen
                    .Where(app => !FirewallRules.PathsEqual(app.Path, ownExecutable))
                    .Select(app => View(app.Path, settings))
                    .Where(view => mode == NetworkNotifyModes.NewApps || view.Untrusted)
                    .ToList();
            if (alerts.Count > 0)
            {
                NewAppsOnline?.Invoke(alerts);
            }
        }

        AutoBlock(settings);
        Polled?.Invoke();
    }

    /// <summary>Every program seen this session plus every blocked one, online first, then untrusted, then by name.</summary>
    public IReadOnlyList<NetworkAppView> Snapshot()
    {
        var settings = readSettings();
        List<string> paths;
        lock (gate)
        {
            paths = [.. (tracker?.Apps.Select(app => app.Path) ?? []).Concat(blockedPaths).Distinct(StringComparer.OrdinalIgnoreCase)];
        }

        return [.. paths
            .Select(path => View(path, settings))
            .OrderByDescending(view => view.Online)
            .ThenByDescending(view => view.Untrusted)
            .ThenBy(view => view.Name, StringComparer.OrdinalIgnoreCase)];
    }

    public NetworkAppView View(string path, NetworkMonitorSettings? settings = null)
    {
        settings ??= readSettings();
        var assessment = Assess(path, settings);
        lock (gate)
        {
            NetworkAppActivity? app = null;
            tracker?.TryGetApp(path, out app);
            var endpoints = app?.Endpoints.Values
                .OrderByDescending(endpoint => endpoint.LastSeenUtc)
                .Select(endpoint => new NetworkEndpointView(endpoint.Address, hostNames.GetValueOrDefault(endpoint.Address) ?? "", endpoint.Port, endpoint.Scope, endpoint.FirstSeenUtc, endpoint.LastSeenUtc))
                .ToList() ?? [];
            return new NetworkAppView(
                path,
                NetworkActivityTracker.DisplayName(path),
                assessment.Verdict,
                assessment.Signer,
                assessment.Signed,
                assessment.TrustedPublisher,
                app is { CurrentConnections: > 0 },
                blockedPaths.Contains(path),
                app?.CurrentConnections ?? 0,
                app?.TotalConnections ?? 0,
                app?.LastSeenUtc,
                endpoints);
        }
    }

    /// <summary>Whether Windows Firewall is on for the active networks (blocks only work when it is).</summary>
    public FirewallProfileState ProfileState() => firewall.ProfileState();

    /// <summary>True for parts of Windows and HashGuard itself, where a block can break things.</summary>
    public bool IsSensitive(string path) =>
        FirewallRules.IsSensitivePath(path, Environment.GetFolderPath(Environment.SpecialFolder.Windows), ownExecutable);

    /// <summary>Adds a Windows Firewall rule blocking the program's outgoing (and optionally incoming) connections.</summary>
    public void Block(string path, bool alsoInbound)
    {
        RequireElevated();
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("HashGuard can only block a program file it can find on disk.", path);
        }

        firewall.Block(path, alsoInbound);
        lock (gate)
        {
            ReloadBlockedLocked();
            blockedPaths.Add(FirewallRules.NormalizePath(path));
        }

        removeAutoBlockExceptions(HashGuardLogic.AutoBlockExceptionKey(path, ""));
        Log(alsoInbound ? "Blocked outgoing and incoming" : "Blocked outgoing", path);
    }

    /// <summary>
    /// Removes HashGuard's rules for the program and remembers that you allowed this exact file,
    /// so auto-block leaves it alone until the file changes. Returns how many rules were removed.
    /// </summary>
    public int Unblock(string path)
    {
        RequireElevated();
        var removed = firewall.Unblock(path);
        lock (gate)
        {
            ReloadBlockedLocked();
            blockedPaths.RemoveWhere(blocked => FirewallRules.PathsEqual(blocked, path));
            autoBlockAttempted.Add(path);
        }

        RememberAllowed(path);
        if (removed > 0)
        {
            Log("Unblocked (auto-block will leave this file alone)", path);
        }

        return removed;
    }

    /// <summary>The paths HashGuard's rules block right now.</summary>
    public IReadOnlyList<string> BlockedPaths()
    {
        lock (gate)
        {
            return [.. blockedPaths];
        }
    }

    /// <summary>Removes every rule in the HashGuard group; returns how many.</summary>
    public int RemoveAllRules()
    {
        RequireElevated();
        var paths = firewall.ListRules().Select(rule => rule.ApplicationPath).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var removed = firewall.RemoveAll();
        lock (gate)
        {
            blockedPaths.Clear();
            autoBlockAttempted.UnionWith(paths);
        }

        foreach (var path in paths)
        {
            RememberAllowed(path);
        }

        Log($"Removed all HashGuard firewall rules ({removed})", "Windows Firewall");
        return removed;
    }

    private void AutoBlock(NetworkMonitorSettings settings)
    {
        if (!settings.AutoBlockMalicious || !IsElevated)
        {
            return;
        }

        List<string> candidates;
        lock (gate)
        {
            candidates = [.. tracker!.Apps
                .Where(app => app.CurrentConnections > 0 && !blockedPaths.Contains(app.Path) && !autoBlockAttempted.Contains(app.Path))
                .Select(app => app.Path)];
        }

        foreach (var path in candidates)
        {
            if (FirewallRules.PathsEqual(path, ownExecutable) || !File.Exists(path) || VerdictOf(path).Kind != NetworkVerdictKind.Malicious)
            {
                continue;
            }

            if (hashCache.TryGetKnownHash(path, out var sha256) && HashGuardLogic.IsAutoBlockException(settings.AutoBlockExceptions, path, sha256))
            {
                continue;
            }

            lock (gate)
            {
                autoBlockAttempted.Add(path);
            }

            try
            {
                firewall.Block(path, alsoInbound: false);
                lock (gate)
                {
                    blockedPaths.Add(FirewallRules.NormalizePath(path));
                }

                Log("Auto-blocked (malicious verdict)", path);
                AutoBlocked?.Invoke(View(path, settings));
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                Log($"Auto-block failed: {ex.Message}", path);
            }
        }
    }

    private void RememberAllowed(string path)
    {
        if (!File.Exists(path))
        {
            return;
        }

        if (!hashCache.TryGetKnownHash(path, out var sha256))
        {
            try
            {
                sha256 = FileHash.Sha256FileAsync(path).GetAwaiter().GetResult();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return;
            }
        }

        addAutoBlockException(HashGuardLogic.AutoBlockExceptionKey(path, sha256));
    }

    private void RequireElevated()
    {
        if (!IsElevated)
        {
            throw new UnauthorizedAccessException("Changing Windows Firewall rules needs HashGuard to run as administrator.");
        }
    }

    private void ReloadBlockedLocked()
    {
        try
        {
            blockedPaths = firewall.ListRules()
                .Where(rule => rule.Enabled && !rule.Inbound)
                .Select(rule => rule.ApplicationPath)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Keep what we had; Windows Firewall may be unavailable for a moment.
        }
    }

    private sealed record Assessment(NetworkVerdict Verdict, string Signer, bool Signed, bool TrustedPublisher);

    private Assessment Assess(string path, NetworkMonitorSettings settings)
    {
        var now = DateTime.UtcNow;
        lock (gate)
        {
            if (assessments.TryGetValue(path, out var cached) && cached.ExpiresUtc > now)
            {
                return cached.Value;
            }
        }

        Assessment assessment;
        if (string.Equals(path, "System", StringComparison.OrdinalIgnoreCase))
        {
            assessment = new Assessment(new NetworkVerdict(NetworkVerdictKind.Clean, "Windows"), "Windows kernel", true, true);
        }
        else if (!File.Exists(path))
        {
            assessment = new Assessment(NetworkVerdict.NotScanned, "Unknown", false, false);
        }
        else
        {
            var signature = SignatureReader.Read(path);
            var signed = signature.Publisher.Length > 0 && HashGuardLogic.SignatureChainValid(signature.Summary);
            assessment = new Assessment(
                VerdictOf(path),
                signature.Publisher.Length == 0 ? "Not signed" : signed ? signature.Publisher : $"{signature.Publisher} (not verified)",
                signed,
                signed && settings.TrustedPublishers.Any(trusted => HashGuardLogic.PublisherEquals(signature.Publisher, trusted)));
        }

        lock (gate)
        {
            assessments[path] = (assessment, now + AssessmentTtl);
        }

        return assessment;
    }

    private NetworkVerdict VerdictOf(string path) =>
        hashCache.TryGetKnownHash(path, out var sha256) && hashCache.TryGet(sha256, out var entry)
            ? NetworkVerdict.FromCache(entry)
            : NetworkVerdict.NotScanned;

    /// <summary>Worker thread: the TCP table's outgoing connections with each owning program's path.</summary>
    private List<(string Path, TcpConnection Connection)> CollectConnections()
    {
        var rows = new List<(string, TcpConnection)>();
        var now = DateTime.UtcNow;
        var live = new HashSet<int>();
        foreach (var connection in ConnectionTable.ReadTcp())
        {
            if (!ConnectionTable.IsOutboundCandidate(connection))
            {
                continue;
            }

            live.Add(connection.Pid);
            lock (gate)
            {
                if (!pidPaths.TryGetValue(connection.Pid, out var cached) || cached.ExpiresUtc < now)
                {
                    cached = (ConnectionTable.TryGetProcessImagePath(connection.Pid) ?? $"Unknown process (PID {connection.Pid})", now + PidPathTtl);
                    pidPaths[connection.Pid] = cached;
                }

                rows.Add((cached.Path, connection));
            }
        }

        lock (gate)
        {
            foreach (var pid in pidPaths.Where(item => !live.Contains(item.Key) && item.Value.ExpiresUtc < now).Select(item => item.Key).ToList())
            {
                pidPaths.Remove(pid);
            }
        }

        return rows;
    }

    private void QueueHostLookups(DateTimeOffset nowUtc)
    {
        List<string> addresses;
        lock (gate)
        {
            addresses = [.. tracker!.Apps.SelectMany(app => app.Endpoints.Values).Where(endpoint => endpoint.LastSeenUtc == nowUtc).Select(endpoint => endpoint.Address).Distinct()];
        }

        foreach (var address in addresses)
        {
            if (!hostNames.ContainsKey(address) && hostLookups.TryAdd(address, 0))
            {
                _ = ResolveHostAsync(address);
            }
        }
    }

    /// <summary>Reverse DNS for an address, at most four at a time and two seconds each; no answer shows the address.</summary>
    private async Task ResolveHostAsync(string address)
    {
        var host = "";
        await dnsGate.WaitAsync().ConfigureAwait(false);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            var entry = await Dns.GetHostEntryAsync(address, timeout.Token).ConfigureAwait(false);
            if (!string.Equals(entry.HostName, address, StringComparison.OrdinalIgnoreCase))
            {
                host = entry.HostName;
            }
        }
        catch (Exception ex) when (ex is System.Net.Sockets.SocketException or OperationCanceledException or ArgumentException)
        {
            // No PTR record or a slow resolver.
        }
        finally
        {
            dnsGate.Release();
        }

        if (hostNames.Count > 5000)
        {
            hostNames.Clear();
            hostLookups.Clear();
        }

        hostNames[address] = host;
    }

    private void Log(string action, string path)
    {
        try
        {
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(actionLogPath)!);
            File.AppendAllText(actionLogPath, $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}\t{action}\t{path}{Environment.NewLine}");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Logging is best-effort.
        }
    }

    private static bool CheckElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public void Dispose()
    {
        stop.Cancel();
        stop.Dispose();
        dnsGate.Dispose();
    }
}
