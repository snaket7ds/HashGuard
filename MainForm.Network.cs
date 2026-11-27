using System.Collections.Concurrent;
using System.Diagnostics;
using System.Drawing;
using System.Net;
using System.Windows.Forms;

namespace HashGuardScanner;

/// <summary>
/// Network Monitor: which programs connect where, their HashGuard verdict, and one-click
/// Windows Firewall blocks (see <see cref="FirewallRules"/>). Monitor mode only: traffic is
/// allowed unless the user blocks a program.
/// </summary>
public sealed partial class MainForm : Form
{
    private const int NetworkWindowPollMs = 1000;
    private const int NetworkBackgroundPollMs = 5000;
    private static readonly TimeSpan NetworkPidPathTtl = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan NetworkAssessmentTtl = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan NetworkAlertSpacing = TimeSpan.FromSeconds(10);

    private readonly Button networkButton = new() { Text = "", Width = 36, Height = 36, Font = new Font("Segoe MDL2 Assets", 11, FontStyle.Regular) };
    private readonly System.Windows.Forms.Timer networkTimer = new();
    private readonly Dictionary<int, (string Path, DateTime ExpiresUtc)> networkPidPaths = [];
    private readonly ConcurrentDictionary<string, string> networkHostNames = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> networkHostLookups = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim networkDnsGate = new(4, 4);
    private readonly Dictionary<string, (NetworkAppAssessment Assessment, DateTime ExpiresUtc)> networkAssessments = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> networkAutoBlockAttempted = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> pendingNetworkAlerts = [];
    private HashSet<string> networkBlockedPaths = new(StringComparer.OrdinalIgnoreCase);
    private NetworkActivityTracker? networkTracker;
    private bool networkBaselinePending;
    private bool networkPollRunning;
    private DateTime lastNetworkAlertUtc = DateTime.MinValue;
    private DateTime lastNetworkSeenSaveUtc = DateTime.MinValue;
    private string? networkAlertAppPath;
    private Form? networkWindow;
    private Action? refreshNetworkWindow;
    private Action<string>? selectNetworkApp;

    private sealed record NetworkAppAssessment(NetworkVerdict Verdict, string Signer, bool Signed, bool TrustedPublisher)
    {
        public bool Untrusted => NetworkVerdict.IsUntrusted(Verdict.Kind, Signed, TrustedPublisher);
    }

    private sealed record NetworkRow(string Path, string[] Columns, bool Blocked, bool Online, NetworkAppAssessment Assessment);

    private static string GetNetworkAppsPath() => Path.Combine(AppPaths.GetConfigDirectory(), "network-apps.json");

    private static string GetNetworkActionLogPath() => Path.Combine(AppPaths.GetLogDirectory(), "network-actions.log");

    private void InitializeNetworkMonitor()
    {
        networkTimer.Tick += async (_, _) => await PollNetworkAsync();
        trayIcon.BalloonTipClicked += (_, _) =>
        {
            if (networkAlertAppPath is { } path)
            {
                networkAlertAppPath = null;
                ShowNetworkMonitor(path);
            }
        };
        trayIcon.BalloonTipClosed += (_, _) => networkAlertAppPath = null;
        UpdateNetworkTimer();
    }

    /// <summary>1 s while the window is open, 5 s in the background when enabled, otherwise off.</summary>
    private void UpdateNetworkTimer()
    {
        var windowOpen = networkWindow is { IsDisposed: false };
        var enabled = windowOpen || appSettings.NetworkMonitorEnabled;
        if (enabled)
        {
            EnsureNetworkTracker();
        }

        networkTimer.Interval = windowOpen ? NetworkWindowPollMs : NetworkBackgroundPollMs;
        networkTimer.Enabled = enabled;
        if (enabled && !networkPollRunning)
        {
            _ = PollNetworkAsync();
        }
    }

    private void EnsureNetworkTracker()
    {
        if (networkTracker is not null)
        {
            return;
        }

        var seen = NetworkActivityTracker.LoadSeenApps(GetNetworkAppsPath());
        // First run: every app already online would look "new". Record them silently once.
        networkBaselinePending = seen.Count == 0;
        networkTracker = new NetworkActivityTracker(seen);
        ReloadNetworkBlockedPaths();
    }

    private async Task PollNetworkAsync()
    {
        if (networkPollRunning || networkTracker is null)
        {
            return;
        }

        networkPollRunning = true;
        try
        {
            var connections = await Task.Run(CollectNetworkConnections);
            var nowUtc = DateTimeOffset.UtcNow;
            var result = networkTracker.Update(connections, nowUtc);
            var baseline = networkBaselinePending;
            networkBaselinePending = false;

            if (result.SeenAppsChanged
                && (result.FirstEverSeen.Count > 0 || DateTime.UtcNow - lastNetworkSeenSaveUtc > TimeSpan.FromMinutes(5)))
            {
                try
                {
                    networkTracker.SaveSeenApps(GetNetworkAppsPath());
                    lastNetworkSeenSaveUtc = DateTime.UtcNow;
                }
                catch
                {
                    // Not fatal: apps may be reported as new once more next session.
                }
            }

            QueueNetworkHostLookups(nowUtc);
            if (baseline)
            {
                if (result.FirstEverSeen.Count > 0)
                {
                    statusLabel.Text = $"Network Monitor recorded {result.FirstEverSeen.Count} app(s) already online; it alerts about new ones from now on.";
                }
            }
            else
            {
                foreach (var app in result.FirstEverSeen)
                {
                    QueueFirstSeenNetworkAlert(app);
                }
            }

            AutoBlockMaliciousNetworkApps();
            FlushNetworkAlerts();
            refreshNetworkWindow?.Invoke();
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Network Monitor poll failed: {ex}");
        }
        finally
        {
            networkPollRunning = false;
        }
    }

    /// <summary>Worker thread: read the TCP table and resolve each owning process's path.</summary>
    private List<(string Path, TcpConnection Connection)> CollectNetworkConnections()
    {
        var rows = new List<(string, TcpConnection)>();
        var now = DateTime.UtcNow;
        var connections = ConnectionTable.ReadTcp();
        lock (networkPidPaths)
        {
            var livePids = new HashSet<int>();
            foreach (var connection in connections)
            {
                if (!ConnectionTable.IsOutboundCandidate(connection))
                {
                    continue;
                }

                livePids.Add(connection.Pid);
                if (!networkPidPaths.TryGetValue(connection.Pid, out var cached) || cached.ExpiresUtc < now)
                {
                    var path = ConnectionTable.TryGetProcessImagePath(connection.Pid) ?? $"Unknown process (PID {connection.Pid})";
                    cached = (path, now + NetworkPidPathTtl);
                    networkPidPaths[connection.Pid] = cached;
                }

                rows.Add((cached.Path, connection));
            }

            foreach (var pid in networkPidPaths.Where(item => !livePids.Contains(item.Key) && item.Value.ExpiresUtc < now).Select(item => item.Key).ToList())
            {
                networkPidPaths.Remove(pid);
            }
        }

        // Warm the signature cache off the UI thread (GetSignatureInfo caches per path+size+mtime).
        foreach (var path in rows.Select(row => row.Item1).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (File.Exists(path))
            {
                _ = GetSignatureInfo(path);
            }
        }

        return rows;
    }

    private void QueueNetworkHostLookups(DateTimeOffset nowUtc)
    {
        if (networkTracker is null)
        {
            return;
        }

        foreach (var endpoint in networkTracker.Apps.SelectMany(app => app.Endpoints.Values).Where(endpoint => endpoint.LastSeenUtc == nowUtc))
        {
            if (!networkHostNames.ContainsKey(endpoint.Address) && networkHostLookups.TryAdd(endpoint.Address, 0))
            {
                _ = ResolveNetworkHostAsync(endpoint.Address);
            }
        }
    }

    private async Task ResolveNetworkHostAsync(string address)
    {
        var host = "";
        await networkDnsGate.WaitAsync();
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            var entry = await Dns.GetHostEntryAsync(address, timeout.Token);
            if (!string.Equals(entry.HostName, address, StringComparison.OrdinalIgnoreCase))
            {
                host = entry.HostName;
            }
        }
        catch
        {
            // No PTR record or a slow resolver: show the address.
        }
        finally
        {
            networkDnsGate.Release();
        }

        if (networkHostNames.Count > 5000)
        {
            networkHostNames.Clear();
            networkHostLookups.Clear();
        }

        networkHostNames[address] = host;
    }

    private string DescribeEndpoint(NetworkEndpoint endpoint)
    {
        var host = networkHostNames.TryGetValue(endpoint.Address, out var name) && !string.IsNullOrWhiteSpace(name) ? name : endpoint.Address;
        return NetworkEndpoint.FormatEndpoint(host, endpoint.Port);
    }

    private NetworkAppAssessment AssessNetworkApp(string path)
    {
        var now = DateTime.UtcNow;
        if (networkAssessments.TryGetValue(path, out var cached) && cached.ExpiresUtc > now)
        {
            return cached.Assessment;
        }

        NetworkAppAssessment assessment;
        if (string.Equals(path, "System", StringComparison.OrdinalIgnoreCase))
        {
            assessment = new NetworkAppAssessment(new NetworkVerdict(NetworkVerdictKind.Clean, "Windows"), "Windows kernel", true, true);
        }
        else if (!File.Exists(path))
        {
            assessment = new NetworkAppAssessment(NetworkVerdict.NotScanned, "Unknown", false, false);
        }
        else
        {
            var verdict = GetNetworkVerdict(path);
            var signature = GetSignatureInfo(path);
            var signed = !string.IsNullOrWhiteSpace(signature.Publisher)
                && signature.Summary.Contains("chain valid", StringComparison.OrdinalIgnoreCase);
            assessment = new NetworkAppAssessment(
                verdict,
                string.IsNullOrWhiteSpace(signature.Publisher) ? "Unsigned" : signed ? signature.Publisher : $"{signature.Publisher} (not verified)",
                signed,
                signed && IsTrustedPublisher(signature.Publisher));
        }

        networkAssessments[path] = (assessment, now + NetworkAssessmentTtl);
        return assessment;
    }

    private NetworkVerdict GetNetworkVerdict(string path) =>
        hashCache.TryGetKnownHash(path, out var sha256) && hashCache.TryGet(sha256, out var entry)
            ? NetworkVerdict.FromCache(entry)
            : NetworkVerdict.NotScanned;

    private void QueueFirstSeenNetworkAlert(NetworkAppActivity app)
    {
        var mode = NetworkNotifyModes.Normalize(appSettings.NetworkNotifyMode);
        if (mode == NetworkNotifyModes.Never)
        {
            return;
        }

        if (mode == NetworkNotifyModes.Untrusted && !AssessNetworkApp(app.Path).Untrusted)
        {
            return;
        }

        if (!pendingNetworkAlerts.Contains(app.Path, StringComparer.OrdinalIgnoreCase))
        {
            pendingNetworkAlerts.Add(app.Path);
        }
    }

    /// <summary>One balloon at most every 10 s; several new apps are combined into one.</summary>
    private void FlushNetworkAlerts()
    {
        if (pendingNetworkAlerts.Count == 0 || DateTime.UtcNow - lastNetworkAlertUtc < NetworkAlertSpacing)
        {
            return;
        }

        if (networkWindow is { Visible: true, WindowState: not FormWindowState.Minimized })
        {
            // The user is already watching the list.
            pendingNetworkAlerts.Clear();
            return;
        }

        var first = pendingNetworkAlerts[0];
        var assessment = AssessNetworkApp(first);
        string message;
        if (pendingNetworkAlerts.Count == 1 && networkTracker is not null && networkTracker.TryGetApp(first, out var app))
        {
            var endpoint = app.MostRecentEndpoint;
            var where = endpoint is null ? "the network" : DescribeEndpoint(endpoint);
            message = $"{app.Name} connected to {where} for the first time. {assessment.Verdict.Label} · {assessment.Signer}. Click to open Network Monitor.";
        }
        else
        {
            var names = pendingNetworkAlerts.Select(NetworkActivityTracker.DisplayName).Take(4).ToList();
            var more = pendingNetworkAlerts.Count > names.Count ? $" and {pendingNetworkAlerts.Count - names.Count} more" : "";
            message = $"{pendingNetworkAlerts.Count} apps went online for the first time: {string.Join(", ", names)}{more}. Click to open Network Monitor.";
        }

        var anyUntrusted = pendingNetworkAlerts.Any(path => AssessNetworkApp(path).Untrusted);
        networkAlertAppPath = first;
        trayIcon.ShowBalloonTip(6000, "HashGuard Network Monitor", message, anyUntrusted ? ToolTipIcon.Warning : ToolTipIcon.Info);
        lastNetworkAlertUtc = DateTime.UtcNow;
        pendingNetworkAlerts.Clear();
    }

    private void AutoBlockMaliciousNetworkApps()
    {
        if (!appSettings.AutoBlockMalicious || networkTracker is null || !IsRunningElevated())
        {
            return;
        }

        foreach (var app in networkTracker.Apps.Where(app => app.CurrentConnections > 0).ToList())
        {
            if (networkBlockedPaths.Contains(app.Path)
                || networkAutoBlockAttempted.Contains(app.Path)
                || !File.Exists(app.Path)
                || GetNetworkVerdict(app.Path).Kind != NetworkVerdictKind.Malicious)
            {
                continue;
            }

            networkAutoBlockAttempted.Add(app.Path);
            try
            {
                FirewallRules.Block(app.Path, alsoInbound: false);
                networkBlockedPaths.Add(app.Path);
                LogNetworkAction("Auto-blocked (malicious verdict)", app.Path);
                networkAlertAppPath = app.Path;
                trayIcon.ShowBalloonTip(6000, "HashGuard blocked an app", $"{app.Name} was blocked in Windows Firewall because HashGuard flags it as malicious. Click to review.", ToolTipIcon.Warning);
                lastNetworkAlertUtc = DateTime.UtcNow;
            }
            catch (Exception ex)
            {
                LogNetworkAction($"Auto-block failed: {ex.Message}", app.Path);
            }
        }
    }

    private void ReloadNetworkBlockedPaths()
    {
        try
        {
            networkBlockedPaths = FirewallRules.ListHashGuardRules()
                .Where(rule => rule.Enabled && !rule.Inbound)
                .Select(rule => rule.ApplicationPath)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            // Keep what we had; Windows Firewall may be unavailable.
        }
    }

    private void LogNetworkAction(string action, string path)
    {
        statusLabel.Text = $"{action}: {NetworkActivityTracker.DisplayName(path)}";
        try
        {
            var logPath = GetNetworkActionLogPath();
            Directory.CreateDirectory(Path.GetDirectoryName(logPath)!);
            File.AppendAllText(logPath, $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}\t{action}\t{path}{Environment.NewLine}");
        }
        catch
        {
            // Logging is best-effort.
        }
    }

    private bool BlockNetworkApp(IWin32Window owner, string path)
    {
        if (!IsRunningElevated())
        {
            MessageBox.Show(owner, "Blocking adds a Windows Firewall rule, which needs HashGuard to run elevated.\n\nTurn on Settings → Behavior → Run elevated, then restart HashGuard.", "Run elevated to block", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return false;
        }

        if (!File.Exists(path))
        {
            MessageBox.Show(owner, "HashGuard can only block a program file it can find on disk. This entry has no program path.", "Can't block this entry", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return false;
        }

        var name = NetworkActivityTracker.DisplayName(path);
        var sensitive = FirewallRules.IsSensitivePath(path, Environment.GetFolderPath(Environment.SpecialFolder.Windows), Application.ExecutablePath);
        var blockButton = new TaskDialogButton("Block");
        var page = new TaskDialogPage
        {
            Caption = "Block in Windows Firewall",
            Heading = $"Block {name} from the network?",
            Text = $"{path}\n\nHashGuard adds a Windows Firewall rule that blocks this program's outgoing connections. Connections it already has open may continue until it reconnects. Use Unblock to undo it."
                + (sensitive ? "\n\nWarning: this is part of Windows or HashGuard itself. Blocking it can break Windows Update, DNS, sign-in, or HashGuard's own lookups." : ""),
            Icon = sensitive ? TaskDialogIcon.Warning : TaskDialogIcon.Shield,
            Verification = new TaskDialogVerificationCheckBox("Also block incoming connections"),
        };
        // TaskDialogButton.Cancel returns a new instance on every access; keep the one we add.
        var cancelButton = TaskDialogButton.Cancel;
        page.Buttons.Add(blockButton);
        page.Buttons.Add(cancelButton);
        page.DefaultButton = sensitive ? cancelButton : blockButton;
        if (TaskDialog.ShowDialog(owner, page) != blockButton)
        {
            return false;
        }

        try
        {
            FirewallRules.Block(path, page.Verification.Checked);
        }
        catch (Exception ex)
        {
            MessageBox.Show(owner, $"Windows Firewall refused the rule:\n{ex.Message}", "Block failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }

        ReloadNetworkBlockedPaths();
        networkBlockedPaths.Add(FirewallRules.NormalizePath(path));
        LogNetworkAction(page.Verification.Checked ? "Blocked outgoing and incoming" : "Blocked outgoing", path);
        return true;
    }

    private bool UnblockNetworkApp(IWin32Window owner, string path)
    {
        if (!IsRunningElevated())
        {
            MessageBox.Show(owner, "Removing a Windows Firewall rule needs HashGuard to run elevated.\n\nTurn on Settings → Behavior → Run elevated, then restart HashGuard.", "Run elevated to unblock", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return false;
        }

        try
        {
            var removed = FirewallRules.Unblock(path);
            ReloadNetworkBlockedPaths();
            networkBlockedPaths.RemoveWhere(blocked => FirewallRules.PathsEqual(blocked, path));
            networkAutoBlockAttempted.Remove(path);
            if (removed == 0)
            {
                MessageBox.Show(owner, "HashGuard found no rule of its own for this program. It may have been removed in Windows Firewall already.", "Nothing to unblock", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return false;
            }

            LogNetworkAction("Unblocked", path);
            return true;
        }
        catch (Exception ex)
        {
            MessageBox.Show(owner, $"Windows Firewall refused the change:\n{ex.Message}", "Unblock failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
    }

    private void RemoveAllNetworkRules(IWin32Window owner)
    {
        if (!IsRunningElevated())
        {
            MessageBox.Show(owner, "Removing Windows Firewall rules needs HashGuard to run elevated.", "Run elevated", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        int count;
        try
        {
            count = FirewallRules.ListHashGuardRules().Count;
        }
        catch (Exception ex)
        {
            MessageBox.Show(owner, $"Windows Firewall could not be read:\n{ex.Message}", "Remove rules", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        if (count == 0)
        {
            MessageBox.Show(owner, "HashGuard has no Windows Firewall rules right now.", "Remove rules", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var accepted = MessageBox.Show(
            owner,
            $"Remove all {count} Windows Firewall rule(s) HashGuard created? Every program HashGuard blocked can connect again.\n\nYour other firewall rules are not touched.",
            "Remove all HashGuard rules",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning,
            MessageBoxDefaultButton.Button2);
        if (accepted != DialogResult.Yes)
        {
            return;
        }

        try
        {
            var removed = FirewallRules.RemoveAllHashGuardRules();
            networkBlockedPaths.Clear();
            networkAutoBlockAttempted.Clear();
            LogNetworkAction($"Removed all HashGuard firewall rules ({removed})", "Windows Firewall");
        }
        catch (Exception ex)
        {
            MessageBox.Show(owner, $"Windows Firewall refused the change:\n{ex.Message}", "Remove rules failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private List<NetworkRow> BuildNetworkRows(string search, bool hideTrusted, bool showIdle)
    {
        var rows = new List<NetworkRow>();
        var now = DateTimeOffset.UtcNow;
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var app in networkTracker?.Apps ?? [])
        {
            paths.Add(app.Path);
        }

        paths.UnionWith(networkBlockedPaths);
        foreach (var path in paths)
        {
            NetworkAppActivity? app = null;
            networkTracker?.TryGetApp(path, out app);
            var blocked = networkBlockedPaths.Contains(path);
            var online = app is { CurrentConnections: > 0 };
            if (!showIdle && !online && !blocked)
            {
                continue;
            }

            var assessment = AssessNetworkApp(path);
            if (hideTrusted && assessment.TrustedPublisher && !blocked
                && assessment.Verdict.Kind is not (NetworkVerdictKind.Malicious or NetworkVerdictKind.Suspicious))
            {
                continue;
            }

            var endpoints = app?.Endpoints.Values.OrderByDescending(endpoint => endpoint.LastSeenUtc).ToList() ?? [];
            var connectedTo = endpoints.Count == 0
                ? "—"
                : DescribeEndpoint(endpoints[0]) + (endpoints.Count > 1 ? $"  (+{endpoints.Count - 1})" : "");
            if (!string.IsNullOrWhiteSpace(search)
                && !path.Contains(search, StringComparison.OrdinalIgnoreCase)
                && !assessment.Signer.Contains(search, StringComparison.OrdinalIgnoreCase)
                && !endpoints.Any(endpoint => DescribeEndpoint(endpoint).Contains(search, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            var connections = app is null ? "—" : online ? $"{app.CurrentConnections} now · {app.TotalConnections}" : $"{app.TotalConnections}";
            var lastSeen = app is null ? "—" : online ? "now" : FormatNetworkAge(now - app.LastSeenUtc);
            var status = blocked ? (online ? "Blocked (open conn.)" : "Blocked") : online ? "Online" : "Idle";
            rows.Add(new NetworkRow(
                path,
                [NetworkActivityTracker.DisplayName(path), assessment.Verdict.Label, assessment.Signer, connectedTo, connections, lastSeen, status],
                blocked,
                online,
                assessment));
        }

        return rows
            .OrderByDescending(row => row.Online)
            .ThenByDescending(row => row.Assessment.Untrusted)
            .ThenBy(row => row.Columns[0], StringComparer.OrdinalIgnoreCase)
            .ThenBy(row => row.Path, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string FormatNetworkAge(TimeSpan age) =>
        age.TotalSeconds < 60 ? $"{Math.Max(1, (int)age.TotalSeconds)} s ago"
        : age.TotalMinutes < 60 ? $"{(int)age.TotalMinutes} min ago"
        : age.TotalHours < 24 ? $"{(int)age.TotalHours} h ago"
        : $"{(int)age.TotalDays} d ago";

    private string BuildNetworkDetail(string path)
    {
        var assessment = AssessNetworkApp(path);
        var lines = new List<string> { path, $"Verdict: {assessment.Verdict.Label} · Signed by: {assessment.Signer}{(networkBlockedPaths.Contains(path) ? " · Blocked in Windows Firewall" : "")}" };
        if (networkTracker is not null && networkTracker.TryGetApp(path, out var app))
        {
            lines.Add($"PIDs: {string.Join(", ", app.Pids.OrderBy(pid => pid).Take(12))} · first seen {app.FirstSeenUtc.LocalDateTime:t} · {app.Endpoints.Count} endpoint(s)");
            var recent = app.Endpoints.Values.OrderByDescending(endpoint => endpoint.LastSeenUtc).Take(4)
                .Select(endpoint => $"{DescribeEndpoint(endpoint)} ({(endpoint.Scope == RemoteScope.Lan ? "LAN" : "internet")})");
            lines.Add("Recent: " + string.Join(", ", recent));
        }

        return string.Join(Environment.NewLine, lines);
    }

    private void ShowNetworkMonitor(string? selectPath = null)
    {
        if (networkWindow is { IsDisposed: false })
        {
            if (networkWindow.WindowState == FormWindowState.Minimized)
            {
                networkWindow.WindowState = FormWindowState.Normal;
            }

            networkWindow.Show();
            networkWindow.Activate();
            if (selectPath is not null)
            {
                selectNetworkApp?.Invoke(selectPath);
            }

            return;
        }

        EnsureNetworkTracker();
        ReloadNetworkBlockedPaths();
        var firewallState = FirewallRules.GetProfileState();
        var elevated = IsRunningElevated();

        var dialog = new Form
        {
            Text = "HashGuard Network Monitor",
            StartPosition = FormStartPosition.CenterScreen,
            Size = new Size(1180, 640),
            MinimumSize = new Size(900, 480),
            Icon = Icon,
            ShowInTaskbar = true,
        };
        var heading = new Label
        {
            Dock = DockStyle.Fill,
            AutoSize = false,
            Height = 30,
            Font = new Font("Segoe UI Semibold", 11, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft,
        };
        var bannerText = new List<string>();
        if (!firewallState.AllActiveProfilesEnabled)
        {
            bannerText.Add(firewallState.Description);
        }

        if (!elevated)
        {
            bannerText.Add("HashGuard isn't running elevated, so Block and Unblock are off and some system processes show as \"Unknown process\". Turn on Settings → Behavior → Run elevated.");
        }

        if (!appSettings.NetworkMonitorEnabled)
        {
            bannerText.Add("Background monitoring is off: HashGuard only watches while this window is open, and sends no alerts. Turn it on in Settings → Network.");
        }

        var banner = new Label
        {
            Text = string.Join(Environment.NewLine, bannerText),
            Dock = DockStyle.Fill,
            AutoSize = false,
            Height = 22 + 18 * bannerText.Count,
            Padding = new Padding(10, 6, 10, 6),
            BackColor = Color.FromArgb(255, 250, 220),
            ForeColor = Color.FromArgb(80, 60, 0),
            BorderStyle = BorderStyle.FixedSingle,
            Visible = bannerText.Count > 0,
            Tag = "callout",
            Margin = new Padding(0, 0, 0, 8),
        };
        var searchBox = new TextBox { PlaceholderText = "Search app, path, publisher, or host", Width = 360, Margin = new Padding(0, 0, 12, 0) };
        var hideTrusted = new CheckBox { Text = "Hide trusted publishers", AutoSize = true, Margin = new Padding(0, 3, 12, 0) };
        var showIdle = new CheckBox { Text = "Show apps not connected now", AutoSize = true, Checked = true, Margin = new Padding(0, 3, 0, 0) };
        var filters = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = false, Margin = new Padding(0, 0, 0, 8) };
        filters.Controls.AddRange([searchBox, hideTrusted, showIdle]);

        var view = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = false,
            HideSelection = false,
            MultiSelect = false,
            BorderStyle = BorderStyle.FixedSingle,
        };
        view.Columns.Add("App", 170);
        view.Columns.Add("Verdict", 110);
        view.Columns.Add("Signed by", 190);
        view.Columns.Add("Connected to", 300);
        view.Columns.Add("Connections", 100);
        view.Columns.Add("Last seen", 80);
        view.Columns.Add("Status", 130);
        var emptyLabel = new Label
        {
            Text = "Watching for connections…",
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleCenter,
            ForeColor = Color.DimGray,
            Font = new Font("Segoe UI", 10, FontStyle.Regular),
        };
        var listHost = new Panel { Dock = DockStyle.Fill };
        listHost.Controls.Add(emptyLabel);
        listHost.Controls.Add(view);
        emptyLabel.BringToFront();

        var detail = new Label
        {
            Dock = DockStyle.Fill,
            AutoSize = false,
            Height = 84,
            AutoEllipsis = true,
            Padding = new Padding(10, 8, 10, 8),
            BackColor = Color.White,
            ForeColor = Color.FromArgb(35, 35, 35),
            BorderStyle = BorderStyle.FixedSingle,
            Tag = "callout",
            Margin = new Padding(0, 8, 0, 0),
        };

        var block = new Button { Text = "Block", AutoSize = true };
        var unblock = new Button { Text = "Unblock", AutoSize = true };
        var scan = new Button { Text = "Scan app", AutoSize = true };
        var openLocation = new Button { Text = "Open File Location", AutoSize = true };
        var details = new Button { Text = "Connections…", AutoSize = true };
        var removeAll = new Button { Text = "Remove all HashGuard rules", AutoSize = true };
        var close = new Button { Text = "Close", AutoSize = true };
        var tips = new ToolTip();
        if (!elevated)
        {
            tips.SetToolTip(block, "Turn on Run elevated in Settings");
            tips.SetToolTip(unblock, "Turn on Run elevated in Settings");
        }

        tips.SetToolTip(removeAll, "Removes only the Windows Firewall rules HashGuard created (group \"HashGuard\")");
        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            AutoSize = true,
            FlowDirection = FlowDirection.RightToLeft,
            WrapContents = true,
            Padding = new Padding(0, 8, 0, 0),
        };
        buttons.Controls.AddRange([close, removeAll, details, openLocation, scan, unblock, block]);

        string? SelectedPath() => view.SelectedItems.Count > 0 ? view.SelectedItems[0].Tag as string : null;

        void UpdateSelectionUi()
        {
            var path = SelectedPath();
            var blocked = path is not null && networkBlockedPaths.Contains(path);
            var isFile = path is not null && File.Exists(path);
            block.Enabled = elevated && isFile && !blocked;
            unblock.Enabled = elevated && blocked;
            scan.Enabled = isFile;
            openLocation.Enabled = isFile;
            details.Enabled = path is not null && networkTracker is not null && networkTracker.TryGetApp(path, out _);
            removeAll.Enabled = elevated;
            detail.Text = path is null
                ? "Select an app to see where it connects. Block adds a Windows Firewall rule for that program; Unblock removes it."
                : BuildNetworkDetail(path);
        }

        void RefreshRows()
        {
            if (dialog.IsDisposed)
            {
                return;
            }

            var rows = BuildNetworkRows(searchBox.Text.Trim(), hideTrusted.Checked, showIdle.Checked);
            var selected = SelectedPath();
            var sameOrder = rows.Count == view.Items.Count
                && rows.Select(row => row.Path).SequenceEqual(view.Items.Cast<ListViewItem>().Select(item => (string)item.Tag!), StringComparer.OrdinalIgnoreCase);
            view.BeginUpdate();
            if (sameOrder)
            {
                for (var index = 0; index < rows.Count; index++)
                {
                    var item = view.Items[index];
                    for (var column = 0; column < rows[index].Columns.Length; column++)
                    {
                        if (item.SubItems[column].Text != rows[index].Columns[column])
                        {
                            item.SubItems[column].Text = rows[index].Columns[column];
                        }
                    }

                    StyleNetworkItem(item, rows[index]);
                }
            }
            else
            {
                var topPath = view.TopItem?.Tag as string;
                view.Items.Clear();
                foreach (var row in rows)
                {
                    var item = new ListViewItem(row.Columns[0]) { Tag = row.Path, UseItemStyleForSubItems = true };
                    for (var column = 1; column < row.Columns.Length; column++)
                    {
                        item.SubItems.Add(row.Columns[column]);
                    }

                    StyleNetworkItem(item, row);
                    view.Items.Add(item);
                    if (selected is not null && string.Equals(row.Path, selected, StringComparison.OrdinalIgnoreCase))
                    {
                        item.Selected = true;
                    }
                }

                var top = view.Items.Cast<ListViewItem>().FirstOrDefault(item => string.Equals(item.Tag as string, topPath, StringComparison.OrdinalIgnoreCase));
                if (top is not null)
                {
                    view.TopItem = top;
                }
            }

            view.EndUpdate();
            emptyLabel.Visible = view.Items.Count == 0;
            var online = networkTracker?.Apps.Count(app => app.CurrentConnections > 0) ?? 0;
            heading.Text = $"{online} app{(online == 1 ? "" : "s")} online · {networkBlockedPaths.Count} blocked by HashGuard";
            UpdateSelectionUi();
        }

        void SelectApp(string path)
        {
            showIdle.Checked = true;
            searchBox.Text = "";
            RefreshRows();
            foreach (ListViewItem item in view.Items)
            {
                if (string.Equals(item.Tag as string, path, StringComparison.OrdinalIgnoreCase))
                {
                    item.Selected = true;
                    item.EnsureVisible();
                    break;
                }
            }
        }

        view.SelectedIndexChanged += (_, _) => UpdateSelectionUi();
        searchBox.TextChanged += (_, _) => RefreshRows();
        hideTrusted.CheckedChanged += (_, _) => RefreshRows();
        showIdle.CheckedChanged += (_, _) => RefreshRows();
        block.Click += (_, _) =>
        {
            if (SelectedPath() is { } path && BlockNetworkApp(dialog, path))
            {
                RefreshRows();
            }
        };
        unblock.Click += (_, _) =>
        {
            if (SelectedPath() is { } path && UnblockNetworkApp(dialog, path))
            {
                RefreshRows();
            }
        };
        scan.Click += async (_, _) =>
        {
            if (SelectedPath() is not { } path)
            {
                return;
            }

            networkAssessments.Remove(path);
            detail.Text = $"Scanning {NetworkActivityTracker.DisplayName(path)}… the result appears in the Review Queue and here.";
            await ScanSelectedFilesAsync([path]);
            networkAssessments.Remove(path);
            RefreshRows();
        };
        openLocation.Click += (_, _) =>
        {
            if (SelectedPath() is { } path && File.Exists(path))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
            }
        };
        details.Click += (_, _) =>
        {
            if (SelectedPath() is { } path && networkTracker is not null && networkTracker.TryGetApp(path, out var app))
            {
                ShowNetworkConnectionsDialog(dialog, app);
            }
        };
        view.DoubleClick += (_, _) => details.PerformClick();
        removeAll.Click += (_, _) =>
        {
            RemoveAllNetworkRules(dialog);
            RefreshRows();
        };
        close.Click += (_, _) => dialog.Close();

        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 6, ColumnCount = 1, Padding = new Padding(12) };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.Controls.Add(heading, 0, 0);
        layout.Controls.Add(banner, 0, 1);
        layout.Controls.Add(filters, 0, 2);
        layout.Controls.Add(listHost, 0, 3);
        layout.Controls.Add(detail, 0, 4);
        layout.Controls.Add(buttons, 0, 5);
        dialog.Controls.Add(layout);
        dialog.CancelButton = close;
        ApplyAppTheme(dialog);

        dialog.FormClosed += (_, _) =>
        {
            networkWindow = null;
            refreshNetworkWindow = null;
            selectNetworkApp = null;
            tips.Dispose();
            UpdateNetworkTimer();
        };

        networkWindow = dialog;
        refreshNetworkWindow = RefreshRows;
        selectNetworkApp = SelectApp;
        RefreshRows();
        dialog.Show();
        UpdateNetworkTimer();
        if (selectPath is not null)
        {
            SelectApp(selectPath);
        }
    }

    private void StyleNetworkItem(ListViewItem item, NetworkRow row)
    {
        var color = row.Assessment.Verdict.Kind switch
        {
            NetworkVerdictKind.Malicious => Color.FromArgb(190, 30, 30),
            NetworkVerdictKind.Suspicious => Color.FromArgb(170, 110, 0),
            _ when row.Blocked => activePalette.MutedText,
            _ => activePalette.Text,
        };
        if (item.ForeColor != color)
        {
            item.ForeColor = color;
        }
    }

    private void ShowNetworkConnectionsDialog(IWin32Window owner, NetworkAppActivity app)
    {
        using var dialog = new Form
        {
            Text = $"{app.Name}: connections this session",
            StartPosition = FormStartPosition.CenterParent,
            Size = new Size(860, 460),
            MinimumSize = new Size(600, 320),
        };
        var view = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, BorderStyle = BorderStyle.FixedSingle };
        view.Columns.Add("Host", 280);
        view.Columns.Add("Address", 200);
        view.Columns.Add("Port", 60);
        view.Columns.Add("Network", 80);
        view.Columns.Add("First seen", 100);
        view.Columns.Add("Last seen", 100);
        foreach (var endpoint in app.Endpoints.Values.OrderByDescending(endpoint => endpoint.LastSeenUtc))
        {
            var host = networkHostNames.TryGetValue(endpoint.Address, out var name) && !string.IsNullOrWhiteSpace(name) ? name : "—";
            var item = new ListViewItem(host);
            item.SubItems.Add(endpoint.Address);
            item.SubItems.Add(endpoint.Port.ToString(System.Globalization.CultureInfo.InvariantCulture));
            item.SubItems.Add(endpoint.Scope == RemoteScope.Lan ? "LAN" : "Internet");
            item.SubItems.Add(endpoint.FirstSeenUtc.LocalDateTime.ToString("T"));
            item.SubItems.Add(endpoint.LastSeenUtc.LocalDateTime.ToString("T"));
            view.Items.Add(item);
        }

        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.OK, Dock = DockStyle.Right };
        var footer = new Panel { Dock = DockStyle.Bottom, Height = 40, Padding = new Padding(0, 8, 0, 0) };
        footer.Controls.Add(close);
        var content = new Panel { Dock = DockStyle.Fill, Padding = new Padding(12) };
        content.Controls.Add(view);
        content.Controls.Add(footer);
        dialog.Controls.Add(content);
        dialog.AcceptButton = close;
        ApplyAppTheme(dialog);
        dialog.ShowDialog(owner);
    }
}
