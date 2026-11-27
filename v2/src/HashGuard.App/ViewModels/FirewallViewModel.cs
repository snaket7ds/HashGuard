using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using HashGuard.App.Services;
using HashGuard.Core;

namespace HashGuard.App.ViewModels;

/// <summary>One program on the Firewall page; updated in place on every poll so the list doesn't flicker.</summary>
public sealed partial class FirewallAppViewModel(string path) : ObservableObject
{
    public string Path { get; } = path;

    public FirewallAppViewModel Self => this;

    [ObservableProperty] public partial NetworkAppView View { get; set; } = null!;

    public string Name => View.Name;

    public string Verdict => View.Verdict.Label;

    public string Signer => View.Signer;

    public bool Blocked => View.Blocked;

    public bool Online => View.Online;

    /// <summary>"Online", "Blocked", "Idle · 5 min ago"…</summary>
    public string Status => View.Blocked
        ? View.Online ? "Blocked · connection still open" : "Blocked"
        : View.Online ? View.CurrentConnections == 1 ? "Online · 1 connection" : $"Online · {View.CurrentConnections} connections"
        : View.LastSeenUtc is { } seen ? $"Idle · {Age(DateTimeOffset.UtcNow - seen)}" : "Idle";

    public string ConnectedTo => View.Endpoints.Count == 0
        ? "No connections seen this session"
        : View.Endpoints[0].Display + (View.Endpoints.Count > 1 ? $" and {View.Endpoints.Count - 1} more" : "");

    /// <summary>The tone of the row's tile: danger for flagged or blocked, attention for untrusted, good otherwise.</summary>
    public ActivityKind Tone => View.Verdict.Kind is NetworkVerdictKind.Malicious ? ActivityKind.Threat
        : View.Blocked ? ActivityKind.Firewall
        : View.Verdict.Kind is NetworkVerdictKind.Suspicious || View.Untrusted ? ActivityKind.Suspicious
        : ActivityKind.Clean;

    public string Glyph => View.Blocked ? "" : View.Online ? "" : "";

    public IReadOnlyList<EndpointRow> Endpoints => [.. View.Endpoints.Select(e => new EndpointRow(
        e.Host.Length > 0 ? e.Host : e.Address,
        NetworkEndpoint.FormatEndpoint(e.Address, e.Port),
        e.Scope == RemoteScope.Lan ? "Local network" : "Internet",
        e.LastSeenUtc.LocalDateTime.ToString("T", CultureInfo.CurrentCulture)))];

    partial void OnViewChanged(NetworkAppView value)
    {
        OnPropertyChanged(nameof(Name));
        OnPropertyChanged(nameof(Verdict));
        OnPropertyChanged(nameof(Signer));
        OnPropertyChanged(nameof(Blocked));
        OnPropertyChanged(nameof(Online));
        OnPropertyChanged(nameof(Status));
        OnPropertyChanged(nameof(ConnectedTo));
        OnPropertyChanged(nameof(Tone));
        OnPropertyChanged(nameof(Glyph));
        OnPropertyChanged(nameof(Endpoints));
    }

    private static string Age(TimeSpan age) =>
        age.TotalSeconds < 60 ? "just now"
        : age.TotalMinutes < 60 ? $"{(int)age.TotalMinutes} min ago"
        : age.TotalHours < 24 ? $"{(int)age.TotalHours} h ago"
        : $"{(int)age.TotalDays} d ago";
}

public sealed record EndpointRow(string Host, string Address, string Network, string LastSeen);

/// <summary>
/// The Firewall page: programs using the network, newest picture every second while the page is
/// open, with Block and Unblock. Filtering and the snapshot happen off the UI thread.
/// </summary>
public sealed partial class FirewallViewModel : ObservableObject
{
    private readonly Dictionary<string, FirewallAppViewModel> byPath = new(StringComparer.OrdinalIgnoreCase);
    private bool refreshing;

    public ObservableCollection<FirewallAppViewModel> Apps { get; } = [];

    [ObservableProperty] public partial FirewallAppViewModel? Selected { get; set; }
    [ObservableProperty] public partial string Search { get; set; } = "";
    [ObservableProperty] public partial bool HideTrusted { get; set; }
    [ObservableProperty] public partial bool ShowIdle { get; set; } = true;
    [ObservableProperty] public partial string Summary { get; set; } = "";
    [ObservableProperty] public partial string EmptyText { get; set; } = "Watching for connections…";
    [ObservableProperty] public partial bool IsEmpty { get; set; } = true;
    [ObservableProperty] public partial string? FirewallWarning { get; set; }

    public bool HasSelection => Selected is not null;

    public bool IsElevated => AppServices.Instance.Network.IsElevated;

    public bool MonitorOff => !AppServices.Instance.Settings.NetworkMonitorEnabled;

    partial void OnSelectedChanged(FirewallAppViewModel? value) => OnPropertyChanged(nameof(HasSelection));

    partial void OnSearchChanged(string value) => _ = RefreshAsync();

    partial void OnHideTrustedChanged(bool value) => _ = RefreshAsync();

    partial void OnShowIdleChanged(bool value) => _ = RefreshAsync();

    public async Task LoadAsync()
    {
        OnPropertyChanged(nameof(IsElevated));
        OnPropertyChanged(nameof(MonitorOff));
        var state = await Task.Run(AppServices.Instance.Network.ProfileState);
        FirewallWarning = state.AllActiveProfilesEnabled ? null : state.Description;
        await RefreshAsync();
    }

    /// <summary>Brings the list up to date, keeping the selection and the order of untouched rows where possible.</summary>
    public async Task RefreshAsync()
    {
        if (refreshing)
        {
            return;
        }

        refreshing = true;
        try
        {
            var search = Search.Trim();
            var hideTrusted = HideTrusted;
            var showIdle = ShowIdle;
            var (views, total, online) = await Task.Run(() =>
            {
                var all = AppServices.Instance.Network.Snapshot();
                var shown = all.Where(view =>
                        (showIdle || view.Online || view.Blocked)
                        && !(hideTrusted && view.TrustedPublisher && !view.Blocked && view.Verdict.Kind is not (NetworkVerdictKind.Malicious or NetworkVerdictKind.Suspicious))
                        && (search.Length == 0
                            || view.Path.Contains(search, StringComparison.OrdinalIgnoreCase)
                            || view.Signer.Contains(search, StringComparison.OrdinalIgnoreCase)
                            || view.Endpoints.Any(e => e.Display.Contains(search, StringComparison.OrdinalIgnoreCase))))
                    .ToList();
                return (shown, all.Count, all.Count(v => v.Online));
            });

            Apply(views);
            Summary = total == 0 ? "" : $"{online.ToString("N0", CultureInfo.CurrentCulture)} online now · {total.ToString("N0", CultureInfo.CurrentCulture)} seen this session";
            IsEmpty = Apps.Count == 0;
            EmptyText = total == 0
                ? MonitorOff ? "Network watching is off. Turn it on in Settings, or keep this page open to watch for now." : "Watching for connections… programs appear here as soon as they go online."
                : "No program matches this filter.";
        }
        finally
        {
            refreshing = false;
        }
    }

    private void Apply(List<NetworkAppView> views)
    {
        var wanted = new HashSet<string>(views.Select(v => v.Path), StringComparer.OrdinalIgnoreCase);
        for (var i = Apps.Count - 1; i >= 0; i--)
        {
            if (!wanted.Contains(Apps[i].Path))
            {
                byPath.Remove(Apps[i].Path);
                Apps.RemoveAt(i);
            }
        }

        for (var i = 0; i < views.Count; i++)
        {
            if (!byPath.TryGetValue(views[i].Path, out var item))
            {
                item = new FirewallAppViewModel(views[i].Path);
                byPath[item.Path] = item;
            }

            if (!ReferenceEquals(item.View, views[i]))
            {
                item.View = views[i];
            }

            var at = Apps.IndexOf(item);
            if (at == -1)
            {
                Apps.Insert(i, item);
            }
            else if (at != i)
            {
                Apps.Move(at, i);
            }
        }

        if (Selected is not null && !byPath.ContainsKey(Selected.Path))
        {
            Selected = null;
        }
    }

    /// <summary>Blocks the program; returns an error message, or null when it worked.</summary>
    public async Task<string?> BlockAsync(FirewallAppViewModel app, bool alsoInbound)
    {
        try
        {
            await Task.Run(() => AppServices.Instance.Network.Block(app.Path, alsoInbound));
            await RefreshAsync();
            return null;
        }
        catch (Exception ex)
        {
            return ex is System.Runtime.InteropServices.COMException ? $"Windows Firewall refused the rule: {ex.Message}" : ex.Message;
        }
    }

    /// <summary>Unblocks the program; returns an error message, or null when it worked.</summary>
    public async Task<string?> UnblockAsync(FirewallAppViewModel app)
    {
        try
        {
            var removed = await Task.Run(() => AppServices.Instance.Network.Unblock(app.Path));
            await RefreshAsync();
            return removed == 0 ? "HashGuard found no rule of its own for this program. It may have been removed in Windows Firewall already." : null;
        }
        catch (Exception ex)
        {
            return ex is System.Runtime.InteropServices.COMException ? $"Windows Firewall refused the change: {ex.Message}" : ex.Message;
        }
    }

    /// <summary>Removes every HashGuard rule; returns a message to show.</summary>
    public async Task<string> RemoveAllAsync()
    {
        try
        {
            var removed = await Task.Run(AppServices.Instance.Network.RemoveAllRules);
            await RefreshAsync();
            return removed == 0 ? "HashGuard has no Windows Firewall rules right now." : removed == 1 ? "Removed 1 rule." : $"Removed {removed} rules.";
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }
}
