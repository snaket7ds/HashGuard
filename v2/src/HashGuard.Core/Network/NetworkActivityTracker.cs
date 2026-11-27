using System.Net;
using System.Text.Json;

namespace HashGuard.Core;

public static class NetworkNotifyModes
{
    /// <summary>Alert when an app HashGuard doesn't trust connects for the first time (default).</summary>
    public const string Untrusted = "untrusted";
    /// <summary>Alert when any app connects for the first time.</summary>
    public const string NewApps = "new";
    public const string Never = "never";

    public static string Normalize(string? mode) => mode switch
    {
        NewApps => NewApps,
        Never => Never,
        _ => Untrusted,
    };
}

public enum NetworkVerdictKind
{
    NotScanned,
    Unknown,
    Clean,
    Suspicious,
    Malicious,
}

public sealed record NetworkVerdict(NetworkVerdictKind Kind, string Label)
{
    public static readonly NetworkVerdict NotScanned = new(NetworkVerdictKind.NotScanned, "Not scanned");

    /// <summary>The Network Monitor verdict for a cached scan entry (null = never scanned).</summary>
    public static NetworkVerdict FromCache(CacheEntry? entry)
    {
        if (entry is null)
        {
            return NotScanned;
        }

        if (entry.Malicious > 0)
        {
            return new(NetworkVerdictKind.Malicious, $"Malicious ({entry.Malicious})");
        }

        if (entry.Suspicious > 0)
        {
            return new(NetworkVerdictKind.Suspicious, $"Suspicious ({entry.Suspicious})");
        }

        return HashCache.IsCleanEntry(entry)
            ? new(NetworkVerdictKind.Clean, "Clean")
            : new(NetworkVerdictKind.Unknown, "Unknown");
    }

    /// <summary>
    /// "Untrusted" for alerts: flagged by a provider, or not from a trusted publisher and
    /// either unsigned or not known clean.
    /// </summary>
    public static bool IsUntrusted(NetworkVerdictKind verdict, bool signed, bool trustedPublisher) =>
        verdict is NetworkVerdictKind.Malicious or NetworkVerdictKind.Suspicious
        || (!trustedPublisher && (!signed || verdict != NetworkVerdictKind.Clean));
}

public sealed class NetworkEndpoint
{
    public required string Address { get; init; }
    public required int Port { get; init; }
    public required RemoteScope Scope { get; init; }
    public DateTimeOffset FirstSeenUtc { get; set; }
    public DateTimeOffset LastSeenUtc { get; set; }
    public string Key => FormatEndpoint(Address, Port);

    public static string FormatEndpoint(string address, int port) =>
        address.Contains(':') ? $"[{address}]:{port}" : $"{address}:{port}";
}

/// <summary>Everything the monitor knows about one program's network use this session.</summary>
public sealed class NetworkAppActivity
{
    public const int MaxEndpoints = 200;

    public required string Path { get; init; }
    public string Name => NetworkActivityTracker.DisplayName(Path);
    public DateTimeOffset FirstSeenUtc { get; set; }
    public DateTimeOffset LastSeenUtc { get; set; }
    public int CurrentConnections { get; set; }
    /// <summary>Distinct connections seen this session (a connection open across polls counts once).</summary>
    public int TotalConnections { get; set; }
    public HashSet<int> Pids { get; } = [];
    public Dictionary<string, NetworkEndpoint> Endpoints { get; } = new(StringComparer.OrdinalIgnoreCase);

    public NetworkEndpoint? MostRecentEndpoint =>
        Endpoints.Values.OrderByDescending(endpoint => endpoint.LastSeenUtc).ThenBy(endpoint => endpoint.Key, StringComparer.Ordinal).FirstOrDefault();
}

/// <summary>First and last time an app was ever seen online; persisted across sessions.</summary>
public sealed class SeenNetworkApp
{
    public DateTimeOffset FirstSeenUtc { get; set; }
    public DateTimeOffset LastSeenUtc { get; set; }
}

public sealed record NetworkUpdateResult(IReadOnlyList<NetworkAppActivity> FirstEverSeen, bool SeenAppsChanged);

/// <summary>
/// Aggregates TCP table polls per program. Pure (no OS calls), so the rules for new
/// connections, first-ever-seen apps and the caps are unit-tested.
/// </summary>
public sealed class NetworkActivityTracker
{
    public const int DefaultMaxSeenApps = 2000;
    public const int MaxSessionApps = 1000;

    private readonly Dictionary<string, NetworkAppActivity> apps = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, SeenNetworkApp> seenApps;
    private readonly int maxSeenApps;
    private HashSet<string> previousConnectionKeys = new(StringComparer.Ordinal);

    public NetworkActivityTracker(Dictionary<string, SeenNetworkApp>? seenApps = null, int maxSeenApps = DefaultMaxSeenApps)
    {
        this.seenApps = seenApps is null
            ? new(StringComparer.OrdinalIgnoreCase)
            : new(seenApps, StringComparer.OrdinalIgnoreCase);
        this.maxSeenApps = Math.Max(1, maxSeenApps);
    }

    public IReadOnlyCollection<NetworkAppActivity> Apps => apps.Values;
    public IReadOnlyDictionary<string, SeenNetworkApp> SeenApps => seenApps;

    public bool TryGetApp(string path, out NetworkAppActivity app) => apps.TryGetValue(path, out app!);

    /// <summary>
    /// Applies one poll. <paramref name="connections"/> are the outbound candidates with the
    /// owning program's path. Returns the apps seen online for the first time ever.
    /// </summary>
    public NetworkUpdateResult Update(IEnumerable<(string Path, TcpConnection Connection)> connections, DateTimeOffset nowUtc)
    {
        var currentKeys = new HashSet<string>(StringComparer.Ordinal);
        var currentCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var firstEver = new List<NetworkAppActivity>();
        var seenChanged = false;

        foreach (var (path, connection) in connections)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                continue;
            }

            if (!apps.TryGetValue(path, out var app))
            {
                if (apps.Count >= MaxSessionApps)
                {
                    DropStalestSessionApp();
                }

                app = new NetworkAppActivity { Path = path, FirstSeenUtc = nowUtc };
                apps[path] = app;
            }

            app.LastSeenUtc = nowUtc;
            app.Pids.Add(connection.Pid);
            currentCounts[path] = currentCounts.GetValueOrDefault(path) + 1;

            var key = connection.Key;
            if (currentKeys.Add(key) && !previousConnectionKeys.Contains(key))
            {
                app.TotalConnections++;
            }

            var address = (connection.RemoteAddress.IsIPv4MappedToIPv6 ? connection.RemoteAddress.MapToIPv4() : connection.RemoteAddress).ToString();
            var endpointKey = NetworkEndpoint.FormatEndpoint(address, connection.RemotePort);
            if (!app.Endpoints.TryGetValue(endpointKey, out var endpoint))
            {
                if (app.Endpoints.Count >= NetworkAppActivity.MaxEndpoints)
                {
                    var stalest = app.Endpoints.Values.OrderBy(item => item.LastSeenUtc).First();
                    app.Endpoints.Remove(stalest.Key);
                }

                endpoint = new NetworkEndpoint
                {
                    Address = address,
                    Port = connection.RemotePort,
                    Scope = ConnectionTable.Classify(connection.RemoteAddress),
                    FirstSeenUtc = nowUtc,
                };
                app.Endpoints[endpointKey] = endpoint;
            }

            endpoint.LastSeenUtc = nowUtc;

            if (seenApps.TryGetValue(path, out var seen))
            {
                if (nowUtc - seen.LastSeenUtc >= TimeSpan.FromHours(1))
                {
                    seen.LastSeenUtc = nowUtc;
                    seenChanged = true;
                }
            }
            else
            {
                if (seenApps.Count >= maxSeenApps)
                {
                    var oldest = seenApps.OrderBy(item => item.Value.LastSeenUtc).First().Key;
                    seenApps.Remove(oldest);
                }

                seenApps[path] = new SeenNetworkApp { FirstSeenUtc = nowUtc, LastSeenUtc = nowUtc };
                seenChanged = true;
                firstEver.Add(app);
            }
        }

        foreach (var app in apps.Values)
        {
            app.CurrentConnections = currentCounts.GetValueOrDefault(app.Path);
        }

        previousConnectionKeys = currentKeys;
        return new NetworkUpdateResult(firstEver, seenChanged);
    }

    private void DropStalestSessionApp()
    {
        var stalest = apps.Values
            .Where(app => app.CurrentConnections == 0)
            .OrderBy(app => app.LastSeenUtc)
            .FirstOrDefault()
            ?? apps.Values.OrderBy(app => app.LastSeenUtc).First();
        apps.Remove(stalest.Path);
    }

    /// <summary>File name of a Windows path ("System" stays "System").</summary>
    public static string DisplayName(string path)
    {
        var cut = path.LastIndexOfAny(['\\', '/']);
        return cut >= 0 && cut < path.Length - 1 ? path[(cut + 1)..] : path;
    }

    public static Dictionary<string, SeenNetworkApp> LoadSeenApps(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                var loaded = JsonSerializer.Deserialize<Dictionary<string, SeenNetworkApp>>(File.ReadAllText(path));
                if (loaded is not null)
                {
                    return new(loaded, StringComparer.OrdinalIgnoreCase);
                }
            }
        }
        catch
        {
            // A corrupt file only means apps are treated as new once more.
        }

        return new(StringComparer.OrdinalIgnoreCase);
    }

    public void SaveSeenApps(string path)
    {
        var directory = System.IO.Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(seenApps, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temp, path, overwrite: true);
    }
}
