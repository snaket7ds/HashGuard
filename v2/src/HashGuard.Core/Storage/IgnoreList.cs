using System.Text;
using System.Text.Json;

namespace HashGuard.Core;

/// <summary>
/// Files the user chose to ignore: by hash (that exact file anywhere) or by path (anything at
/// that location). Stored as v1 did, in <c>config\ignored-hashes.json</c> and <c>config\ignored-paths.json</c>.
/// </summary>
public sealed class IgnoreList(string? hashesPath = null, string? pathsPath = null)
{
    private static readonly JsonSerializerOptions WriteOptions = new() { WriteIndented = true };
    private readonly string hashesPath = hashesPath ?? AppPaths.GetIgnoredHashesPath();
    private readonly string pathsPath = pathsPath ?? AppPaths.GetIgnoredPathsPath();
    private readonly Lock gate = new();
    private HashSet<string> hashes = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> paths = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>A copy of the ignored hashes, safe to hand to a scan.</summary>
    public IReadOnlySet<string> Hashes
    {
        get
        {
            lock (gate)
            {
                return new HashSet<string>(hashes, StringComparer.OrdinalIgnoreCase);
            }
        }
    }

    /// <summary>A copy of the ignored paths, safe to hand to a scan.</summary>
    public IReadOnlySet<string> Paths
    {
        get
        {
            lock (gate)
            {
                return new HashSet<string>(paths, StringComparer.OrdinalIgnoreCase);
            }
        }
    }

    public void Load()
    {
        var loadedHashes = Read(hashesPath);
        var loadedPaths = Read(pathsPath);
        lock (gate)
        {
            hashes = loadedHashes;
            paths = loadedPaths;
        }
    }

    public void AddHash(string sha256) => Change(ref hashes, sha256, add: true, hashesPath);

    public void RemoveHash(string sha256) => Change(ref hashes, sha256, add: false, hashesPath);

    public void AddPath(string path) => Change(ref paths, path, add: true, pathsPath);

    public void RemovePath(string path) => Change(ref paths, path, add: false, pathsPath);

    private void Change(ref HashSet<string> set, string value, bool add, string file)
    {
        value = value.Trim();
        if (value.Length == 0)
        {
            return;
        }

        string[] snapshot;
        lock (gate)
        {
            var changed = add ? set.Add(value) : set.Remove(value);
            if (!changed)
            {
                return;
            }

            snapshot = [.. set.Order(StringComparer.OrdinalIgnoreCase)];
        }

        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllText(file, JsonSerializer.Serialize(snapshot, WriteOptions), Encoding.UTF8);
    }

    private static HashSet<string> Read(string file)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (File.Exists(file))
            {
                foreach (var value in JsonSerializer.Deserialize<List<string>>(File.ReadAllText(file, Encoding.UTF8)) ?? [])
                {
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        set.Add(value.Trim());
                    }
                }
            }
        }
        catch
        {
            // A malformed list is treated as empty; the user can ignore files again.
        }

        return set;
    }
}
