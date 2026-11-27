namespace HashGuard.Core;

/// <summary>
/// Files waiting to be checked because the user opened or selected them. Skips pictures, video,
/// audio and camera raw files, files it already queued, and files unchanged since they were last
/// queued; holds at most <see cref="MaxQueued"/>.
/// </summary>
public sealed class FileActivityQueue
{
    public const int MaxQueued = 200;

    /// <summary>Media types v1 never scanned on open: large, personal, and not executable.</summary>
    public static readonly IReadOnlySet<string> ExcludedExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        ".3fr", ".3g2", ".3gp", ".aif", ".aiff", ".arw", ".avi", ".bmp", ".cr2", ".cr3", ".crw", ".dcr", ".dng",
        ".erf", ".flac", ".flv", ".gif", ".heic", ".heif", ".iiq", ".jpeg", ".jpg", ".k25", ".kdc", ".m2ts",
        ".m4a", ".m4v", ".mef", ".mkv", ".mos", ".mov", ".mp3", ".mp4", ".mpeg", ".mpg", ".mrw", ".mts", ".nef",
        ".nrw", ".ogg", ".orf", ".pef", ".png", ".raf", ".raw", ".rw2", ".rwl", ".sr2", ".srf", ".tif", ".tiff",
        ".wav", ".webm", ".webp", ".wma", ".wmv", ".x3f",
    };

    private readonly Lock gate = new();
    private readonly List<string> queue = [];
    private readonly HashSet<string> queued = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (long Length, DateTime LastWriteUtc)> lastQueued = new(StringComparer.OrdinalIgnoreCase);

    public int Count
    {
        get
        {
            lock (gate)
            {
                return queue.Count;
            }
        }
    }

    /// <summary>Queues the file if it should be checked; returns whether it was queued.</summary>
    public bool TryAdd(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || ExcludedExtensions.Contains(Path.GetExtension(path)))
        {
            return false;
        }

        (long, DateTime) state;
        try
        {
            path = Path.GetFullPath(path);
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                return false;
            }

            state = (info.Length, info.LastWriteTimeUtc);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
        }

        lock (gate)
        {
            if (queued.Contains(path) || queue.Count >= MaxQueued
                || (lastQueued.TryGetValue(path, out var previous) && previous == state))
            {
                return false;
            }

            if (lastQueued.Count > 5000)
            {
                lastQueued.Clear();
            }

            lastQueued[path] = state;
            queued.Add(path);
            queue.Add(path);
            return true;
        }
    }

    /// <summary>Removes and returns everything queued that still exists, oldest first.</summary>
    public List<string> TakeAll()
    {
        lock (gate)
        {
            var taken = queue.Where(File.Exists).ToList();
            queue.Clear();
            queued.Clear();
            return taken;
        }
    }

    public void Clear()
    {
        lock (gate)
        {
            queue.Clear();
            queued.Clear();
            lastQueued.Clear();
        }
    }
}

/// <summary>
/// Notices files the user opens or selects, as v1 did: shortcuts Windows adds to the Recent folder
/// (pointing at files just opened), and every 15 seconds the selected or focused file in each open
/// File Explorer window. Nothing is read from the files here; they're only queued.
/// </summary>
public sealed class FileActivityWatcher : IDisposable
{
    private static readonly TimeSpan ExplorerPollInterval = TimeSpan.FromSeconds(15);

    private readonly FileActivityQueue queue;
    private FileSystemWatcher? recentWatcher;
    private CancellationTokenSource? stop;

    public FileActivityWatcher(FileActivityQueue queue) => this.queue = queue;

    /// <summary>Raised (on a worker thread) when a file was queued.</summary>
    public event Action? Queued;

    public bool IsRunning => stop is not null;

    public void Start()
    {
        if (stop is not null)
        {
            return;
        }

        stop = new CancellationTokenSource();
        StartRecentWatcher();
        var token = stop.Token;
        _ = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                PollExplorerSelection();
                try
                {
                    await Task.Delay(ExplorerPollInterval, token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        });
    }

    public void Stop()
    {
        stop?.Cancel();
        stop?.Dispose();
        stop = null;
        recentWatcher?.Dispose();
        recentWatcher = null;
        queue.Clear();
    }

    public void Dispose() => Stop();

    private void StartRecentWatcher()
    {
        var recent = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
        if (string.IsNullOrWhiteSpace(recent) || !Directory.Exists(recent))
        {
            return;
        }

        try
        {
            recentWatcher = new FileSystemWatcher(recent, "*.lnk")
            {
                IncludeSubdirectories = false,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                InternalBufferSize = 16 * 1024,
            };
            recentWatcher.Created += (_, e) => Add(ResolveShortcut(e.FullPath));
            recentWatcher.Changed += (_, e) => Add(ResolveShortcut(e.FullPath));
            recentWatcher.Renamed += (_, e) => Add(ResolveShortcut(e.FullPath));
            recentWatcher.EnableRaisingEvents = true;
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or UnauthorizedAccessException)
        {
            recentWatcher = null; // Only the Explorer selection is watched then.
        }
    }

    private void Add(string? path)
    {
        if (queue.TryAdd(path))
        {
            Queued?.Invoke();
        }
    }

    /// <summary>A shortcut's target, through the Windows Script Host shell (as v1 did).</summary>
    private static string? ResolveShortcut(string shortcutPath) => RunSta(() =>
    {
        var shellType = Type.GetTypeFromProgID("WScript.Shell");
        if (shellType is null)
        {
            return null;
        }

        dynamic shell = Activator.CreateInstance(shellType)!;
        dynamic shortcut = shell.CreateShortcut(shortcutPath);
        return (string?)shortcut.TargetPath;
    });

    /// <summary>The selected (or, failing that, focused) file of every open File Explorer window.</summary>
    private void PollExplorerSelection()
    {
        var paths = RunSta(() =>
        {
            var found = new List<string>();
            var shellType = Type.GetTypeFromProgID("Shell.Application");
            if (shellType is null)
            {
                return found;
            }

            dynamic shell = Activator.CreateInstance(shellType)!;
            foreach (var window in shell.Windows())
            {
                try
                {
                    string? fullName = window.FullName;
                    if (!string.Equals(Path.GetFileName(fullName), "explorer.exe", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var document = window.Document;
                    var selected = new List<string>();
                    foreach (var item in document.SelectedItems())
                    {
                        if ((string?)item.Path is { Length: > 0 } path)
                        {
                            selected.Add(path);
                        }
                    }

                    if (selected.Count == 0 && document.FocusedItem is { } focused && (string?)focused.Path is { Length: > 0 } focusedPath)
                    {
                        selected.Add(focusedPath);
                    }

                    found.AddRange(selected);
                }
                catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException or InvalidCastException)
                {
                    // A window closing, or not a folder view: skip it.
                }
            }

            return found;
        }) ?? [];

        foreach (var path in paths)
        {
            Add(path);
        }
    }

    /// <summary>Runs shell COM calls on a short-lived single-threaded apartment thread, as the shell expects; failures give the default.</summary>
    private static T? RunSta<T>(Func<T?> work)
    {
        T? result = default;
        var thread = new Thread(() =>
        {
            try
            {
                result = work();
            }
            catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException or InvalidCastException or UnauthorizedAccessException)
            {
                result = default;
            }
        })
        {
            IsBackground = true,
        };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return thread.Join(TimeSpan.FromSeconds(10)) ? result : default;
    }
}
