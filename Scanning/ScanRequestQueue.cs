namespace HashGuardScanner;

internal enum ScanRequestOutcome
{
    Queued,
    Duplicate,
    Full,
}

/// <summary>
/// Bounded, de-duplicated queue for Explorer right-click (<c>--scan-file</c>) requests.
/// A multi-file selection or a repeated click arrives as a burst of pipe requests; this keeps
/// the burst to one queued entry per path, drops a repeat of the same path within
/// <see cref="RepeatWindow"/>, and caps the queue so a flood cannot grow it without bound.
/// </summary>
internal sealed class ScanRequestQueue
{
    public const int MaxQueued = 50;
    public static readonly TimeSpan RepeatWindow = TimeSpan.FromSeconds(5);

    private readonly object gate = new();
    private readonly Queue<string> queue = new();
    private readonly HashSet<string> queued = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> lastAcceptedUtc = new(StringComparer.OrdinalIgnoreCase);

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

    public ScanRequestOutcome TryEnqueue(string path, DateTimeOffset nowUtc)
    {
        lock (gate)
        {
            if (queued.Contains(path)
                || (lastAcceptedUtc.TryGetValue(path, out var last) && nowUtc - last < RepeatWindow))
            {
                return ScanRequestOutcome.Duplicate;
            }

            if (queue.Count >= MaxQueued)
            {
                return ScanRequestOutcome.Full;
            }

            PruneRepeatWindow(nowUtc);
            lastAcceptedUtc[path] = nowUtc;
            queued.Add(path);
            queue.Enqueue(path);
            return ScanRequestOutcome.Queued;
        }
    }

    /// <summary>Removes and returns everything queued, oldest first.</summary>
    public List<string> DequeueAll()
    {
        lock (gate)
        {
            var paths = queue.ToList();
            queue.Clear();
            queued.Clear();
            return paths;
        }
    }

    private void PruneRepeatWindow(DateTimeOffset nowUtc)
    {
        if (lastAcceptedUtc.Count < MaxQueued * 2)
        {
            return;
        }

        foreach (var path in lastAcceptedUtc.Where(item => nowUtc - item.Value >= RepeatWindow).Select(item => item.Key).ToList())
        {
            lastAcceptedUtc.Remove(path);
        }
    }
}
