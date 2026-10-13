namespace HashGuardScanner;

/// <summary>
/// Runs a small number of per-item tasks at once and hands back results in input order.
/// Used so provider lookups for different files overlap without changing result order.
/// </summary>
internal static class OrderedConcurrency
{
    /// <summary>
    /// Starts up to <paramref name="maxInFlight"/> calls of <paramref name="start"/> and calls
    /// <paramref name="onCompleted"/> for each item in input order. On failure or cancellation,
    /// waits for the calls still running before rethrowing, so nothing outlives the caller.
    /// </summary>
    public static async Task ForEachAsync<TItem, TResult>(
        IReadOnlyList<TItem> items,
        int maxInFlight,
        Func<TItem, Task<TResult>> start,
        Func<int, TResult, Task> onCompleted,
        CancellationToken cancellationToken = default)
    {
        maxInFlight = Math.Max(1, maxInFlight);
        var inFlight = new Queue<Task<TResult>>();
        var next = 0;
        try
        {
            for (var done = 0; done < items.Count; done++)
            {
                while (next < items.Count && inFlight.Count < maxInFlight)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    inFlight.Enqueue(start(items[next++]));
                }

                var result = await inFlight.Dequeue();
                await onCompleted(done, result);
            }
        }
        catch
        {
            try
            {
                await Task.WhenAll(inFlight);
            }
            catch
            {
                // The first failure is the one rethrown; the rest are drained only.
            }

            throw;
        }
    }
}
