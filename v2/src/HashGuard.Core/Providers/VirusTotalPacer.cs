namespace HashGuard.Core;

/// <summary>
/// Keeps VirusTotal inside its limits, in one place. Scans look up several files at once, but the
/// free tier allows 4 requests a minute and 500 a day. While the free-API limit or a per-request
/// delay is set, lookups take turns and start at least <see cref="Delay"/> apart. With neither set,
/// lookups are not held back.
/// </summary>
public sealed class VirusTotalPacer
{
    private readonly SemaphoreSlim lane = new(1, 1);
    private readonly Func<Task<QuotaReservation>> reserve;
    private readonly Func<TimeSpan, CancellationToken, Task> delay;
    private DateTimeOffset nextRequestUtc = DateTimeOffset.MinValue;

    /// <param name="reserve">Books one request against the free quota; defaults to a <see cref="QuotaTracker"/>.</param>
    /// <param name="delay">Waits; replaceable so tests don't sleep.</param>
    public VirusTotalPacer(
        bool freeApiLimit,
        TimeSpan delayPerRequest,
        Func<Task<QuotaReservation>>? reserve = null,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        FreeApiLimit = freeApiLimit;
        Delay = delayPerRequest < TimeSpan.Zero ? TimeSpan.Zero : delayPerRequest;
        if (reserve is null)
        {
            var tracker = new QuotaTracker();
            reserve = async () =>
            {
                await tracker.EnsureLoadedAsync();
                return await tracker.TryReserveAsync();
            };
        }

        this.reserve = reserve;
        this.delay = delay ?? Task.Delay;
    }

    public bool FreeApiLimit { get; }

    public TimeSpan Delay { get; }

    private bool Paced => FreeApiLimit || Delay > TimeSpan.Zero;

    /// <summary>Takes a turn in the lane. Dispose the result to give the turn back.</summary>
    public async Task<IDisposable> EnterAsync(CancellationToken cancellationToken)
    {
        if (!Paced)
        {
            return NoTurn.Instance;
        }

        await lane.WaitAsync(cancellationToken);
        return new Turn(this);
    }

    /// <summary>Waits out the spacing since the last request, then books the next slot. Call while holding a turn.</summary>
    public async Task WaitForSpacingAsync(CancellationToken cancellationToken)
    {
        if (!Paced)
        {
            return;
        }

        var wait = nextRequestUtc - DateTimeOffset.UtcNow;
        if (wait > TimeSpan.Zero)
        {
            await delay(wait, cancellationToken);
        }

        nextRequestUtc = DateTimeOffset.UtcNow + Delay;
    }

    /// <summary>
    /// Books one request against the free quota. With <paramref name="waitForMinuteSlot"/>, a full
    /// minute window is waited out once. When no slot is free, marks <paramref name="result"/> deferred.
    /// </summary>
    public async Task<bool> TryReserveAsync(ScanResult? result, bool waitForMinuteSlot, CancellationToken cancellationToken)
    {
        if (!FreeApiLimit)
        {
            return true;
        }

        var reservation = await reserve();
        if (!reservation.Available && waitForMinuteSlot && string.Equals(reservation.LimitName, "minute", StringComparison.OrdinalIgnoreCase))
        {
            await delay(TimeSpan.FromSeconds(16), cancellationToken);
            reservation = await reserve();
        }

        if (reservation.Available)
        {
            return true;
        }

        if (result is not null)
        {
            result.VirusTotalDeferred = true;
            result.AppendNote($"VirusTotal: queued for a future scan because the free API {reservation.LimitName} limit is reached.");
        }

        return false;
    }

    private sealed class Turn(VirusTotalPacer owner) : IDisposable
    {
        private int released;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref released, 1) == 0)
            {
                owner.lane.Release();
            }
        }
    }

    private sealed class NoTurn : IDisposable
    {
        public static readonly NoTurn Instance = new();

        public void Dispose()
        {
        }
    }
}
