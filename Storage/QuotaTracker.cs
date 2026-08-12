using System.Text.Json;

namespace HashGuardScanner;

internal sealed class QuotaTracker
{
    private const int DailyLimit = 500;
    private const int MinuteLimit = 4;
    private QuotaState state = new();
    private bool loaded;

    /// <summary>Load free-API quota state once per process; keep updates in memory.</summary>
    public async Task EnsureLoadedAsync()
    {
        if (loaded)
        {
            return;
        }

        await LoadAsync();
    }

    public async Task LoadAsync()
    {
        try
        {
            var path = AppPaths.GetQuotaPath();
            if (File.Exists(path))
            {
                await using var stream = File.OpenRead(path);
                state = await JsonSerializer.DeserializeAsync<QuotaState>(stream) ?? new QuotaState();
            }
        }
        catch
        {
            // Ignore stale or malformed quota data; it is local rate-limit bookkeeping.
            state = new QuotaState();
        }

        ResetIfNewDay();
        TrimOldMinuteRequests(DateTimeOffset.UtcNow);
        loaded = true;
        await SaveAsync();
    }

    public async Task<QuotaReservation> TryReserveAsync()
    {
        ResetIfNewDay();
        var now = DateTimeOffset.UtcNow;
        TrimOldMinuteRequests(now);

        if (state.DailyCount >= DailyLimit)
        {
            return new QuotaReservation(false, "daily");
        }

        if (state.MinuteRequestsUtc.Count >= MinuteLimit)
        {
            return new QuotaReservation(false, "minute");
        }

        state.MinuteRequestsUtc.Add(now);
        state.DailyCount++;
        await SaveAsync();
        return new QuotaReservation(true, "");
    }

    private void ResetIfNewDay()
    {
        var today = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd");
        if (state.UtcDay == today)
        {
            return;
        }

        state.UtcDay = today;
        state.DailyCount = 0;
        state.MinuteRequestsUtc.Clear();
    }

    private void TrimOldMinuteRequests(DateTimeOffset now)
    {
        state.MinuteRequestsUtc = state.MinuteRequestsUtc
            .Where(requestTime => now - requestTime < TimeSpan.FromMinutes(1))
            .ToList();
    }

    private async Task SaveAsync()
    {
        var path = AppPaths.GetQuotaPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await using var stream = File.Create(path);
        await JsonSerializer.SerializeAsync(stream, state, new JsonSerializerOptions { WriteIndented = true });
    }
}
