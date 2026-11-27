namespace HashGuard.Core;

/// <summary>Team Cymru's Malware Hash Registry, queried over DNS-over-HTTPS. Needs no API key.</summary>
public sealed class CymruProvider : IReputationProvider
{
    public const string ProviderName = "Cymru MHR";

    private readonly Func<string, CancellationToken, Task<CymruReputation?>> query;

    /// <param name="query">The registry lookup; defaults to <see cref="CymruClient.QueryAsync"/>.</param>
    public CymruProvider(Func<string, CancellationToken, Task<CymruReputation?>>? query = null)
    {
        this.query = query ?? CymruClient.QueryAsync;
    }

    public string Name => ProviderName;

    public async Task LookupAsync(ScanResult result, LookupRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(result.Sha256) || result.Sha256.Length != 64)
        {
            return;
        }

        try
        {
            var reputation = await query(result.Sha256, cancellationToken);
            if (reputation is null)
            {
                result.SetProviderResult(Name, ProviderState.Clean, "No malware match.");
                result.AppendNote("Team Cymru MHR: no malware match.");
                return;
            }

            result.AppendNote($"Team Cymru MHR: malware match, {reputation.DetectionPercent}% AV hit rate, last seen {reputation.LastSeenUtc:yyyy-MM-dd} UTC.");
            result.SetProviderResult(Name, ProviderState.Detected, $"{reputation.DetectionPercent}% AV hit rate, last seen {reputation.LastSeenUtc:yyyy-MM-dd} UTC.");
            if (!result.IsDetection)
            {
                result.Malicious = 1;
                result.Status = "detected";
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            result.AppendNote($"Team Cymru MHR lookup failed: {ex.Message}");
            result.SetProviderResult(Name, ProviderState.Error, ex.Message);
        }
    }
}
