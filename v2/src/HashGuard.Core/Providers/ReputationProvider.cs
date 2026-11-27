using System.Net;

namespace HashGuard.Core;

/// <summary>What one lookup may do. Only VirusTotal uses the upload flags.</summary>
public sealed record LookupRequest(string Path, bool AllowUploads = true, bool UploadUnknown = false);

/// <summary>
/// A reputation source (VirusTotal, MetaDefender, Team Cymru). A lookup records its verdict on the
/// <see cref="ScanResult"/>: one <see cref="ProviderResult"/> row plus a plain-language note.
/// Lookups never throw for service errors; they record an Error row instead. Cancellation does throw.
/// </summary>
public interface IReputationProvider
{
    /// <summary>The name shown in provider rows, such as "VirusTotal".</summary>
    string Name { get; }

    Task LookupAsync(ScanResult result, LookupRequest request, CancellationToken cancellationToken);
}

public static class ScanResultNotes
{
    /// <summary>Adds a note, separated from earlier ones by "; ".</summary>
    public static void AppendNote(this ScanResult result, string note) =>
        result.Notes = string.IsNullOrWhiteSpace(result.Notes) ? note : $"{result.Notes}; {note}";

    /// <summary>Records a provider's verdict, replacing any earlier row from the same provider.</summary>
    public static void SetProviderResult(this ScanResult result, string provider, ProviderState state, string detail)
    {
        result.ProviderResults.RemoveAll(item => string.Equals(item.Provider, provider, StringComparison.OrdinalIgnoreCase));
        result.ProviderResults.Add(new ProviderResult(provider, state, detail));
    }

    /// <summary>The message shown for a failed lookup; 401s get a hint to check the API key.</summary>
    public static string FormatError(Exception ex) =>
        ex is HttpRequestException { StatusCode: HttpStatusCode.Unauthorized }
            ? "A reputation service returned 401 Unauthorized. Verify the saved API key in Settings."
            : ex.Message;

    /// <summary>Shortens a service's error body for a note.</summary>
    public static string TrimServiceError(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return "";
        }

        var trimmed = body.ReplaceLineEndings(" ").Trim();
        return trimmed.Length <= 240 ? trimmed : trimmed[..240] + "…";
    }
}
