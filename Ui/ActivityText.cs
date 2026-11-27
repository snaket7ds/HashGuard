using System.Globalization;

namespace HashGuardScanner;

internal enum ActivityKind
{
    Threat,
    Suspicious,
    Unknown,
    Error,
    Handled,
    Clean,
    Firewall,
    Quarantine,
}

internal sealed record ActivityDescription(ActivityKind Kind, string Title, string Pill);

/// <summary>
/// Plain-language wording for Activity rows ("invoice_viewer.exe is flagged as malicious",
/// "Today", …). Pure, so it is unit-tested.
/// </summary>
internal static class ActivityText
{
    public static ActivityDescription Describe(string status, int malicious, int suspicious, bool handled, string name)
    {
        if (handled || string.Equals(status, "ignored", StringComparison.OrdinalIgnoreCase))
        {
            return new(ActivityKind.Handled, $"{name} was handled", status.Equals("ignored", StringComparison.OrdinalIgnoreCase) ? "Ignored" : "Handled");
        }

        if (malicious > 0)
        {
            return new(ActivityKind.Threat, $"{name} is flagged as malicious", malicious == 1 ? "Threat · 1 engine" : $"Threat · {malicious} engines");
        }

        if (suspicious > 0)
        {
            return new(ActivityKind.Suspicious, $"{name} looks suspicious", suspicious == 1 ? "Suspicious · 1" : $"Suspicious · {suspicious}");
        }

        if (string.Equals(status, "error", StringComparison.OrdinalIgnoreCase))
        {
            return new(ActivityKind.Error, $"{name} couldn't be checked", "Error");
        }

        if (string.Equals(status, "unknown", StringComparison.OrdinalIgnoreCase) || string.Equals(status, "uploaded", StringComparison.OrdinalIgnoreCase))
        {
            return string.Equals(status, "uploaded", StringComparison.OrdinalIgnoreCase)
                ? new(ActivityKind.Unknown, $"{name} was sent to VirusTotal", "Waiting")
                : new(ActivityKind.Unknown, $"{name} is unknown to every source", "Unknown");
        }

        return new(ActivityKind.Clean, $"{name} is clean", "Clean");
    }

    /// <summary>"Today", "Yesterday", or e.g. "Monday, 23 November".</summary>
    public static string DayHeader(DateTime day, DateTime today)
    {
        if (day.Date == today.Date)
        {
            return "Today";
        }

        if (day.Date == today.Date.AddDays(-1))
        {
            return "Yesterday";
        }

        return day.ToString(day.Year == today.Year ? "dddd, d MMMM" : "d MMMM yyyy", CultureInfo.CurrentCulture);
    }

    /// <summary>Parses the Activity log's timestamp column; unknown formats give null.</summary>
    public static DateTime? ParseTimestamp(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var parsed)
            || DateTimeOffset.TryParse(value, CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal, out parsed)
            ? parsed.LocalDateTime
            : null;
    }

    /// <summary>
    /// The log's trust column in plain words: "Signed by Microsoft Windows" or "Not signed".
    /// Certificate-chain codes (NotTimeValid, RevocationStatusUnknown, …) and service names are
    /// left for the details window.
    /// </summary>
    public static string FriendlyTrust(string? trust)
    {
        if (string.IsNullOrWhiteSpace(trust))
        {
            return "";
        }

        string? signer = null;
        var unsigned = false;
        foreach (var part in trust.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (signer is null && part.StartsWith("Signed by ", StringComparison.OrdinalIgnoreCase))
            {
                signer = part["Signed by ".Length..].Trim();
            }
            else if (signer is null && part.StartsWith("trusted publisher:", StringComparison.OrdinalIgnoreCase))
            {
                signer = part["trusted publisher:".Length..].Trim();
            }
            else if (part.StartsWith("Unsigned", StringComparison.OrdinalIgnoreCase))
            {
                unsigned = true;
            }
        }

        return !string.IsNullOrWhiteSpace(signer) ? $"Signed by {signer}" : unsigned ? "Not signed" : "";
    }

    /// <summary>A path as people write it: without the NT "\??\" prefix some drivers report.</summary>
    public static string FriendlyPath(string? path)
    {
        var value = path ?? "";
        return value.StartsWith(@"\??\", StringComparison.Ordinal) ? value[4..] : value;
    }

    /// <summary>"174 clean · 1 unknown · 1 flagged" for a batch of checks (zero counts left out).</summary>
    public static string BatchSummary(int clean, int unknown, int flagged, int errors)
    {
        var parts = new List<string>();
        if (clean > 0) parts.Add($"{clean.ToString("N0", CultureInfo.CurrentCulture)} clean");
        if (unknown > 0) parts.Add($"{unknown.ToString("N0", CultureInfo.CurrentCulture)} unknown");
        if (flagged > 0) parts.Add($"{flagged.ToString("N0", CultureInfo.CurrentCulture)} flagged");
        if (errors > 0) parts.Add(errors == 1 ? "1 couldn't be checked" : $"{errors.ToString("N0", CultureInfo.CurrentCulture)} couldn't be checked");
        return string.Join(" · ", parts);
    }

    /// <summary>The name shown for a row: the process name, else the file name of the path.</summary>
    public static string DisplayName(string processNames, string path)
    {
        var first = (processNames ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(first) && !first.StartsWith("Scheduled task:", StringComparison.OrdinalIgnoreCase) && !first.StartsWith("Service:", StringComparison.OrdinalIgnoreCase))
        {
            return first;
        }

        var cut = (path ?? "").LastIndexOfAny(['\\', '/']);
        var file = cut >= 0 ? path![(cut + 1)..] : path ?? "";
        return string.IsNullOrWhiteSpace(file) ? first ?? "A file" : file;
    }
}
