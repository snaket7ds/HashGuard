using System.Text;
using System.Text.Json;

namespace HashGuardScanner;

internal enum ProviderState
{
    NotChecked,
    Clean,
    Unknown,
    Deferred,
    Error,
    Detected,
}

internal enum ActivityFilter
{
    All,
    ActionNeeded,
    Unknown,
    Clean,
    Errors,
}

internal static class HashGuardLogic
{
    public static string? TryExtractExecutablePath(string? command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return null;
        }

        var expanded = Environment.ExpandEnvironmentVariables(command.Trim());
        if (expanded.StartsWith("\"", StringComparison.Ordinal))
        {
            var endQuote = expanded.IndexOf('"', 1);
            if (endQuote > 1)
            {
                return NormalizeExecutablePath(expanded[1..endQuote]);
            }
        }

        var exeIndex = expanded.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIndex >= 0)
        {
            return NormalizeExecutablePath(expanded[..(exeIndex + 4)].Trim());
        }

        return NormalizeExecutablePath(expanded.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault());
    }

    public static List<string> ParseCsvLine(string line)
    {
        var values = new List<string>();
        var current = new StringBuilder();
        var quoted = false;

        for (var index = 0; index < line.Length; index++)
        {
            var character = line[index];
            if (character == '"')
            {
                if (quoted && index + 1 < line.Length && line[index + 1] == '"')
                {
                    current.Append('"');
                    index++;
                }
                else
                {
                    quoted = !quoted;
                }
            }
            else if (character == ',' && !quoted)
            {
                values.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(character);
            }
        }

        values.Add(current.ToString());
        return values;
    }

    public static string ExtractChangelogSection(string changelog, string tag)
    {
        var lines = changelog.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        var start = Array.FindIndex(lines, line => line.StartsWith($"## {tag}", StringComparison.Ordinal));
        if (start < 0)
        {
            return $"Release notes for {tag} were not found in CHANGELOG.md.";
        }

        var end = lines.Length;
        for (var index = start + 1; index < lines.Length; index++)
        {
            if (lines[index].StartsWith("## ", StringComparison.Ordinal))
            {
                end = index;
                break;
            }
        }

        return string.Join(Environment.NewLine, lines[start..end]).TrimEnd() + Environment.NewLine;
    }

    public static bool CanReuseProviderCache(
        string status,
        bool virusTotalDeferred,
        DateTimeOffset checkedAtUtc,
        DateTimeOffset now,
        bool uploadUnknownEnabled = false)
    {
        if (checkedAtUtc == default)
        {
            return false;
        }

        // Cached "unknown"/"uploaded" must not block a live VirusTotal upload.
        if (uploadUnknownEnabled && IsPendingVirusTotalUploadStatus(status))
        {
            return false;
        }

        var age = now - checkedAtUtc;
        return string.Equals(status, "unknown", StringComparison.OrdinalIgnoreCase)
                && age <= TimeSpan.FromHours(12)
            || string.Equals(status, "uploaded", StringComparison.OrdinalIgnoreCase)
                && age <= TimeSpan.FromHours(12)
            || string.Equals(status, "error", StringComparison.OrdinalIgnoreCase)
                && age <= TimeSpan.FromHours(1)
            || virusTotalDeferred
                && age <= TimeSpan.FromMinutes(30);
    }

    public static bool IsPendingVirusTotalUploadStatus(string? status) =>
        string.Equals(status, "unknown", StringComparison.OrdinalIgnoreCase)
        || string.Equals(status, "uploaded", StringComparison.OrdinalIgnoreCase);

    public static bool IsVirusTotalNotFound(int statusCode, string? body)
    {
        if (statusCode == 404)
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(body))
        {
            return false;
        }

        return body.Contains("NotFoundError", StringComparison.OrdinalIgnoreCase)
            || body.Contains("\"NotFound\"", StringComparison.OrdinalIgnoreCase);
    }

    public static string? TryReadVirusTotalAnalysisId(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            return JsonPath.ReadString(doc.RootElement, "data", "id");
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static bool IsVirusTotalAlreadyExists(int statusCode, string? body) =>
        statusCode == 409
        || (!string.IsNullOrWhiteSpace(body) && body.Contains("AlreadyExistsError", StringComparison.OrdinalIgnoreCase));

    public static bool MatchesActivityFilter(ActivityFilter filter, string status, string riskText, int malicious, int suspicious)
    {
        if (IsIgnoredStatus(status))
        {
            return filter is ActivityFilter.All or ActivityFilter.Clean;
        }

        return filter switch
        {
            ActivityFilter.ActionNeeded => NeedsAction(status, riskText, malicious, suspicious),
            ActivityFilter.Unknown => IsUnknownStatus(status),
            ActivityFilter.Clean => IsCleanStatus(status),
            ActivityFilter.Errors => string.Equals(status, "error", StringComparison.OrdinalIgnoreCase),
            _ => true,
        };
    }

    public static bool IsIgnoredStatus(string? status) =>
        string.Equals(status, "ignored", StringComparison.OrdinalIgnoreCase);

    public static bool IsCleanStatus(string? status) =>
        string.Equals(status, "clean", StringComparison.OrdinalIgnoreCase)
        || string.Equals(status, "clean/seen", StringComparison.OrdinalIgnoreCase)
        || IsIgnoredStatus(status);

    public static bool IsUnknownStatus(string? status) =>
        string.Equals(status, "unknown", StringComparison.OrdinalIgnoreCase)
        || string.Equals(status, "uploaded", StringComparison.OrdinalIgnoreCase)
        || string.Equals(status, "limited access", StringComparison.OrdinalIgnoreCase);

    public static bool NeedsAction(
        string? status,
        string? riskText,
        int malicious,
        int suspicious,
        bool needsVirusTotalUpload = false)
    {
        if (IsIgnoredStatus(status))
        {
            return false;
        }

        return needsVirusTotalUpload
            || malicious + suspicious > 0
            || string.Equals(status, "error", StringComparison.OrdinalIgnoreCase)
            || (riskText?.StartsWith("High", StringComparison.OrdinalIgnoreCase) ?? false);
    }

    /// <summary>
    /// True when notes indicate the file was moved to HashGuard quarantine.
    /// </summary>
    public static bool NoteIndicatesQuarantined(string? notes) =>
        !string.IsNullOrWhiteSpace(notes)
        && (notes.Contains("Quarantined to ", StringComparison.OrdinalIgnoreCase)
            || notes.Contains("Quarantined", StringComparison.OrdinalIgnoreCase));

    public static string QuarantineDisplayName(QuarantineEntry entry)
    {
        var path = !string.IsNullOrWhiteSpace(entry.OriginalPath) ? entry.OriginalPath : entry.QuarantinePath;
        if (string.IsNullOrWhiteSpace(path))
        {
            return "(unknown file)";
        }

        var slash = path.LastIndexOfAny(['\\', '/']);
        return slash >= 0 && slash < path.Length - 1 ? path[(slash + 1)..] : path;
    }

    public static bool QuarantineEntryIsRestorable(QuarantineEntry entry, Func<string, bool>? fileExists = null)
    {
        fileExists ??= File.Exists;
        return !string.IsNullOrWhiteSpace(entry.QuarantinePath) && fileExists(entry.QuarantinePath);
    }

    public static int CountRestorableQuarantineEntries(IEnumerable<QuarantineEntry> entries, Func<string, bool>? fileExists = null)
        => entries.Count(entry => QuarantineEntryIsRestorable(entry, fileExists));

    public static bool QuarantineEntryMatchesFilter(QuarantineEntry entry, string? query)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            return true;
        }

        var needle = query.Trim();
        return ContainsIgnoreCase(QuarantineDisplayName(entry), needle)
            || ContainsIgnoreCase(entry.OriginalPath, needle)
            || ContainsIgnoreCase(entry.QuarantinePath, needle)
            || ContainsIgnoreCase(entry.Sha256, needle)
            || ContainsIgnoreCase(entry.Notes, needle);
    }

    private static bool ContainsIgnoreCase(string? value, string needle) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Contains(needle, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Whether a selected review-queue row can be ignored by hash and/or path.
    /// </summary>
    public static bool CanIgnoreTarget(string? sha256, string? path, out string kind, out string value)
    {
        if (!string.IsNullOrWhiteSpace(sha256))
        {
            kind = "hash";
            value = sha256.Trim();
            return true;
        }

        if (!string.IsNullOrWhiteSpace(path))
        {
            kind = "path";
            value = path.Trim();
            return true;
        }

        kind = "";
        value = "";
        return false;
    }

    public static string RiskBucket(int riskScore) => riskScore switch
    {
        >= 70 => "High",
        >= 40 => "Medium",
        _ => "Low",
    };

    public const string IgnoreNote = "File hash ignored by user.";
    public const string IgnorePathNote = "File path ignored by user.";

    public static bool HasIgnoreNote(string? notes) =>
        !string.IsNullOrWhiteSpace(notes)
        && (notes.Contains(IgnoreNote, StringComparison.OrdinalIgnoreCase)
            || notes.Contains(IgnorePathNote, StringComparison.OrdinalIgnoreCase)
            || notes.Contains("Detection ignored by user.", StringComparison.OrdinalIgnoreCase)
            || notes.Contains("ignored by user", StringComparison.OrdinalIgnoreCase));

    public static string RemoveIgnoreNote(string? notes)
    {
        if (string.IsNullOrWhiteSpace(notes))
        {
            return "";
        }

        var parts = notes.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Where(part =>
                !part.Contains("ignored by user", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(part, IgnoreNote, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(part, IgnorePathNote, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(part, "Detection ignored by user.", StringComparison.OrdinalIgnoreCase));
        return string.Join("; ", parts);
    }

    public static string BuildTrayAlertSignature(IEnumerable<(string Sha256, string Path)> actionNeededItems)
    {
        return string.Join("|", actionNeededItems
            .Select(item => !string.IsNullOrWhiteSpace(item.Sha256) ? item.Sha256.ToLowerInvariant() : item.Path.ToLowerInvariant())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase));
    }

    public static bool ShouldShowTrayAlert(bool suppressRepeat, string previousSignature, string currentSignature)
    {
        if (string.IsNullOrWhiteSpace(currentSignature))
        {
            return false;
        }

        if (!suppressRepeat)
        {
            return true;
        }

        return !string.Equals(previousSignature, currentSignature, StringComparison.Ordinal);
    }

    public static bool PublisherMatchesForIgnore(string? signaturePublisher, string? trustedOrSelectedPublisher)
    {
        if (string.IsNullOrWhiteSpace(signaturePublisher) || string.IsNullOrWhiteSpace(trustedOrSelectedPublisher))
        {
            return false;
        }

        return signaturePublisher.Contains(trustedOrSelectedPublisher, StringComparison.OrdinalIgnoreCase)
            || trustedOrSelectedPublisher.Contains(signaturePublisher, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Builds an anonymous telemetry payload shape without file paths, hashes, or process names.
    /// </summary>
    public static Dictionary<string, object> BuildScanCompleteTelemetry(
        int itemsScanned,
        int actionNeeded,
        int detections,
        int unknown,
        int errors)
    {
        return new Dictionary<string, object>
        {
            ["items_scanned"] = itemsScanned,
            ["action_needed"] = actionNeeded,
            ["detections"] = detections,
            ["unknown"] = unknown,
            ["errors"] = errors,
        };
    }

    public static bool TelemetryPayloadLooksSafe(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return false;
        }

        // Guard against accidental inclusion of sensitive fields in serialized payloads.
        var lower = json.ToLowerInvariant();
        return !lower.Contains("\"path\"")
            && !lower.Contains("sha256")
            && !lower.Contains("apikey")
            && !lower.Contains("process_name")
            && !lower.Contains("username")
            && !lower.Contains("machine");
    }

    private static string? NormalizeExecutablePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var trimmed = path.Trim();
        if (trimmed.Length >= 3 && char.IsLetter(trimmed[0]) && trimmed[1] == ':' && (trimmed[2] == '\\' || trimmed[2] == '/'))
        {
            return trimmed;
        }

        try
        {
            return Path.GetFullPath(trimmed);
        }
        catch
        {
            return trimmed;
        }
    }
}
