using System.Text;

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

    public static bool CanReuseProviderCache(string status, bool virusTotalDeferred, DateTimeOffset checkedAtUtc, DateTimeOffset now)
    {
        if (checkedAtUtc == default)
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

    public static bool NeedsAction(string? status, string? riskText, int malicious, int suspicious)
    {
        if (IsIgnoredStatus(status))
        {
            return false;
        }

        return malicious + suspicious > 0
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
