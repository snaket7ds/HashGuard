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
        return filter switch
        {
            ActivityFilter.ActionNeeded => malicious + suspicious > 0
                || string.Equals(status, "error", StringComparison.OrdinalIgnoreCase)
                || riskText.StartsWith("High", StringComparison.OrdinalIgnoreCase),
            ActivityFilter.Unknown => string.Equals(status, "unknown", StringComparison.OrdinalIgnoreCase)
                || string.Equals(status, "uploaded", StringComparison.OrdinalIgnoreCase)
                || string.Equals(status, "limited access", StringComparison.OrdinalIgnoreCase),
            ActivityFilter.Clean => string.Equals(status, "clean", StringComparison.OrdinalIgnoreCase)
                || string.Equals(status, "clean/seen", StringComparison.OrdinalIgnoreCase)
                || string.Equals(status, "ignored", StringComparison.OrdinalIgnoreCase),
            ActivityFilter.Errors => string.Equals(status, "error", StringComparison.OrdinalIgnoreCase),
            _ => true,
        };
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
