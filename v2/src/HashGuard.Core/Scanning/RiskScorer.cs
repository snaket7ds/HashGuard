namespace HashGuard.Core;

/// <summary>
/// HashGuard's local risk score (0–100) and trust summary for a scanned file: detections, unknown
/// hashes, risky locations, auto-start, signing and age push it up; trusted publishers and install
/// locations pull it down.
/// </summary>
public static class RiskScorer
{
    public static void Apply(ScanResult result, IEnumerable<string> trustedPublishers)
    {
        var score = 0;
        var reasons = new List<string>();
        var trust = new List<string>();

        if (result.Malicious > 0)
        {
            score += 80;
            reasons.Add($"{result.Malicious} malicious detection(s)");
        }

        if (result.Suspicious > 0)
        {
            score += Math.Min(50, result.Suspicious * 15);
            reasons.Add($"{result.Suspicious} suspicious detection(s)");
        }

        if (string.Equals(result.Status, "unknown", StringComparison.OrdinalIgnoreCase)
            || string.Equals(result.Status, "uploaded", StringComparison.OrdinalIgnoreCase))
        {
            score += 20;
            reasons.Add("hash not known clean");
        }

        if (string.Equals(result.Status, "error", StringComparison.OrdinalIgnoreCase))
        {
            score += 25;
            reasons.Add("scan error needs review");
        }

        if (IsRiskyUserWritablePath(result.Path))
        {
            score += 25;
            reasons.Add("user-writable/risky path");
        }

        if (result.PersistenceSources.Count > 0)
        {
            score += 25;
            reasons.Add("starts automatically");
            trust.Add(string.Join("; ", result.PersistenceSources));
        }

        var unsigned = result.SignatureSummary.StartsWith("Unsigned", StringComparison.OrdinalIgnoreCase);
        var trustedPublisher = HashGuardLogic.SignatureChainValid(result.SignatureSummary)
            && !string.IsNullOrWhiteSpace(result.SignaturePublisher)
            && trustedPublishers.Any(trusted => HashGuardLogic.PublisherEquals(result.SignaturePublisher, trusted));
        if (unsigned)
        {
            score += 15;
            reasons.Add("unsigned");
        }
        else if (trustedPublisher)
        {
            score = Math.Max(0, score - 20);
            trust.Add($"trusted publisher: {result.SignaturePublisher}");
        }
        else if (!string.IsNullOrWhiteSpace(result.SignatureSummary))
        {
            trust.Add(result.SignatureSummary);
        }

        if (result.FileAgeDays is >= 0 and < 7)
        {
            score += 10;
            reasons.Add("recently modified");
        }

        if (IsWindowsOrProgramFilesPath(result.Path) && !unsigned)
        {
            score = Math.Max(0, score - 15);
            trust.Add("trusted install location");
        }

        result.RiskScore = Math.Clamp(score, 0, 100);
        result.RiskLevel = result.RiskScore >= 70 ? "High" : result.RiskScore >= 40 ? "Medium" : "Low";
        result.TrustSummary = trust.Count == 0 ? result.SignatureSummary : string.Join("; ", trust.Distinct(StringComparer.OrdinalIgnoreCase));

        if (reasons.Count > 0)
        {
            result.AppendNote($"Risk: {string.Join(", ", reasons.Distinct(StringComparer.OrdinalIgnoreCase))}.");
        }
    }

    public static bool IsRiskyUserWritablePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var lower = path.ToLowerInvariant();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).ToLowerInvariant();
        return lower.Contains(@"\appdata\", StringComparison.Ordinal)
            || lower.Contains(@"\temp\", StringComparison.Ordinal)
            || lower.Contains(@"\downloads\", StringComparison.Ordinal)
            || (!string.IsNullOrWhiteSpace(userProfile) && lower.StartsWith(userProfile, StringComparison.OrdinalIgnoreCase) && !IsWindowsOrProgramFilesPath(path));
    }

    public static bool IsWindowsOrProgramFilesPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        return new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            }
            .Where(root => !string.IsNullOrWhiteSpace(root))
            .Any(root => path.StartsWith(root, StringComparison.OrdinalIgnoreCase));
    }
}
