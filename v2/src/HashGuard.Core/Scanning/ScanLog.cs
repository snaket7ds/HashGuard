using System.Globalization;
using System.Text;

namespace HashGuard.Core;

/// <summary>
/// The scan history: one CSV file per day in <c>logs\scan-log-yyyyMMdd.csv</c>, same columns as
/// v1, so the Activity page and the hash cache's log import read old and new rows alike.
/// </summary>
public static class ScanLog
{
    public const string Header = "timestamp_computer_time,status,risk_score,risk_level,trust,provider_results,malicious,suspicious,harmless,undetected,process_names,pids,sha256,path,link,notes";

    private static readonly Lock WriteGate = new();

    /// <summary>Raised after rows are written, so views showing the history can refresh.</summary>
    public static event Action? Changed;

    public static void Append(IEnumerable<ScanResult> results, string? logDirectory = null)
    {
        var rows = results.Select(FormatRow).ToList();
        if (rows.Count == 0)
        {
            return;
        }

        var directory = logDirectory ?? AppPaths.GetLogDirectory();
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"scan-log-{DateTime.Now:yyyyMMdd}.csv");
        lock (WriteGate)
        {
            var writeHeader = !File.Exists(path);
            using var writer = new StreamWriter(path, append: true, Encoding.UTF8);
            if (writeHeader)
            {
                writer.WriteLine(Header);
            }

            foreach (var row in rows)
            {
                writer.WriteLine(row);
            }
        }

        Changed?.Invoke();
    }

    internal static string FormatRow(ScanResult result) => string.Join(",", new[]
    {
        DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
        result.Status,
        result.RiskScore.ToString(CultureInfo.InvariantCulture),
        result.RiskLevel,
        result.TrustSummary,
        result.ProviderSummary,
        result.Malicious.ToString(CultureInfo.InvariantCulture),
        result.Suspicious.ToString(CultureInfo.InvariantCulture),
        result.Harmless.ToString(CultureInfo.InvariantCulture),
        result.Undetected.ToString(CultureInfo.InvariantCulture),
        result.ProcessNames,
        result.Pids,
        result.Sha256,
        result.Path,
        result.Link,
        result.Notes,
    }.Select(Quote));

    private static string Quote(string value) => $"\"{value.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
}
