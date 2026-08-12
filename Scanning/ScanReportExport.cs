using System.Text;

namespace HashGuardScanner;

/// <summary>CSV/HTML export of scan results for support and auditing.</summary>
internal static class ScanReportExport
{
    public static string ToCsv(IEnumerable<ScanResult> results)
    {
        var sb = new StringBuilder();
        sb.AppendLine("status,risk_score,risk_level,trust,malicious,suspicious,process_names,pids,sha256,path,notes,new_since_last_scan,provider_results");
        foreach (var result in results)
        {
            sb.Append(Escape(result.Status)).Append(',')
                .Append(result.RiskScore).Append(',')
                .Append(Escape(result.RiskLevel)).Append(',')
                .Append(Escape(result.TrustSummary)).Append(',')
                .Append(result.Malicious).Append(',')
                .Append(result.Suspicious).Append(',')
                .Append(Escape(result.ProcessNames)).Append(',')
                .Append(Escape(result.Pids)).Append(',')
                .Append(Escape(result.Sha256)).Append(',')
                .Append(Escape(result.Path)).Append(',')
                .Append(Escape(result.Notes)).Append(',')
                .Append(result.IsNewSinceLastScan ? "yes" : "no").Append(',')
                .Append(Escape(result.ProviderSummary))
                .AppendLine();
        }

        return sb.ToString();
    }

    public static string ToHtml(IEnumerable<ScanResult> results, string version, DateTimeOffset generatedAt)
    {
        var list = results.ToList();
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html><html><head><meta charset=\"utf-8\"/>");
        sb.AppendLine("<title>HashGuard Scan Report</title>");
        sb.AppendLine("<style>body{font-family:Segoe UI,sans-serif;margin:24px;color:#203040}table{border-collapse:collapse;width:100%}th,td{border:1px solid #d0d6dc;padding:6px 8px;font-size:13px;vertical-align:top}th{background:#f2f5f7;text-align:left}.hi{background:#ffebee}.new{background:#e8f5e9}</style>");
        sb.AppendLine("</head><body>");
        sb.AppendLine($"<h1>HashGuard Scan Report</h1>");
        sb.AppendLine($"<p>Version {Html(version)} · Generated {Html(generatedAt.ToLocalTime().ToString("g"))} · {list.Count} item(s)</p>");
        sb.AppendLine("<table><thead><tr><th>Status</th><th>Risk</th><th>Process</th><th>Path</th><th>SHA-256</th><th>Notes</th></tr></thead><tbody>");
        foreach (var result in list)
        {
            var css = result.IsAlert ? "hi" : result.IsNewSinceLastScan ? "new" : "";
            sb.Append("<tr class=\"").Append(css).Append("\">")
                .Append("<td>").Append(Html(result.Status)).Append(result.IsNewSinceLastScan ? " · new" : "").Append("</td>")
                .Append("<td>").Append(Html($"{result.RiskLevel} {result.RiskScore}")).Append("</td>")
                .Append("<td>").Append(Html(result.ProcessNames)).Append("</td>")
                .Append("<td>").Append(Html(result.Path)).Append("</td>")
                .Append("<td><code>").Append(Html(result.Sha256)).Append("</code></td>")
                .Append("<td>").Append(Html(result.Notes)).Append("</td>")
                .AppendLine("</tr>");
        }

        sb.AppendLine("</tbody></table></body></html>");
        return sb.ToString();
    }

    private static string Escape(string? value)
    {
        value ??= "";
        if (value.Contains('"') || value.Contains(',') || value.Contains('\n') || value.Contains('\r'))
        {
            return $"\"{value.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
        }

        return value;
    }

    private static string Html(string? value) =>
        (value ?? "")
            .Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal)
            .Replace("\"", "&quot;", StringComparison.Ordinal);
}
