using System.Globalization;
using System.Text;

namespace HashGuard.Core;

/// <summary>One file check from the scan history.</summary>
public sealed record ActivityLogRow(
    DateTime? When,
    string Status,
    string RiskLevel,
    int RiskScore,
    string Trust,
    string ProviderResults,
    int Malicious,
    int Suspicious,
    string ProcessNames,
    string Pids,
    string Sha256,
    string Path,
    string Link,
    string Notes);

/// <summary>
/// Reads the scan history (v1's and v2's <c>scan-log-*.csv</c> files), newest first. To keep the
/// Activity page quick it reads at most the 14 newest files, the last 2 MB of each and 2,500 rows,
/// and it keeps the result until a log file changes.
/// </summary>
public sealed class ActivityLogReader(IEnumerable<string>? logDirectories = null)
{
    public const int MaxFiles = 14;
    public const int MaxRows = 2500;
    internal const long MaxBytesPerFile = 2L * 1024 * 1024;

    private readonly Lock gate = new();
    private IReadOnlyList<ActivityLogRow> cache = [];
    private string cacheSignature = "";

    public IReadOnlyList<ActivityLogRow> Read()
    {
        var files = NewestFiles();
        var signature = string.Join(";", files.Select(file => $"{file.FullName}|{file.Length}|{file.LastWriteTimeUtc.Ticks}"));
        lock (gate)
        {
            if (signature == cacheSignature)
            {
                return cache;
            }
        }

        var rows = new List<ActivityLogRow>();
        foreach (var file in files)
        {
            rows.AddRange(ReadFile(file.FullName, MaxRows - rows.Count));
            if (rows.Count >= MaxRows)
            {
                break;
            }
        }

        // Files are taken newest first, but two folders can interleave; order by time to be sure.
        IReadOnlyList<ActivityLogRow> sorted = [.. rows.OrderByDescending(row => row.When ?? DateTime.MinValue)];
        lock (gate)
        {
            cache = sorted;
            cacheSignature = signature;
        }

        return sorted;
    }

    private List<FileInfo> NewestFiles()
    {
        var directories = (logDirectories ?? AppPaths.GetLogDirectories()).Distinct(StringComparer.OrdinalIgnoreCase);
        var files = new List<FileInfo>();
        foreach (var directory in directories)
        {
            try
            {
                if (Directory.Exists(directory))
                {
                    files.AddRange(new DirectoryInfo(directory).EnumerateFiles("scan-log-*.csv"));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // An unreadable folder just contributes nothing.
            }
        }

        return [.. files.OrderByDescending(file => file.LastWriteTimeUtc).Take(MaxFiles)];
    }

    /// <summary>The rows of one log file, last row first.</summary>
    internal static List<ActivityLogRow> ReadFile(string path, int maxRows)
    {
        var rows = new List<ActivityLogRow>();
        if (maxRows <= 0)
        {
            return rows;
        }

        List<string> lines;
        try
        {
            lines = ReadLines(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return rows; // Locked or vanished: skip it rather than fail the page.
        }

        if (lines.Count < 2)
        {
            return rows;
        }

        var columns = HashGuardLogic.ParseCsvLine(lines[0])
            .Select((name, index) => (Name: name.Trim(), Index: index))
            .GroupBy(column => column.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First().Index, StringComparer.OrdinalIgnoreCase);

        for (var index = lines.Count - 1; index >= 1 && rows.Count < maxRows; index--)
        {
            if (string.IsNullOrWhiteSpace(lines[index]))
            {
                continue;
            }

            var cells = HashGuardLogic.ParseCsvLine(lines[index]);
            string Value(string name) => columns.TryGetValue(name, out var i) && i < cells.Count ? cells[i] : "";
            int Number(string name) => int.TryParse(Value(name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : 0;

            var timestamp = Value("timestamp_computer_time");
            if (string.IsNullOrWhiteSpace(timestamp))
            {
                timestamp = Value("timestamp");
            }

            rows.Add(new ActivityLogRow(
                ActivityText.ParseTimestamp(timestamp),
                Value("status"),
                Value("risk_level"),
                Number("risk_score"),
                Value("trust"),
                Value("provider_results"),
                Number("malicious"),
                Number("suspicious"),
                Value("process_names"),
                Value("pids"),
                Value("sha256"),
                Value("path"),
                Value("link"),
                Value("notes")));
        }

        return rows;
    }

    /// <summary>
    /// The header line plus every line of the file, or for a large file the header plus the
    /// lines in its last <see cref="MaxBytesPerFile"/> bytes. Opened shared so a scan can keep
    /// writing while the page reads.
    /// </summary>
    internal static List<string> ReadLines(string path, long maxBytes = MaxBytesPerFile)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (stream.Length <= maxBytes)
        {
            using var whole = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            return SplitLines(whole.ReadToEnd());
        }

        string header;
        using (var headReader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 4096, leaveOpen: true))
        {
            header = headReader.ReadLine() ?? "";
        }

        // Read the tail as bytes and decode it, dropping the partial first line.
        stream.Seek(-maxBytes, SeekOrigin.End);
        var buffer = new byte[maxBytes];
        stream.ReadExactly(buffer);
        var tail = SplitLines(Encoding.UTF8.GetString(buffer));
        tail[0] = header;
        return tail;
    }

    private static List<string> SplitLines(string text) =>
        [.. text.Split('\n').Select(line => line.TrimEnd('\r'))];
}
