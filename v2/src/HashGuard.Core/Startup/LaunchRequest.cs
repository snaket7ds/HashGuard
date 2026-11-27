namespace HashGuard.Core;

/// <summary>What a launch of HashGuard.exe asks for.</summary>
public enum LaunchKind
{
    /// <summary>Plain start: show the window.</summary>
    Show,

    /// <summary>Started with Windows (<c>--minimized</c>): stay in the tray.</summary>
    Minimized,

    /// <summary>Explorer's right-click "Scan with HashGuard" (<c>--scan-file path</c>).</summary>
    ScanFile,

    /// <summary>The daily scan task (<c>--scheduled-scan</c>): scan quietly.</summary>
    ScheduledScan,
}

/// <summary>
/// A launch request, parsed from the command line and passed to an already-running HashGuard
/// as one line of text: <c>show</c>, <c>minimized</c>, <c>scheduled-scan</c> or
/// <c>scan-file\tC:\path</c>.
/// </summary>
public sealed record LaunchRequest(LaunchKind Kind, string? Path = null)
{
    public static LaunchRequest Parse(IReadOnlyList<string> args)
    {
        for (var index = 0; index < args.Count; index++)
        {
            if (string.Equals(args[index], "--scan-file", StringComparison.OrdinalIgnoreCase) && index + 1 < args.Count)
            {
                return new(LaunchKind.ScanFile, args[index + 1]);
            }
        }

        if (args.Any(arg => string.Equals(arg, ScheduledScan.Argument, StringComparison.OrdinalIgnoreCase)))
        {
            return new(LaunchKind.ScheduledScan);
        }

        return args.Any(arg => string.Equals(arg, ElevatedStartupTask.StartupArguments, StringComparison.OrdinalIgnoreCase))
            ? new(LaunchKind.Minimized)
            : new(LaunchKind.Show);
    }

    public string ToMessage() => Kind switch
    {
        LaunchKind.ScanFile => $"scan-file\t{Path}",
        LaunchKind.ScheduledScan => "scheduled-scan",
        LaunchKind.Minimized => "minimized",
        _ => "show",
    };

    /// <summary>Reads a message; anything unrecognised or malformed gives null.</summary>
    public static LaunchRequest? FromMessage(string? message)
    {
        if (string.IsNullOrWhiteSpace(message) || message.Length > 4096)
        {
            return null;
        }

        var parts = message.Split('\t', 2);
        return parts[0] switch
        {
            "show" => new(LaunchKind.Show),
            "minimized" => new(LaunchKind.Minimized),
            "scheduled-scan" => new(LaunchKind.ScheduledScan),
            "scan-file" when parts.Length == 2 && parts[1].Length > 0 => new(LaunchKind.ScanFile, parts[1]),
            _ => null,
        };
    }
}
