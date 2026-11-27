using System.Diagnostics;

namespace HashGuard.Core;

public static partial class ProcessCollector
{
    /// <summary>Ids of the running processes whose executable is <paramref name="path"/>.</summary>
    public static IReadOnlyList<int> FindRunning(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return [];
        }

        var wanted = System.IO.Path.GetFullPath(path);
        return CollectRunning().Files.TryGetValue(wanted, out var files)
            ? files.Select(file => file.Pid).ToList()
            : [];
    }

    /// <summary>
    /// Stops every process running <paramref name="path"/> (and its child processes), checking
    /// each id still belongs to that file right before stopping it, so a reused id is never hit.
    /// Returns how many were stopped; throws when one could not be stopped.
    /// </summary>
    public static int StopRunning(string path)
    {
        var wanted = System.IO.Path.GetFullPath(path);
        var stopped = 0;
        foreach (var pid in FindRunning(wanted))
        {
            using var process = TryGetProcess(pid);
            if (process is null)
            {
                continue; // Already gone.
            }

            var current = TryGetImagePath(pid, out _);
            if (!string.Equals(current is null ? null : System.IO.Path.GetFullPath(current), wanted, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            process.Kill(entireProcessTree: true);
            process.WaitForExit(5000);
            stopped++;
        }

        return stopped;
    }

    private static Process? TryGetProcess(int pid)
    {
        try
        {
            return Process.GetProcessById(pid);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}
