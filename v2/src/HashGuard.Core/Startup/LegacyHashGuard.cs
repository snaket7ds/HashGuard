using System.Diagnostics;

namespace HashGuard.Core;

/// <summary>A HashGuard 1.x process running next to v2.</summary>
public sealed record LegacyProcess(int Pid, string Path, string Version);

/// <summary>
/// Finds and closes HashGuard 1.x. v1 and v2 share the exe name but not the single-instance
/// check, and both monitoring at once would mean doubled alerts and two copies managing the same
/// firewall rules. v1 is told apart by its file version (1.x).
/// </summary>
public static class LegacyHashGuard
{
    /// <summary>v1 copies running in this Windows session (other people's sessions are left alone).</summary>
    public static IReadOnlyList<LegacyProcess> FindRunning() =>
        FindRunning(path => FileVersionInfo.GetVersionInfo(path));

    internal static IReadOnlyList<LegacyProcess> FindRunning(Func<string, FileVersionInfo?> versionOf)
    {
        var found = new List<LegacyProcess>();
        var mySession = Process.GetCurrentProcess().SessionId;
        foreach (var process in Process.GetProcessesByName("HashGuard"))
        {
            using (process)
            {
                try
                {
                    if (process.Id == Environment.ProcessId || process.SessionId != mySession)
                    {
                        continue;
                    }

                    var path = ProcessCollector.TryGetImagePath(process.Id, out _);
                    if (path is null)
                    {
                        continue;
                    }

                    if (versionOf(path) is { } version && IsLegacy(version.FileMajorPart, version.ProductVersion))
                    {
                        found.Add(new LegacyProcess(process.Id, path, version.ProductVersion?.Split('+')[0] ?? $"{version.FileMajorPart}.{version.FileMinorPart}.{version.FileBuildPart}"));
                    }
                }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or FileNotFoundException)
                {
                    // Exited meanwhile, or unreadable: nothing to report.
                }
            }
        }

        return found;
    }

    /// <summary>True for a 1.x build. A file with no version information is not assumed to be v1.</summary>
    internal static bool IsLegacy(int fileMajor, string? productVersion) =>
        fileMajor == 1 || (fileMajor == 0 && productVersion?.StartsWith("1.", StringComparison.Ordinal) == true);

    /// <summary>
    /// Ends the given v1 processes, checking each id still belongs to the same file. v1 hides to
    /// the tray when asked to close, so the process is ended. Returns the ones that could not be
    /// ended (typically a v1 running as administrator when v2 is not).
    /// </summary>
    public static IReadOnlyList<LegacyProcess> Close(IEnumerable<LegacyProcess> processes)
    {
        var failed = new List<LegacyProcess>();
        foreach (var legacy in processes)
        {
            try
            {
                using var process = Process.GetProcessById(legacy.Pid);
                var current = ProcessCollector.TryGetImagePath(legacy.Pid, out _);
                if (!string.Equals(current, legacy.Path, StringComparison.OrdinalIgnoreCase))
                {
                    continue; // Exited, and the id now belongs to something else.
                }

                process.Kill();
                if (!process.WaitForExit(5000))
                {
                    failed.Add(legacy);
                }
            }
            catch (ArgumentException)
            {
                // Already gone.
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or UnauthorizedAccessException)
            {
                failed.Add(legacy);
            }
        }

        return failed;
    }
}
