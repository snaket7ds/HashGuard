using System.Diagnostics;

namespace HashGuardScanner;

/// <summary>Registers or removes a daily HashGuard full-scan scheduled task (current user).</summary>
internal static class ScheduledScan
{
    public const string TaskName = "HashGuardDailyScan";

    public static void Apply(bool enabled, int hourLocal, string executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath))
        {
            return;
        }

        hourLocal = Math.Clamp(hourLocal, 0, 23);
        if (!enabled)
        {
            TryRunSchtasks($"/Delete /TN \"{TaskName}\" /F");
            return;
        }

        // /SC DAILY at HH:00, start HashGuard (not minimized so user sees results if interactive).
        var startTime = $"{hourLocal:00}:00";
        TryRunSchtasks(
            $"/Create /F /TN \"{TaskName}\" /SC DAILY /ST {startTime} /TR \"\\\"{executablePath}\\\"\"");
    }

    public static bool IsRegistered()
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", $"/Query /TN \"{TaskName}\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var process = Process.Start(psi);
            if (process is null)
            {
                return false;
            }

            process.WaitForExit(5000);
            return process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private static void TryRunSchtasks(string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", arguments)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var process = Process.Start(psi);
            process?.WaitForExit(8000);
        }
        catch
        {
            // Scheduled task setup is best-effort on locked-down machines.
        }
    }
}
