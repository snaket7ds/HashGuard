using System.Diagnostics;
using System.Text;
using System.Xml.Linq;

namespace HashGuardScanner;

/// <summary>
/// Starts HashGuard elevated at sign-in without a UAC prompt.
///
/// A HKCU\...\Run entry always starts a program unelevated, so with "Run elevated" on
/// HashGuard relaunched itself through UAC at every sign-in. Task Scheduler can start a
/// program with the user's full (admin) token at logon without asking, as long as an
/// elevated process registered the task. This class builds and registers that task.
/// </summary>
internal static class ElevatedStartupTask
{
    public const string TaskName = @"\HashGuard\Start at sign-in";
    public const string StartupArguments = "--minimized";
    private const string TaskNamespace = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    /// <summary>
    /// Task XML for a logon trigger that runs <paramref name="executablePath"/> with the highest
    /// available privileges in the signed-in user's interactive session.
    /// </summary>
    /// <param name="userSid">The user's SID (S-1-5-21-…); used for both trigger and principal.</param>
    public static string BuildTaskXml(string executablePath, string userSid)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            throw new ArgumentException("Executable path is required.", nameof(executablePath));
        }

        if (string.IsNullOrWhiteSpace(userSid))
        {
            throw new ArgumentException("User SID is required.", nameof(userSid));
        }

        XNamespace ns = TaskNamespace;
        var workingDirectory = WindowsDirectoryOf(executablePath);
        var task = new XElement(ns + "Task",
            new XAttribute("version", "1.2"),
            new XElement(ns + "RegistrationInfo",
                new XElement(ns + "Author", "HashGuard"),
                new XElement(ns + "Description", "Starts HashGuard elevated when you sign in, without a UAC prompt. Managed by HashGuard Settings (Start with Windows + Run elevated).")),
            new XElement(ns + "Triggers",
                new XElement(ns + "LogonTrigger",
                    new XElement(ns + "Enabled", "true"),
                    new XElement(ns + "UserId", userSid),
                    // A short delay lets the shell and tray come up first.
                    new XElement(ns + "Delay", "PT10S"))),
            new XElement(ns + "Principals",
                new XElement(ns + "Principal",
                    new XAttribute("id", "Author"),
                    new XElement(ns + "UserId", userSid),
                    new XElement(ns + "LogonType", "InteractiveToken"),
                    new XElement(ns + "RunLevel", "HighestAvailable"))),
            new XElement(ns + "Settings",
                new XElement(ns + "MultipleInstancesPolicy", "IgnoreNew"),
                new XElement(ns + "DisallowStartIfOnBatteries", "false"),
                new XElement(ns + "StopIfGoingOnBatteries", "false"),
                new XElement(ns + "AllowHardTerminate", "false"),
                new XElement(ns + "StartWhenAvailable", "false"),
                new XElement(ns + "RunOnlyIfNetworkAvailable", "false"),
                new XElement(ns + "IdleSettings",
                    new XElement(ns + "StopOnIdleEnd", "false"),
                    new XElement(ns + "RestartOnIdle", "false")),
                new XElement(ns + "AllowStartOnDemand", "true"),
                new XElement(ns + "Enabled", "true"),
                new XElement(ns + "Hidden", "false"),
                new XElement(ns + "RunOnlyIfIdle", "false"),
                // The schtasks default is 72 hours, after which Windows would kill the tray app.
                new XElement(ns + "ExecutionTimeLimit", "PT0S"),
                // 7 (the default) is below-normal CPU and low I/O priority; 4 matches a normal launch.
                new XElement(ns + "Priority", "4")),
            new XElement(ns + "Actions",
                new XAttribute("Context", "Author"),
                new XElement(ns + "Exec",
                    new XElement(ns + "Command", executablePath),
                    new XElement(ns + "Arguments", StartupArguments),
                    new XElement(ns + "WorkingDirectory", workingDirectory))));

        return new XDocument(new XDeclaration("1.0", "UTF-16", null), task).Declaration + Environment.NewLine + task;
    }

    /// <summary>
    /// Folder of a Windows path. Split by hand so the result is the same whichever OS runs the
    /// tests (Path.GetDirectoryName ignores '\' on Linux). "C:\x.exe" gives "C:\".
    /// </summary>
    internal static string WindowsDirectoryOf(string path)
    {
        var cut = path.LastIndexOfAny(['\\', '/']);
        if (cut <= 0)
        {
            return "";
        }

        var directory = path[..cut];
        return directory.EndsWith(':') ? directory + "\\" : directory;
    }

    /// <summary>The Exec command of a task XML, or null if it has none.</summary>
    public static string? ReadCommand(string taskXml)
    {
        if (string.IsNullOrWhiteSpace(taskXml))
        {
            return null;
        }

        try
        {
            XNamespace ns = TaskNamespace;
            return XDocument.Parse(taskXml).Descendants(ns + "Exec").Elements(ns + "Command").FirstOrDefault()?.Value.Trim().Trim('"');
        }
        catch (System.Xml.XmlException)
        {
            return null;
        }
    }

    /// <summary>True when the task exists and starts <paramref name="executablePath"/>.</summary>
    public static bool IsInstalledFor(string executablePath)
    {
        var (exitCode, output, _) = RunSchtasks($"/Query /TN \"{TaskName}\" /XML", 8000);
        if (exitCode != 0)
        {
            return false;
        }

        var command = ReadCommand(output);
        return command is not null && string.Equals(
            Path.GetFullPath(command),
            Path.GetFullPath(executablePath),
            StringComparison.OrdinalIgnoreCase);
    }

    public static bool Exists() => RunSchtasks($"/Query /TN \"{TaskName}\"", 8000).ExitCode == 0;

    /// <summary>Creates or replaces the task. Must be called from an elevated process.</summary>
    public static void Install(string executablePath, string userSid)
    {
        var xmlPath = Path.Combine(Path.GetTempPath(), $"hashguard-startup-{Guid.NewGuid():N}.xml");
        try
        {
            // schtasks /XML expects UTF-16 with a BOM, matching the declaration.
            File.WriteAllText(xmlPath, BuildTaskXml(executablePath, userSid), Encoding.Unicode);
            var (exitCode, output, error) = RunSchtasks($"/Create /TN \"{TaskName}\" /XML \"{xmlPath}\" /F", 15000);
            if (exitCode != 0)
            {
                throw new InvalidOperationException(FirstNonEmpty(error, output, $"schtasks exited with code {exitCode}."));
            }
        }
        finally
        {
            try
            {
                File.Delete(xmlPath);
            }
            catch
            {
                // A leftover temp file is harmless.
            }
        }
    }

    /// <summary>Deletes the task if present. Needs elevation, because an elevated process created it.</summary>
    public static void Remove()
    {
        if (!Exists())
        {
            return;
        }

        var (exitCode, output, error) = RunSchtasks($"/Delete /TN \"{TaskName}\" /F", 15000);
        if (exitCode != 0)
        {
            throw new InvalidOperationException(FirstNonEmpty(error, output, $"schtasks exited with code {exitCode}."));
        }
    }

    private static string FirstNonEmpty(params string[] values) =>
        values.Select(value => value.Trim()).FirstOrDefault(value => value.Length > 0) ?? "";

    private static (int ExitCode, string Output, string Error) RunSchtasks(string arguments, int timeoutMs)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo("schtasks.exe", arguments)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            if (process is null)
            {
                return (-1, "", "Could not start schtasks.exe.");
            }

            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(timeoutMs))
            {
                try
                {
                    process.Kill();
                }
                catch
                {
                    // Already gone.
                }

                return (-1, "", "schtasks.exe timed out.");
            }

            return (process.ExitCode, outputTask.Result, errorTask.Result);
        }
        catch (Exception ex)
        {
            return (-1, "", ex.Message);
        }
    }
}
