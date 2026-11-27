using System.Globalization;
using System.Text;
using System.Xml.Linq;

namespace HashGuardScanner;

/// <summary>
/// The daily scan: a Task Scheduler task that starts HashGuard with <see cref="Argument"/>.
///
/// Since v1.1.0 it is on by default, so it has to work on PCs that are off at the set hour
/// (StartWhenAvailable runs a missed scan as soon as possible) and must not open a second
/// HashGuard: a running instance receives <see cref="PipeToken"/> over the scan pipe instead.
/// </summary>
internal static class ScheduledScan
{
    public const string TaskName = "HashGuardDailyScan";
    public const string Argument = "--scheduled-scan";
    /// <summary>Sent over the scan-request pipe; never a valid file path.</summary>
    public const string PipeToken = "::scheduled-scan";
    private const string TaskNamespace = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    /// <summary>Registers (replaces) or removes the task. Highest privileges needs an elevated caller.</summary>
    public static void Apply(bool enabled, int hourLocal, string executablePath, bool highestPrivileges = false)
    {
        if (!enabled)
        {
            ElevatedStartupTask.RunSchtasks($"/Delete /TN \"{TaskName}\" /F", 8000);
            return;
        }

        if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath))
        {
            return;
        }

        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var sid = identity.User?.Value;
        if (string.IsNullOrWhiteSpace(sid))
        {
            return;
        }

        var xml = BuildTaskXml(executablePath, sid, hourLocal, highestPrivileges, DateTime.Today);
        var xmlPath = Path.Combine(Path.GetTempPath(), $"hashguard-daily-{Guid.NewGuid():N}.xml");
        try
        {
            File.WriteAllText(xmlPath, xml, Encoding.Unicode);
            ElevatedStartupTask.RunSchtasks($"/Create /TN \"{TaskName}\" /XML \"{xmlPath}\" /F", 15000);
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

    /// <summary>
    /// Registers the task when the setting is on and the task is missing, points at another exe,
    /// or predates v1.1.0 (no <see cref="Argument"/>). Never throws: daily scan setup is best-effort.
    /// </summary>
    public static void EnsureRegistered(bool enabled, int hourLocal, string executablePath, bool highestPrivileges)
    {
        try
        {
            if (!enabled)
            {
                return;
            }

            var (exitCode, output, _) = ElevatedStartupTask.RunSchtasks($"/Query /TN \"{TaskName}\" /XML", 8000);
            if (exitCode == 0 && IsCurrent(output, executablePath))
            {
                return;
            }

            Apply(true, hourLocal, executablePath, highestPrivileges);
        }
        catch
        {
            // Locked-down machines may refuse Task Scheduler; scanning still works by hand.
        }
    }

    public static bool IsCurrent(string taskXml, string executablePath)
    {
        try
        {
            XNamespace ns = TaskNamespace;
            var exec = XDocument.Parse(taskXml).Descendants(ns + "Exec").FirstOrDefault();
            var command = exec?.Element(ns + "Command")?.Value.Trim().Trim('"');
            var arguments = exec?.Element(ns + "Arguments")?.Value ?? "";
            return command is not null
                && string.Equals(command, executablePath, StringComparison.OrdinalIgnoreCase)
                && arguments.Contains(Argument, StringComparison.OrdinalIgnoreCase);
        }
        catch (System.Xml.XmlException)
        {
            return false;
        }
    }

    public static string BuildTaskXml(string executablePath, string userSid, int hourLocal, bool highestPrivileges, DateTime startDay)
    {
        hourLocal = Math.Clamp(hourLocal, 0, 23);
        XNamespace ns = TaskNamespace;
        var start = startDay.Date.AddHours(hourLocal).ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture);
        var task = new XElement(ns + "Task",
            new XAttribute("version", "1.2"),
            new XElement(ns + "RegistrationInfo",
                new XElement(ns + "Author", "HashGuard"),
                new XElement(ns + "Description", "HashGuard's daily scan of running apps. Managed in HashGuard Settings.")),
            new XElement(ns + "Triggers",
                new XElement(ns + "CalendarTrigger",
                    new XElement(ns + "StartBoundary", start),
                    new XElement(ns + "Enabled", "true"),
                    new XElement(ns + "ScheduleByDay", new XElement(ns + "DaysInterval", "1")))),
            new XElement(ns + "Principals",
                new XElement(ns + "Principal",
                    new XAttribute("id", "Author"),
                    new XElement(ns + "UserId", userSid),
                    new XElement(ns + "LogonType", "InteractiveToken"),
                    new XElement(ns + "RunLevel", highestPrivileges ? "HighestAvailable" : "LeastPrivilege"))),
            new XElement(ns + "Settings",
                new XElement(ns + "MultipleInstancesPolicy", "IgnoreNew"),
                new XElement(ns + "DisallowStartIfOnBatteries", "false"),
                new XElement(ns + "StopIfGoingOnBatteries", "false"),
                // Run a missed scan (PC off or asleep at the set hour) as soon as possible.
                new XElement(ns + "StartWhenAvailable", "true"),
                new XElement(ns + "RunOnlyIfNetworkAvailable", "false"),
                new XElement(ns + "AllowStartOnDemand", "true"),
                new XElement(ns + "Enabled", "true"),
                new XElement(ns + "Hidden", "false"),
                new XElement(ns + "RunOnlyIfIdle", "false"),
                // The launcher exits at once when HashGuard is already running; otherwise HashGuard
                // stays in the tray, so no time limit.
                new XElement(ns + "ExecutionTimeLimit", "PT0S"),
                new XElement(ns + "Priority", "7")),
            new XElement(ns + "Actions",
                new XAttribute("Context", "Author"),
                new XElement(ns + "Exec",
                    new XElement(ns + "Command", executablePath),
                    new XElement(ns + "Arguments", $"{Argument} {ElevatedStartupTask.StartupArguments}"),
                    new XElement(ns + "WorkingDirectory", ElevatedStartupTask.WindowsDirectoryOf(executablePath)))));
        return new XDocument(new XDeclaration("1.0", "UTF-16", null), task).Declaration + Environment.NewLine + task;
    }
}
