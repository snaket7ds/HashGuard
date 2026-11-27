using Microsoft.Win32;

namespace HashGuard.Core;

/// <summary>Where HashGuard is registered with Windows; replaceable in tests so they never touch the real registry.</summary>
public interface IIntegrationStore
{
    /// <summary>The HKCU Run value "HashGuard" (start at sign-in, not elevated), or null.</summary>
    string? RunCommand { get; }

    void SetRunCommand(string? command);

    /// <summary>The Explorer "Scan with HashGuard" command, or null when the menu isn't there.</summary>
    string? ContextMenuCommand { get; }

    void SetContextMenu(string? executablePath);

    /// <summary>The executable of the elevated sign-in task, or null when there's none.</summary>
    string? StartupTaskExecutable { get; }

    void InstallStartupTask(string executablePath);

    void RemoveStartupTask();

    /// <summary>The executable of the daily scan task, or null when there's none.</summary>
    string? DailyTaskExecutable { get; }

    void ApplyDailyTask(bool enabled, int hourLocal, string executablePath, bool highestPrivileges);
}

/// <summary>The real registry (per user) and Task Scheduler, with v1's names.</summary>
public sealed class WindowsIntegrationStore : IIntegrationStore
{
    public const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    public const string RunValueName = "HashGuard";

    /// <summary>Explorer menu keys: files, all file-system objects, and every file type.</summary>
    public static readonly string[] ContextMenuKeys =
    [
        @"Software\Classes\*\shell\HashGuard",
        @"Software\Classes\AllFilesystemObjects\shell\HashGuard",
        @"Software\Classes\SystemFileAssociations\*\shell\HashGuard",
    ];

    /// <summary>Names used before HashGuard was called HashGuard; removed when the menu is written.</summary>
    private static readonly string[] LegacyContextMenuKeys =
    [
        @"Software\Classes\*\shell\VTPS",
        @"Software\Classes\AllFilesystemObjects\shell\VTPS",
        @"Software\Classes\SystemFileAssociations\*\shell\VTPS",
        @"Software\Classes\*\shell\VTProcessScanner",
    ];

    public string? RunCommand
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath);
            return key?.GetValue(RunValueName) as string;
        }
    }

    public void SetRunCommand(string? command)
    {
        if (command is null)
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
            key?.DeleteValue(RunValueName, throwOnMissingValue: false);
            return;
        }

        using var created = Registry.CurrentUser.CreateSubKey(RunKeyPath);
        created.SetValue(RunValueName, command);
    }

    public string? ContextMenuCommand
    {
        get
        {
            using var command = Registry.CurrentUser.OpenSubKey(ContextMenuKeys[0] + @"\command");
            return command?.GetValue("") as string;
        }
    }

    public void SetContextMenu(string? executablePath)
    {
        foreach (var path in ContextMenuKeys.Concat(LegacyContextMenuKeys))
        {
            Registry.CurrentUser.DeleteSubKeyTree(path, throwOnMissingSubKey: false);
        }

        if (executablePath is null)
        {
            return;
        }

        foreach (var path in ContextMenuKeys)
        {
            using var key = Registry.CurrentUser.CreateSubKey(path);
            key.SetValue("", "Scan with HashGuard");
            key.SetValue("Icon", executablePath);
            key.SetValue("MultiSelectModel", "Single");
            using var command = key.CreateSubKey("command");
            command.SetValue("", $"\"{executablePath}\" --scan-file \"%1\"");
        }
    }

    public string? StartupTaskExecutable => QueryTaskExecutable(ElevatedStartupTask.TaskName);

    public void InstallStartupTask(string executablePath) =>
        ElevatedStartupTask.Install(executablePath, WindowsIntegration.CurrentUserSid());

    public void RemoveStartupTask() => ElevatedStartupTask.Remove();

    public string? DailyTaskExecutable => QueryTaskExecutable(ScheduledScan.TaskName);

    public void ApplyDailyTask(bool enabled, int hourLocal, string executablePath, bool highestPrivileges) =>
        ScheduledScan.Apply(enabled, hourLocal, executablePath, highestPrivileges);

    private static string? QueryTaskExecutable(string taskName)
    {
        var (exitCode, output, _) = ElevatedStartupTask.RunSchtasks($"/Query /TN \"{taskName}\" /XML", 8000);
        return exitCode == 0 ? ElevatedStartupTask.ReadCommand(output) : null;
    }
}

/// <summary>What is registered with Windows, and for which copy of HashGuard.</summary>
public sealed record IntegrationStatus(
    bool StartWithWindows,
    bool StartsElevated,
    bool RightClickMenu,
    bool DailyScan,
    string? StartupOwner,
    string? RightClickOwner,
    string? DailyScanOwner);

/// <summary>
/// HashGuard's place in Windows: starting at sign-in (the Run key, or an elevated logon task when
/// "Run as administrator" is on, so there's no UAC prompt), the daily scan task, and Explorer's
/// "Scan with HashGuard" menu. Same names as v1.
/// </summary>
/// <remarks>
/// It never takes a registration over from another copy of HashGuard that still exists (an
/// installed v1, or another v2): the "owner" fields name that copy and the setters refuse. A
/// registration pointing at a file that no longer exists is free to take.
/// </remarks>
public sealed class WindowsIntegration(string executablePath, bool isElevated, IIntegrationStore? store = null)
{
    private readonly IIntegrationStore store = store ?? new WindowsIntegrationStore();

    public string ExecutablePath { get; } = Path.GetFullPath(executablePath);

    public bool IsElevated { get; } = isElevated;

    public IntegrationStatus Read()
    {
        var runExe = ExecutableOf(store.RunCommand);
        var taskExe = ExecutableOf(store.StartupTaskExecutable);
        var menuExe = ExecutableOf(store.ContextMenuCommand);
        var dailyExe = ExecutableOf(store.DailyTaskExecutable);
        return new IntegrationStatus(
            IsMine(runExe) || IsMine(taskExe),
            IsMine(taskExe),
            IsMine(menuExe),
            IsMine(dailyExe),
            OtherOwner(runExe) ?? OtherOwner(taskExe),
            OtherOwner(menuExe),
            OtherOwner(dailyExe));
    }

    /// <summary>
    /// Starts HashGuard at sign-in, or stops it. With <paramref name="elevated"/>, an elevated logon
    /// task (no UAC prompt), which only an elevated copy can create; until then the Run key keeps
    /// HashGuard starting. The other way is removed, so only one starts it.
    /// </summary>
    public string SetStartWithWindows(bool on, bool elevated)
    {
        var status = Read();
        RefuseIfOwned(status.StartupOwner, "start with Windows");
        if (!on)
        {
            store.SetRunCommand(null);
            if (store.StartupTaskExecutable is not null)
            {
                if (!IsElevated)
                {
                    throw new UnauthorizedAccessException("The start-up task was created as administrator, so only HashGuard running as administrator can remove it.");
                }

                store.RemoveStartupTask();
            }

            return "HashGuard no longer starts with Windows.";
        }

        if (elevated && IsElevated)
        {
            store.InstallStartupTask(ExecutablePath);
            store.SetRunCommand(null);
            return "HashGuard starts as administrator when you sign in, without a prompt.";
        }

        store.SetRunCommand($"\"{ExecutablePath}\" {ElevatedStartupTask.StartupArguments}");
        if (!elevated && store.StartupTaskExecutable is not null && IsElevated)
        {
            store.RemoveStartupTask();
        }

        return elevated
            ? "HashGuard starts when you sign in. Start it once as administrator to make that start prompt-free and elevated."
            : "HashGuard starts when you sign in.";
    }

    public void SetRightClickMenu(bool on)
    {
        RefuseIfOwned(Read().RightClickOwner, "the Explorer menu");
        store.SetContextMenu(on ? ExecutablePath : null);
    }

    public void SetDailyScan(bool on, int hourLocal, bool elevated)
    {
        RefuseIfOwned(Read().DailyScanOwner, "the daily scan");
        store.ApplyDailyTask(on, Math.Clamp(hourLocal, 0, 23), ExecutablePath, elevated && IsElevated);
    }

    /// <summary>
    /// At start-up: re-points registrations that name a HashGuard.exe which no longer exists (moved
    /// or reinstalled) to this copy, and upgrades a Run-key start to the elevated task once running
    /// as administrator with "Run as administrator" on. Never throws.
    /// </summary>
    public void RepairAtStartup(AppSettings settings)
    {
        try
        {
            var status = Read();
            if (IsStale(store.ContextMenuCommand))
            {
                store.SetContextMenu(ExecutablePath);
            }

            if (IsStale(store.RunCommand) || (status.StartWithWindows && settings.RunElevated && IsElevated && !status.StartsElevated))
            {
                SetStartWithWindows(on: true, settings.RunElevated);
            }

            if (IsStale(store.DailyTaskExecutable) || (settings.ScheduledDailyScan && store.DailyTaskExecutable is null && status.DailyScanOwner is null))
            {
                store.ApplyDailyTask(settings.ScheduledDailyScan, settings.ScheduledScanHour, ExecutablePath, settings.RunElevated && IsElevated);
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Best-effort: Windows integration problems must never stop HashGuard starting.
        }
    }

    /// <summary>The executable in a command line: the quoted part, else everything before " --".</summary>
    public static string? ExecutableOf(string? command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return null;
        }

        var text = command.Trim();
        if (text.StartsWith('"'))
        {
            var end = text.IndexOf('"', 1);
            return end > 1 ? text[1..end] : null;
        }

        var cut = text.IndexOf(" --", StringComparison.Ordinal);
        return (cut > 0 ? text[..cut] : text).Trim();
    }

    public static string CurrentUserSid()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return identity.User?.Value ?? throw new InvalidOperationException("Could not read the current user's SID.");
    }

    private bool IsMine(string? exe) => exe is not null && FirewallRules.PathsEqual(exe, ExecutablePath);

    /// <summary>Another copy that still exists, or null.</summary>
    private string? OtherOwner(string? exe) => exe is not null && !IsMine(exe) && File.Exists(exe) ? exe : null;

    /// <summary>A registration naming a file that's gone (HashGuard was moved or reinstalled elsewhere).</summary>
    private static bool IsStale(string? command) => ExecutableOf(command) is { } exe && !File.Exists(exe);

    private static void RefuseIfOwned(string? owner, string what)
    {
        if (owner is not null)
        {
            throw new InvalidOperationException($"Another copy of HashGuard manages {what}: {owner}. Change it there, or uninstall that copy first.");
        }
    }
}
