using System.Diagnostics;
using System.Runtime.InteropServices;

namespace HashGuard.Core;

/// <summary>What first-run setup asked for.</summary>
public sealed record InstallOptions(bool DesktopShortcut);

/// <summary>
/// Installs HashGuard for this PC: copies the single HashGuard.exe to Program Files\HashGuard,
/// brings along settings, logs and quarantine from the folder it ran from (never overwriting what
/// is already installed), adds Start menu (and optionally Desktop) shortcuts, then starts the
/// installed copy. Needs administrator rights; the app relaunches itself elevated with
/// <see cref="InstallArgument"/> to get them.
/// </summary>
/// <remarks>
/// Unlike v1's installer it doesn't end every HashGuard process: only a copy running from the
/// install folder itself (the one being replaced), and it doesn't install a root certificate.
/// </remarks>
public sealed class Installer(string sourceExe, string? installDirectory = null, string? startMenuDirectory = null, string? desktopDirectory = null)
{
    public const string InstallArgument = "--install";
    public const string DesktopShortcutArgument = "--desktop-shortcut";
    public const string PostInstallArgument = "--post-install";

    public static string DefaultInstallDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "HashGuard");

    public string InstallDirectory { get; } = installDirectory ?? DefaultInstallDirectory;

    public string InstalledExe => Path.Combine(InstallDirectory, "HashGuard.exe");

    /// <summary>Replaceable in tests: shortcut creation and starting the installed copy.</summary>
    internal Action<string, string>? CreateShortcutOverride { get; init; }

    internal Action<string>? StartOverride { get; init; }

    internal Func<string, IReadOnlyList<int>>? FindRunningOverride { get; init; }

    /// <summary>Replaceable in tests, so they never touch the real registry or Task Scheduler.</summary>
    internal IIntegrationStore? IntegrationStoreOverride { get; init; }

    /// <summary>True when HashGuard already runs from the install folder (nothing to copy).</summary>
    public bool IsRunningInstalled => FirewallRules.PathsEqual(sourceExe, InstalledExe);

    /// <summary>Copies, makes shortcuts and starts the installed copy. Throws when the copy fails.</summary>
    public void Install(InstallOptions options)
    {
        // A new install (not an upgrade, where your earlier choices stand) turns the Windows
        // features on: start at sign-in, the Explorer menu and the daily scan.
        var newInstall = !File.Exists(InstalledExe);
        if (!IsRunningInstalled)
        {
            StopInstalledCopy();
            Directory.CreateDirectory(InstallDirectory);
            File.Copy(sourceExe, InstalledExe, overwrite: true);
            var sourceFolder = Path.GetDirectoryName(sourceExe)!;
            CopyMissing(Path.Combine(sourceFolder, AppPaths.ConfigFolderName), Path.Combine(InstallDirectory, AppPaths.ConfigFolderName));
            CopyMissing(Path.Combine(sourceFolder, "logs"), Path.Combine(InstallDirectory, "logs"));
        }

        Directory.CreateDirectory(Path.Combine(InstallDirectory, AppPaths.ConfigFolderName));
        var createShortcut = CreateShortcutOverride ?? CreateShortcut;
        createShortcut(Path.Combine(startMenuDirectory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs"), "HashGuard.lnk"), InstalledExe);
        if (options.DesktopShortcut)
        {
            createShortcut(Path.Combine(desktopDirectory ?? Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "HashGuard.lnk"), InstalledExe);
        }

        if (newInstall)
        {
            // The installer runs as administrator, so the settings' "Run as administrator" choice
            // can get its prompt-free start-up task straight away.
            var settings = new SettingsStore(Path.Combine(InstallDirectory, AppPaths.ConfigFolderName, AppPaths.AppSettingsFileName)).Load();
            new WindowsIntegration(InstalledExe, isElevated: true, IntegrationStoreOverride).TurnOnDefaults(settings);
        }

        (StartOverride ?? (exe => Process.Start(new ProcessStartInfo(exe, PostInstallArgument) { UseShellExecute = true })))(InstalledExe);
    }

    /// <summary>Ends a copy running from the install folder, so its file can be replaced.</summary>
    private void StopInstalledCopy()
    {
        if (!File.Exists(InstalledExe))
        {
            return;
        }

        if (FindRunningOverride is { } find)
        {
            if (find(InstalledExe).Count > 0)
            {
                throw new IOException("The installed copy is still running.");
            }

            return;
        }

        ProcessCollector.StopRunning(InstalledExe);
    }

    /// <summary>Copies files that don't exist at the destination yet; existing ones are left as they are.</summary>
    internal static void CopyMissing(string source, string destination)
    {
        if (!Directory.Exists(source) || FirewallRules.PathsEqual(source, destination))
        {
            return;
        }

        foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            var target = Path.Combine(destination, Path.GetRelativePath(source, file));
            if (File.Exists(target))
            {
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target);
        }
    }

    /// <summary>A .lnk through the Windows Script Host shell, as v1 made them.</summary>
    public static void CreateShortcut(string shortcutPath, string targetPath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(shortcutPath)!);
        var shellType = Type.GetTypeFromProgID("WScript.Shell") ?? throw new InvalidOperationException("Windows Script Host isn't available to create shortcuts.");
        dynamic shell = Activator.CreateInstance(shellType)!;
        try
        {
            dynamic shortcut = shell.CreateShortcut(shortcutPath);
            shortcut.TargetPath = targetPath;
            shortcut.WorkingDirectory = Path.GetDirectoryName(targetPath);
            shortcut.IconLocation = $"{targetPath},0";
            shortcut.Save();
            Marshal.FinalReleaseComObject(shortcut);
        }
        finally
        {
            Marshal.FinalReleaseComObject(shell);
        }
    }
}
