using HashGuard.Core;

/// <summary>Tests for v2's Windows integration with a fake registry and Task Scheduler.</summary>
internal static class V2IntegrationTests
{
    public static (string Name, Action Test)[] All =>
    [
        ("Integration: command lines give their executable", () =>
        {
            Equal(@"C:\Program Files\HashGuard\HashGuard.exe", WindowsIntegration.ExecutableOf("\"C:\\Program Files\\HashGuard\\HashGuard.exe\" --minimized"));
            Equal(@"C:\HG\HashGuard.exe", WindowsIntegration.ExecutableOf(@"C:\HG\HashGuard.exe --scan-file ""%1"""));
            Equal(@"C:\HG\HashGuard.exe", WindowsIntegration.ExecutableOf(@"C:\HG\HashGuard.exe"));
            Equal<string?>(null, WindowsIntegration.ExecutableOf("  "));
        }),
        ("Integration: another copy that still exists is never taken over", () => WithTemp(dir =>
        {
            var other = Write(dir, "v1", "HashGuard.exe");
            var mine = Write(dir, "v2", "HashGuard.exe");
            var store = new FakeStore { Run = $"\"{other}\" --minimized", Menu = $"\"{other}\" --scan-file \"%1\"", Daily = other };
            var integration = new WindowsIntegration(mine, isElevated: false, store);

            var status = integration.Read();
            False(status.StartWithWindows);
            Equal(other, status.StartupOwner);
            Equal(other, status.RightClickOwner);
            Equal(other, status.DailyScanOwner);
            Throws<InvalidOperationException>(() => integration.SetRightClickMenu(true));
            Throws<InvalidOperationException>(() => integration.SetStartWithWindows(false, false));
            Throws<InvalidOperationException>(() => integration.SetDailyScan(true, 9, false));
            Equal($"\"{other}\" --minimized", store.Run);

            integration.RepairAtStartup(new AppSettings { ScheduledDailyScan = true });
            Equal(other, WindowsIntegration.ExecutableOf(store.Menu));
            Equal(other, store.Daily);
        })),
        ("Integration: registrations for a copy that's gone are re-pointed at start-up", () => WithTemp(dir =>
        {
            var mine = Write(dir, "v2", "HashGuard.exe");
            var gone = Path.Combine(dir, "old", "HashGuard.exe");
            var store = new FakeStore { Run = $"\"{gone}\" --minimized", Menu = $"\"{gone}\" --scan-file \"%1\"", Daily = gone };
            var integration = new WindowsIntegration(mine, isElevated: false, store);
            integration.RepairAtStartup(new AppSettings { ScheduledDailyScan = true, ScheduledScanHour = 7 });
            Equal(mine, WindowsIntegration.ExecutableOf(store.Run));
            Equal(mine, WindowsIntegration.ExecutableOf(store.Menu));
            Equal(mine, store.Daily);
            Equal(7, store.DailyHour);
        })),
        ("Integration: start-up repair never creates an administrator task or anything new", () => WithTemp(dir =>
        {
            var mine = Write(dir, "v2", "HashGuard.exe");
            // Running as administrator with "Run as administrator" on and a Run-key start: left as it is.
            var store = new FakeStore { Run = $"\"{mine}\" --minimized" };
            new WindowsIntegration(mine, isElevated: true, store).RepairAtStartup(new AppSettings { RunElevated = true, ScheduledDailyScan = true });
            Equal<string?>(null, store.Task);
            Equal($"\"{mine}\" --minimized", store.Run);
            Equal<string?>(null, store.Daily);
            Equal<string?>(null, store.Menu);

            // A stale daily task is re-pointed without administrator rights.
            var gone = Path.Combine(dir, "old", "HashGuard.exe");
            var stale = new FakeStore { Daily = gone };
            new WindowsIntegration(mine, isElevated: true, stale).RepairAtStartup(new AppSettings { RunElevated = true, ScheduledDailyScan = true });
            Equal(mine, stale.Daily);
            False(stale.DailyElevated);
        })),
        ("Integration: start with Windows uses the Run key, or the elevated task when allowed", () => WithTemp(dir =>
        {
            var mine = Write(dir, "v2", "HashGuard.exe");
            var store = new FakeStore();
            var plain = new WindowsIntegration(mine, isElevated: false, store);
            plain.SetStartWithWindows(true, elevated: true);
            Equal($"\"{mine}\" --minimized", store.Run);
            Equal<string?>(null, store.Task);
            True(plain.Read().StartWithWindows);

            var admin = new WindowsIntegration(mine, isElevated: true, store);
            admin.SetStartWithWindows(true, elevated: true);
            Equal(mine, store.Task);
            Equal<string?>(null, store.Run);
            True(admin.Read().StartsElevated);

            Throws<UnauthorizedAccessException>(() => plain.SetStartWithWindows(false, false));
            admin.SetStartWithWindows(false, false);
            False(admin.Read().StartWithWindows);
        })),
        ("Integration: the Explorer menu and daily scan point at this copy", () => WithTemp(dir =>
        {
            var mine = Write(dir, "v2", "HashGuard.exe");
            var store = new FakeStore();
            var integration = new WindowsIntegration(mine, isElevated: false, store);
            integration.SetRightClickMenu(true);
            integration.SetDailyScan(true, 30, elevated: true);
            var status = integration.Read();
            True(status.RightClickMenu);
            True(status.DailyScan);
            Equal(23, store.DailyHour);
            False(store.DailyElevated); // Not running as administrator, so not highest privileges.
            integration.SetRightClickMenu(false);
            Equal<string?>(null, store.Menu);
        })),
        ("Installer: copies the exe and brings data along without overwriting what's installed", () => WithTemp(dir =>
        {
            var source = Write(dir, "portable", "HashGuard.exe");
            File.WriteAllText(Path.Combine(dir, "portable", "HashGuard.exe"), "new build");
            Write(dir, Path.Combine("portable", "config"), "settings.json");
            Write(dir, Path.Combine("portable", "logs"), "scan-log-20261127.csv");
            var target = Path.Combine(dir, "Program Files", "HashGuard");
            Directory.CreateDirectory(Path.Combine(target, "config"));
            File.WriteAllText(Path.Combine(target, "config", "settings.json"), "installed settings");

            var shortcuts = new List<string>();
            string? started = null;
            var installer = new Installer(source, target, Path.Combine(dir, "Start"), Path.Combine(dir, "Desktop"))
            {
                CreateShortcutOverride = (link, _) => shortcuts.Add(link),
                StartOverride = exe => started = exe,
                FindRunningOverride = _ => [],
                IntegrationStoreOverride = new FakeStore(),
            };
            installer.Install(new InstallOptions(DesktopShortcut: true));

            Equal("new build", File.ReadAllText(Path.Combine(target, "HashGuard.exe")));
            Equal("installed settings", File.ReadAllText(Path.Combine(target, "config", "settings.json")));
            True(File.Exists(Path.Combine(target, "logs", "scan-log-20261127.csv")));
            Equal(2, shortcuts.Count);
            Equal(installer.InstalledExe, started);
        })),
        ("Installer: refuses while the installed copy is running, and needs no copy when run from there", () => WithTemp(dir =>
        {
            var source = Write(dir, "portable", "HashGuard.exe");
            var target = Path.Combine(dir, "Program Files", "HashGuard");
            Write(dir, Path.Combine("Program Files", "HashGuard"), "HashGuard.exe");
            var busy = new Installer(source, target, Path.Combine(dir, "Start")) { CreateShortcutOverride = (_, _) => { }, StartOverride = _ => { }, FindRunningOverride = _ => [42], IntegrationStoreOverride = new FakeStore() };
            Throws<IOException>(() => busy.Install(new InstallOptions(false)));

            var installed = new Installer(Path.Combine(target, "HashGuard.exe"), target, Path.Combine(dir, "Start")) { CreateShortcutOverride = (_, _) => { }, StartOverride = _ => { }, IntegrationStoreOverride = new FakeStore() };
            True(installed.IsRunningInstalled);
            installed.Install(new InstallOptions(false));
        })),
        ("Installer: a new install turns on start at sign-in, the Explorer menu and the daily scan", () => WithTemp(dir =>
        {
            var source = Write(dir, "portable", "HashGuard.exe");
            var target = Path.Combine(dir, "Program Files", "HashGuard");
            var store = new FakeStore();
            new Installer(source, target, Path.Combine(dir, "Start")) { CreateShortcutOverride = (_, _) => { }, StartOverride = _ => { }, FindRunningOverride = _ => [], IntegrationStoreOverride = store }
                .Install(new InstallOptions(false));

            var exe = Path.Combine(target, "HashGuard.exe");
            Equal($"\"{exe}\" --minimized", store.Run);
            True(store.Menu!.StartsWith($"\"{exe}\"", StringComparison.Ordinal));
            Equal(exe, store.Daily);
            Equal(new AppSettings().ScheduledScanHour, store.DailyHour);
        })),
        ("Installer: an upgrade keeps your choices, and another copy's registrations are left alone", () => WithTemp(dir =>
        {
            // Upgrade: the exe is already installed and everything was switched off.
            var source = Write(dir, "portable", "HashGuard.exe");
            var target = Path.Combine(dir, "Program Files", "HashGuard");
            Write(dir, Path.Combine("Program Files", "HashGuard"), "HashGuard.exe");
            var upgrade = new FakeStore();
            new Installer(source, target, Path.Combine(dir, "Start")) { CreateShortcutOverride = (_, _) => { }, StartOverride = _ => { }, FindRunningOverride = _ => [], IntegrationStoreOverride = upgrade }
                .Install(new InstallOptions(false));
            Equal<string?>(null, upgrade.Run);
            Equal<string?>(null, upgrade.Menu);
            Equal<string?>(null, upgrade.Daily);

            // New install, but another existing copy has the Explorer menu: only that one is skipped.
            var other = Write(dir, "other", "HashGuard.exe");
            var shared = new FakeStore { Menu = $"\"{other}\" --scan-file \"%1\"" };
            new Installer(source, Path.Combine(dir, "Fresh", "HashGuard"), Path.Combine(dir, "Start")) { CreateShortcutOverride = (_, _) => { }, StartOverride = _ => { }, FindRunningOverride = _ => [], IntegrationStoreOverride = shared }
                .Install(new InstallOptions(false));
            Equal($"\"{other}\" --scan-file \"%1\"", shared.Menu);
            True(shared.Run is not null);
            True(shared.Daily is not null);
        })),
    ];

    private sealed class FakeStore : IIntegrationStore
    {
        public string? Run { get; set; }
        public string? Menu { get; set; }
        public string? Task { get; set; }
        public string? Daily { get; set; }
        public int DailyHour { get; private set; }
        public bool DailyElevated { get; private set; }

        public string? RunCommand => Run;

        public void SetRunCommand(string? command) => Run = command;

        public string? ContextMenuCommand => Menu;

        public void SetContextMenu(string? executablePath) => Menu = executablePath is null ? null : $"\"{executablePath}\" --scan-file \"%1\"";

        public string? StartupTaskExecutable => Task;

        public void InstallStartupTask(string executablePath) => Task = executablePath;

        public void RemoveStartupTask() => Task = null;

        public string? DailyTaskExecutable => Daily;

        public void ApplyDailyTask(bool enabled, int hourLocal, string executablePath, bool highestPrivileges)
        {
            Daily = enabled ? executablePath : null;
            DailyHour = hourLocal;
            DailyElevated = highestPrivileges;
        }
    }

    private static string Write(string dir, string folder, string name)
    {
        var path = Path.Combine(dir, folder, name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, "exe");
        return path;
    }

    private static void WithTemp(Action<string> test)
    {
        var dir = Directory.CreateTempSubdirectory("hg-int").FullName;
        try
        {
            test(dir);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static void Throws<T>(Action action) where T : Exception
    {
        try
        {
            action();
        }
        catch (T)
        {
            return;
        }

        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }

    private static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected <{expected}> but got <{actual}>.");
        }
    }

    private static void True(bool value)
    {
        if (!value)
        {
            throw new InvalidOperationException("Expected true.");
        }
    }

    private static void False(bool value) => True(!value);
}
