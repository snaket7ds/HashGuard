using H.NotifyIcon;
using H.NotifyIcon.Core;
using HashGuard.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HashGuard.App;

public partial class App : Application
{
    private MainWindow? window;
    private TaskbarIcon? tray;

    public App()
    {
        AppDomain.CurrentDomain.UnhandledException += (_, e) => WriteCrashLog(e.ExceptionObject as Exception);
        UnhandledException += (_, e) => WriteCrashLog(e.Exception);
        InitializeComponent();
    }

    /// <summary>Writes the error to logs\crash.log next to the scan logs; never throws.</summary>
    internal static void WriteCrashLog(Exception? error)
    {
        try
        {
            string directory;
            try
            {
                directory = HashGuard.Core.AppPaths.GetLogDirectory();
            }
            catch
            {
                directory = Path.GetTempPath();
            }

            Directory.CreateDirectory(directory);
            File.AppendAllText(Path.Combine(directory, "crash.log"), $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {error}{Environment.NewLine}{Environment.NewLine}");
        }
        catch
        {
            // Nothing more can be done.
        }
    }

    /// <summary>The main window, for pickers and dialogs that need its handle.</summary>
    public static MainWindow? MainWindow { get; private set; }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        try
        {
            Services.AppServices.Initialize();
        }
        catch (Exception ex)
        {
            WriteCrashLog(ex);
            throw;
        }

        window = new MainWindow();
        MainWindow = window;

        // Started with Windows or by the daily scan task: stay in the tray.
        var launch = Program.Launch;
        var startMinimized = Services.AppServices.Instance.Settings.StartMinimized && launch.Kind == LaunchKind.Show;
        if (launch.Kind is not (LaunchKind.Minimized or LaunchKind.ScheduledScan) && !startMinimized)
        {
            window.Activate();
        }

        // First start without settings: setup, once the window has its content.
        if (Services.AppServices.Instance.IsFirstRun && launch.Kind == LaunchKind.Show)
        {
            window.ShowFromTray();
            window.DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, async () =>
            {
                if (window.Content.XamlRoot is { } root)
                {
                    await FirstRunSetup.ShowAsync(window, root);
                }
            });
        }

        // The tray icon is created after the window is up, so it never delays the first frame.
        window.DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, CreateTrayIcon);

        if (launch.Kind is LaunchKind.ScanFile or LaunchKind.ScheduledScan)
        {
            window.DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => Handle(launch));
        }

        window.DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => _ = window.CheckForLegacyAsync());

        // Later launches of HashGuard.exe hand their request to this copy.
        Program.Instance?.Listen(request => window.DispatcherQueue.TryEnqueue(() => Handle(request)));

        // The network monitor: watches in the background when switched on, tells about new programs.
        var network = Services.AppServices.Instance.Network;
        network.NewAppsOnline += apps => window.DispatcherQueue.TryEnqueue(() => NotifyNewApps(apps));
        network.AutoBlocked += app => window.DispatcherQueue.TryEnqueue(() => Notify(
            "HashGuard blocked a program",
            $"{app.Name} was blocked in Windows Firewall because security vendors flag it as malicious. Open Firewall to unblock it.",
            urgent: true));
        network.Start();

        // Scans HashGuard runs by itself. A start-up scan is skipped when this launch already scans.
        var services = Services.AppServices.Instance;
        services.BackgroundFindings += findings => window.DispatcherQueue.TryEnqueue(() => NotifyFindings(findings));
        background = new Services.BackgroundScanner(services);
        // An installed copy keeps its Windows registrations pointing at itself (after a move or an
        // upgrade from v1). Portable and test copies leave them alone unless you change them in Settings.
        if (Services.AppServices.IsInstalledCopy)
        {
            _ = Task.Run(() => services.Integration.RepairAtStartup(services.Settings));
        }

        // Update checks: a minute after start, then every 6 hours, when switched on. Installing waits for you.
        services.UpdateFound += offer => window.DispatcherQueue.TryEnqueue(() => tray?.ShowNotification(
            $"HashGuard {offer.Version} is available",
            "Open HashGuard, then Settings → Updates, to install it.",
            NotificationIcon.Info));
        _ = Task.Run(async () =>
        {
            await Task.Delay(TimeSpan.FromMinutes(1));
            while (true)
            {
                if (services.Settings.AutoUpdateChecks)
                {
                    try
                    {
                        await services.CheckForUpdateAsync();
                    }
                    catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException or System.Text.Json.JsonException)
                    {
                        // Offline or GitHub busy: try again next time.
                    }
                }

                await Task.Delay(TimeSpan.FromHours(6));
            }
        });

        background.Start(startupScan: services.Settings.AutoProcessScan && launch.Kind is (LaunchKind.Show or LaunchKind.Minimized));
    }

    private Services.BackgroundScanner? background;

    private void NotifyFindings(IReadOnlyList<ScanResult> findings)
    {
        if (tray is null || findings.Count == 0)
        {
            return;
        }

        var threats = findings.Count(r => r.IsAlert);
        var first = ActivityText.DisplayName(findings[0].ProcessNames, findings[0].Path);
        var (title, message) = threats > 0
            ? (threats == 1 ? $"{first} is flagged as malicious" : $"{threats} files are flagged as malicious",
               "Open HashGuard to quarantine or ignore it.")
            : (findings.Count == 1 ? $"{first} needs your decision" : $"{findings.Count} files need your decision",
               "A background check found something to look at. Open HashGuard's Scan page.");
        tray.ShowNotification(title, message, threats > 0 ? NotificationIcon.Error : NotificationIcon.Warning);
    }

    private DateTime lastNetworkNoticeUtc = DateTime.MinValue;

    /// <summary>One notice at most every 10 seconds; several new programs are combined.</summary>
    private void NotifyNewApps(IReadOnlyList<NetworkAppView> apps)
    {
        if (window is null || window.FirewallPageVisible || DateTime.UtcNow - lastNetworkNoticeUtc < TimeSpan.FromSeconds(10))
        {
            return; // Already watching the list, or a notice was just shown.
        }

        if (apps.Count == 1)
        {
            var app = apps[0];
            var where = app.Endpoints.Count > 0 ? app.Endpoints[0].Display : "the network";
            Notify("New program went online", $"{app.Name} connected to {where} for the first time. {app.Verdict.Label} · {app.Signer}. Open Firewall to block it.", app.Untrusted);
        }
        else
        {
            var names = string.Join(", ", apps.Take(4).Select(a => a.Name)) + (apps.Count > 4 ? $" and {apps.Count - 4} more" : "");
            Notify($"{apps.Count} programs went online", $"{names} connected for the first time. Open Firewall to review them.", apps.Any(a => a.Untrusted));
        }
    }

    private void Notify(string title, string message, bool urgent)
    {
        if (tray is null)
        {
            return;
        }

        lastNetworkNoticeUtc = DateTime.UtcNow;
        tray.ShowNotification(title, message, urgent ? NotificationIcon.Warning : NotificationIcon.Info);
    }

    private void Handle(LaunchRequest request)
    {
        switch (request.Kind)
        {
            case LaunchKind.Show:
                window?.ShowFromTray();
                break;
            case LaunchKind.ScanFile when request.Path is not null:
                window?.QueueScanFile(request.Path);
                break;
            case LaunchKind.ScheduledScan:
                _ = RunScheduledScanAsync();
                break;
        }
    }

    /// <summary>The daily scan: quiet, no window. Skipped when a scan is already running.</summary>
    private static async Task RunScheduledScanAsync()
    {
        var services = Services.AppServices.Instance;
        if (services.Scans.IsBusy)
        {
            return;
        }

        try
        {
            if (await services.Scans.ScanRunningAppsAsync() is not null)
            {
                services.MarkFullScan(DateTime.Now);
            }
        }
        catch (Exception ex)
        {
            WriteCrashLog(ex);
        }
    }

    private void CreateTrayIcon()
    {
        using var iconStream = typeof(App).Assembly.GetManifestResourceStream("HashGuard.ico");
        var menu = new MenuFlyout();
        // Commands, not Click: in PopupMenu mode H.NotifyIcon copies the items into a native menu
        // and runs each item's Command; it never raises the WinUI Click event.
        var open = new MenuFlyoutItem { Text = "Open HashGuard", Command = new CommunityToolkit.Mvvm.Input.RelayCommand(() => window?.ShowFromTray()) };
        var exit = new MenuFlyoutItem { Text = "Exit", Command = new CommunityToolkit.Mvvm.Input.RelayCommand(ExitApp) };
        menu.Items.Add(open);
        menu.Items.Add(new MenuFlyoutSeparator());
        menu.Items.Add(exit);

        tray = new TaskbarIcon
        {
            ToolTipText = "HashGuard",
            Icon = iconStream is null ? null : new System.Drawing.Icon(iconStream),
            ContextMenuMode = ContextMenuMode.PopupMenu,
            ContextFlyout = menu,
            NoLeftClickDelay = true,
        };
        tray.LeftClickCommand = new CommunityToolkit.Mvvm.Input.RelayCommand(() => window?.ShowFromTray());
        tray.ForceCreate();
    }

    /// <summary>Exit from the tray menu. Runs after the menu has closed, not inside the tray icon's own callback.</summary>
    internal void ExitApp() => window?.DispatcherQueue.TryEnqueue(() =>
    {
        background?.Dispose();
        Services.AppServices.Instance.Network.Dispose();
        tray?.Dispose();
        tray = null;
        window?.CloseForReal();
        Exit();
    });
}
