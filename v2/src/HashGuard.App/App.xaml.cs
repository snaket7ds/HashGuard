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
        if (launch.Kind is not (LaunchKind.Minimized or LaunchKind.ScheduledScan))
        {
            window.Activate();
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
        var open = new MenuFlyoutItem { Text = "Open HashGuard" };
        open.Click += (_, _) => window?.ShowFromTray();
        var exit = new MenuFlyoutItem { Text = "Exit" };
        exit.Click += (_, _) => ExitApp();
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

    private void ExitApp()
    {
        tray?.Dispose();
        tray = null;
        window?.CloseForReal();
        Exit();
    }
}
