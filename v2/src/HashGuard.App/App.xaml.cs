using H.NotifyIcon;
using H.NotifyIcon.Core;
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
        window.Activate();

        // The tray icon is created after the window is up, so it never delays the first frame.
        window.DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, CreateTrayIcon);
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
