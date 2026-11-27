using System.Diagnostics;
using HashGuard.App.Pages;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Windows.Graphics;

namespace HashGuard.App;

public sealed partial class MainWindow : Window
{
    private bool reallyClosing;

    public MainWindow()
    {
        InitializeComponent();

        // HASHGUARD_THEME=Dark|Light overrides the saved theme, for screenshots.
        if (Enum.TryParse<ElementTheme>(Environment.GetEnvironmentVariable("HASHGUARD_THEME"), out var theme))
        {
            Root.RequestedTheme = theme;
        }
        else
        {
            ApplyTheme(ViewModels.SettingsViewModel.ThemeOf(Services.AppServices.Instance.Settings));
        }

        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
        AppWindow.SetIcon(Path.Combine(AppContext.BaseDirectory, "Assets", "HashGuard.ico"));

        var scale = (Content as FrameworkElement)?.XamlRoot?.RasterizationScale ?? GetDpiScale();
        AppWindow.Resize(new SizeInt32((int)(1120 * scale), (int)(760 * scale)));
        if (AppWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.PreferredMinimumWidth = (int)(760 * scale);
            presenter.PreferredMinimumHeight = (int)(560 * scale);
        }

        // Closing the window keeps HashGuard in the tray, as in v1.
        AppWindow.Closing += (_, e) =>
        {
            if (!reallyClosing)
            {
                e.Cancel = true;
                AppWindow.Hide();
            }
        };

        ContentFrame.Navigate(typeof(HomePage), null, new SuppressNavigationTransitionInfo());
        StartupProbe.Attach(this);
    }

    /// <summary>Shows the window from the tray or the taskbar and brings it to the front.</summary>
    public void ShowFromTray()
    {
        if (AppWindow.Presenter is OverlappedPresenter { State: OverlappedPresenterState.Minimized } presenter)
        {
            presenter.Restore();
        }

        AppWindow.Show();
        Activate();
        Win32.SetForegroundWindow(WinRT.Interop.WindowNative.GetWindowHandle(this));
        _ = CheckForLegacyAsync();
    }

    private IReadOnlyList<HashGuard.Core.LegacyProcess> legacyProcesses = [];

    /// <summary>Shows or hides the "HashGuard 1.x is also running" notice.</summary>
    public async Task CheckForLegacyAsync()
    {
        try
        {
            legacyProcesses = await Task.Run(HashGuard.Core.LegacyHashGuard.FindRunning);
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
            return;
        }

        if (legacyProcesses.Count == 0)
        {
            LegacyNotice.IsOpen = false;
            return;
        }

        var versions = string.Join(", ", legacyProcesses.Select(p => p.Version).Distinct());
        LegacyNotice.Title = $"HashGuard {versions} is also running";
        LegacyNotice.Message = "Running both means duplicate alerts and two copies managing the same firewall rules.";
        LegacyNotice.Severity = InfoBarSeverity.Warning;
        LegacyCloseButton.Visibility = Visibility.Visible;
        LegacyNotice.IsOpen = true;
    }

    private async void CloseLegacy_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new ContentDialog
        {
            XamlRoot = Content.XamlRoot,
            Title = "Close HashGuard 1.x?",
            Content = "HashGuard 1.x only hides to the tray when its window is closed, so this ends it. Anything it is doing, such as a scan, stops. Its settings, logs and quarantine stay, and this copy keeps using them.",
            PrimaryButtonText = "Close it",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary)
        {
            return;
        }

        var failed = await Task.Run(() => HashGuard.Core.LegacyHashGuard.Close(legacyProcesses));
        if (failed.Count == 0)
        {
            LegacyNotice.IsOpen = false;
            legacyProcesses = [];
            return;
        }

        LegacyNotice.Severity = InfoBarSeverity.Error;
        LegacyNotice.Title = "HashGuard 1.x couldn't be closed";
        LegacyNotice.Message = "It's probably running as administrator. Close it from its tray icon (right-click, Exit), or run this copy as administrator.";
        LegacyCloseButton.Visibility = Visibility.Collapsed;
    }

    private readonly HashGuard.Core.ScanRequestQueue fileRequests = new();
    private Microsoft.UI.Dispatching.DispatcherQueueTimer? fileRequestTimer;

    /// <summary>
    /// A right-click "Scan with HashGuard" request. Requests arriving together (a multi-file
    /// selection starts one launch per file) are gathered and scanned as one batch, after any
    /// scan that is already running.
    /// </summary>
    public void QueueScanFile(string rawPath)
    {
        var path = HashGuard.Core.ScanPathSecurity.TryNormalizeScanPath(rawPath, out _);
        if (path is null || fileRequests.TryEnqueue(path, DateTimeOffset.UtcNow) != HashGuard.Core.ScanRequestOutcome.Queued)
        {
            return;
        }

        ShowFromTray();
        if (fileRequestTimer is null)
        {
            fileRequestTimer = DispatcherQueue.CreateTimer();
            fileRequestTimer.IsRepeating = false;
            fileRequestTimer.Tick += (_, _) => DrainFileRequests();
        }

        fileRequestTimer.Interval = TimeSpan.FromMilliseconds(400);
        fileRequestTimer.Stop();
        fileRequestTimer.Start();
    }

    private void DrainFileRequests()
    {
        if (Services.AppServices.Instance.Scans.IsBusy)
        {
            fileRequestTimer!.Interval = TimeSpan.FromSeconds(1);
            fileRequestTimer.Start();
            return;
        }

        var files = fileRequests.DequeueAll();
        if (files.Count > 0)
        {
            ShowScanPage(files);
        }
    }

    public void CloseForReal()
    {
        reallyClosing = true;
        Close();
    }

    private void Nav_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.IsSettingsSelected)
        {
            Navigate(typeof(SettingsPage), null);
            return;
        }

        var tag = (args.SelectedItem as NavigationViewItem)?.Tag as string;
        switch (tag)
        {
            case "Home":
                Navigate(typeof(HomePage), null);
                break;
            case "Scan":
                Navigate(typeof(ScanPage), pendingScanParameter);
                pendingScanParameter = null;
                break;
            case "Quarantine":
                Navigate(typeof(QuarantinePage), null);
                break;
            case "Activity":
                Navigate(typeof(ActivityPage), null);
                break;
            case "Firewall":
                Navigate(typeof(FirewallPage), pendingFirewallPath);
                pendingFirewallPath = null;
                break;
            case not null:
                Navigate(typeof(PlaceholderPage), tag);
                break;
        }
    }

    private object? pendingScanParameter;

    /// <summary>Opens the Scan page; with <paramref name="startScan"/>, starts a full scan there.</summary>
    public void ShowScanPage(bool startScan) => ShowScanPage(startScan ? "start" : null);

    /// <summary>Opens the Scan page with a parameter: "start" for a full scan, or a list of files to scan.</summary>
    private void ShowScanPage(object? parameter)
    {
        var scanItem = Nav.MenuItems.OfType<NavigationViewItem>().First(i => (string)i.Tag == "Scan");
        if (ReferenceEquals(Nav.SelectedItem, scanItem))
        {
            ContentFrame.Navigate(typeof(ScanPage), parameter, new SuppressNavigationTransitionInfo());
            return;
        }

        pendingScanParameter = parameter;
        Nav.SelectedItem = scanItem;
    }

    /// <summary>Applies "system", "light" or "dark" (settings.json's names) to the whole window.</summary>
    public void ApplyTheme(string colorMode)
    {
        Root.RequestedTheme = colorMode switch
        {
            HashGuard.Core.AppConstants.ColorModeLight => ElementTheme.Light,
            HashGuard.Core.AppConstants.ColorModeDark => ElementTheme.Dark,
            _ => ElementTheme.Default,
        };

        // The caption buttons (minimise, maximise, close) don't follow the content theme by themselves.
        var dark = Root.ActualTheme == ElementTheme.Dark;
        AppWindow.TitleBar.ButtonForegroundColor = dark ? Microsoft.UI.Colors.White : Microsoft.UI.Colors.Black;
        AppWindow.TitleBar.ButtonHoverForegroundColor = AppWindow.TitleBar.ButtonForegroundColor;
        AppWindow.TitleBar.ButtonHoverBackgroundColor = dark ? Windows.UI.Color.FromArgb(0x19, 0xFF, 0xFF, 0xFF) : Windows.UI.Color.FromArgb(0x19, 0, 0, 0);
    }

    private string? pendingFirewallPath;

    /// <summary>Shows the window on the Firewall page, with this program selected (from an alert).</summary>
    public void ShowFirewall(string? path)
    {
        ShowFromTray();
        if (ContentFrame.Content is FirewallPage page)
        {
            if (path is not null)
            {
                page.SelectWhenListed(path);
            }

            return;
        }

        pendingFirewallPath = path;
        ShowPage("Firewall");
    }

    /// <summary>True while the Firewall page is on screen, so alerts about what it already shows can be skipped.</summary>
    public bool FirewallPageVisible => AppWindow.IsVisible && ContentFrame.Content is FirewallPage;

    /// <summary>Selects the navigation item with this tag, which opens its page.</summary>
    public void ShowPage(string tag) =>
        Nav.SelectedItem = Nav.MenuItems.OfType<NavigationViewItem>().First(i => (string)i.Tag == tag);

    private void Navigate(Type page, object? parameter)
    {
        if (ContentFrame.CurrentSourcePageType == page && parameter is null && page != typeof(PlaceholderPage))
        {
            return;
        }

        if (ContentFrame.CurrentSourcePageType == page && page == typeof(PlaceholderPage) && Equals(parameter, (ContentFrame.Content as Page)?.Tag))
        {
            return;
        }

        ContentFrame.Navigate(page, parameter, new EntranceNavigationTransitionInfo());
    }

    private double GetDpiScale() => Win32.GetDpiForWindow(WinRT.Interop.WindowNative.GetWindowHandle(this)) / 96.0;

    private static partial class Win32
    {
        [System.Runtime.InteropServices.LibraryImport("user32.dll")]
        internal static partial uint GetDpiForWindow(nint hwnd);

        [System.Runtime.InteropServices.LibraryImport("user32.dll")]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        internal static partial bool SetForegroundWindow(nint hwnd);
    }
}

/// <summary>
/// Spike-only: when HASHGUARD_MEASURE_FILE is set, writes the milliseconds from process start
/// to the first rendered frame into that file, then exits. Used to compare start-up time.
/// </summary>
internal static class StartupProbe
{
    public static void Attach(Window window)
    {
        var file = Environment.GetEnvironmentVariable("HASHGUARD_MEASURE_FILE");
        if (string.IsNullOrEmpty(file))
        {
            return;
        }

        var frames = 0;
        void OnRendering(object? sender, object e)
        {
            // Frame 2: the first frame with the page laid out and drawn.
            if (++frames < 2)
            {
                return;
            }

            CompositionTarget.Rendering -= OnRendering;
            var started = Process.GetCurrentProcess().StartTime;
            var ms = (DateTime.Now - started).TotalMilliseconds;
            File.AppendAllText(file, $"{ms:F0}{Environment.NewLine}");
            Environment.Exit(0);
        }

        CompositionTarget.Rendering += OnRendering;
    }
}
