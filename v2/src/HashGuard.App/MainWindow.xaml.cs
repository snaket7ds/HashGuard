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

        // Spike-only: HASHGUARD_THEME=Dark|Light overrides the Windows theme for screenshots.
        if (Enum.TryParse<ElementTheme>(Environment.GetEnvironmentVariable("HASHGUARD_THEME"), out var theme))
        {
            Root.RequestedTheme = theme;
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

    public void ShowFromTray()
    {
        AppWindow.Show();
        Activate();
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
            Navigate(typeof(PlaceholderPage), "Settings");
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
            case not null:
                Navigate(typeof(PlaceholderPage), tag);
                break;
        }
    }

    private object? pendingScanParameter;

    /// <summary>Opens the Scan page; with <paramref name="startScan"/>, starts a full scan there.</summary>
    public void ShowScanPage(bool startScan)
    {
        var scanItem = Nav.MenuItems.OfType<NavigationViewItem>().First(i => (string)i.Tag == "Scan");
        if (ReferenceEquals(Nav.SelectedItem, scanItem))
        {
            ContentFrame.Navigate(typeof(ScanPage), startScan ? "start" : null, new SuppressNavigationTransitionInfo());
            return;
        }

        pendingScanParameter = startScan ? "start" : null;
        Nav.SelectedItem = scanItem;
    }

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
