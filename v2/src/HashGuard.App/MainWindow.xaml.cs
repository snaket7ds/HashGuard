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
        if (tag == "Home")
        {
            Navigate(typeof(HomePage), null);
        }
        else if (tag is not null)
        {
            Navigate(typeof(PlaceholderPage), tag);
        }
    }

    private void Navigate(Type page, object? parameter)
    {
        if (ContentFrame.CurrentSourcePageType == page && Equals(parameter, (ContentFrame.Content as Page)?.Tag))
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
