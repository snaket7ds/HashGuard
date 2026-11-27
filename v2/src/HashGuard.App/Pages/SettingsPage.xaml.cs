using HashGuard.App.ViewModels;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;

namespace HashGuard.App.Pages;

public sealed partial class SettingsPage : Page
{
    private readonly DispatcherQueueTimer saveTimer;
    private bool loading;

    public SettingsViewModel ViewModel { get; } = new();

    public SettingsPage()
    {
        InitializeComponent();

        // Keys and numbers save once typing pauses, not on every keystroke.
        saveTimer = DispatcherQueue.CreateTimer();
        saveTimer.Interval = TimeSpan.FromMilliseconds(700);
        saveTimer.IsRepeating = false;
        saveTimer.Tick += (_, _) => ViewModel.Save();
        Unloaded += (_, _) =>
        {
            if (saveTimer.IsRunning)
            {
                saveTimer.Stop();
                ViewModel.Save();
            }
        };
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        loading = true;
        ViewModel.Load();
        VirusTotalKeyBox.Password = ViewModel.VirusTotalKey;
        MetaDefenderKeyBox.Password = ViewModel.MetaDefenderKey;
        loading = false;
    }

    private void VirusTotalKey_Changed(object sender, RoutedEventArgs e)
    {
        ViewModel.VirusTotalKey = VirusTotalKeyBox.Password;
        SaveSoon();
    }

    private void MetaDefenderKey_Changed(object sender, RoutedEventArgs e)
    {
        ViewModel.MetaDefenderKey = MetaDefenderKeyBox.Password;
        SaveSoon();
    }

    private void Number_Changed(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        // The first value comes from the binding when the page opens; that's not a change.
        if (!double.IsNaN(args.OldValue))
        {
            SaveSoon();
        }
    }

    private void SaveSoon()
    {
        if (loading)
        {
            return;
        }

        saveTimer.Stop();
        saveTimer.Start();
    }

    private void AddPublisher_Click(object sender, RoutedEventArgs e) => ViewModel.AddPublisher();

    private void NewPublisher_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == Windows.System.VirtualKey.Enter)
        {
            ViewModel.NewPublisher = ((TextBox)sender).Text;
            ViewModel.AddPublisher();
            e.Handled = true;
        }
    }

    private void RemovePublisher_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is string name)
        {
            ViewModel.RemovePublisher(name);
        }
    }

    private void RemoveIgnoredPath_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is string path)
        {
            ViewModel.RemoveIgnoredPath(path);
        }
    }

    private void RemoveIgnoredHash_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is string hash)
        {
            ViewModel.RemoveIgnoredHash(hash);
        }
    }

    // x:Bind helpers.
    public static Visibility VisibleWhenNot(bool value) => value ? Visibility.Collapsed : Visibility.Visible;

    public static Visibility VisibleWhenAny(int count) => count > 0 ? Visibility.Visible : Visibility.Collapsed;
}
