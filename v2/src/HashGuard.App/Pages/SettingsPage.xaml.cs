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
        _ = ViewModel.LoadIntegrationAsync();
    }

    private bool applying;

    /// <summary>Applies a Windows setting the user switched; a failure is explained and the switches re-read.</summary>
    private async Task ApplyAsync(Func<HashGuard.Core.WindowsIntegration, string?> apply)
    {
        if (!ViewModel.IntegrationReady || applying)
        {
            return; // A value loaded from Windows, or a change already being applied.
        }

        applying = true;
        try
        {
            if (await ViewModel.ApplyIntegrationAsync(apply) is { } error)
            {
                await new ContentDialog { XamlRoot = XamlRoot, Title = "Windows didn't take the change", Content = error, CloseButtonText = "OK" }.ShowAsync();
            }
        }
        finally
        {
            applying = false;
        }
    }

    private async void StartWithWindows_Toggled(object sender, RoutedEventArgs e)
    {
        var on = StartWithWindowsSwitch.IsOn;
        var elevated = ViewModel.RunElevated;
        await ApplyAsync(integration => integration.SetStartWithWindows(on, elevated));
    }

    private async void RunElevated_Toggled(object sender, RoutedEventArgs e)
    {
        if (loading || applying)
        {
            return;
        }

        ViewModel.Save();
        // Start at sign-in follows: the elevated task when on (and allowed), the Run key when off.
        if (ViewModel.StartWithWindows && ViewModel.CanChangeStartup)
        {
            var elevated = RunElevatedSwitch.IsOn;
            await ApplyAsync(integration => integration.SetStartWithWindows(true, elevated));
        }
    }

    private async void DailyScan_Toggled(object sender, RoutedEventArgs e)
    {
        var on = DailyScanSwitch.IsOn;
        var hour = (int)(double.IsNaN(ViewModel.DailyScanHour) ? 12 : ViewModel.DailyScanHour);
        var elevated = ViewModel.RunElevated;
        await ApplyAsync(integration =>
        {
            integration.SetDailyScan(on, hour, elevated);
            return null;
        });
    }

    private async void DailyHour_Changed(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (double.IsNaN(args.OldValue) || double.IsNaN(args.NewValue) || !ViewModel.DailyScan)
        {
            return;
        }

        var hour = (int)args.NewValue;
        var elevated = ViewModel.RunElevated;
        await ApplyAsync(integration =>
        {
            integration.SetDailyScan(true, hour, elevated);
            return null;
        });
    }

    private async void RightClick_Toggled(object sender, RoutedEventArgs e)
    {
        var on = RightClickSwitch.IsOn;
        await ApplyAsync(integration =>
        {
            integration.SetRightClickMenu(on);
            return null;
        });
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

    private async void CheckUpdates_Click(object sender, RoutedEventArgs e) => await ViewModel.CheckForUpdateAsync();

    private async void InstallUpdate_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.Offer is not { } offer)
        {
            return;
        }

        var notes = string.IsNullOrWhiteSpace(offer.Notes) ? "" : $"\n\n{offer.Notes.Trim()}";
        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = $"Install HashGuard {offer.Version}?",
            Content = new ScrollViewer
            {
                MaxHeight = 360,
                Content = new TextBlock { Text = $"HashGuard closes, updates and starts again.{notes}", TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true },
            },
            PrimaryButtonText = "Install",
            CloseButtonText = "Not now",
            DefaultButton = ContentDialogButton.Primary,
        };
        if (await dialog.ShowAsync() == ContentDialogResult.Primary && await ViewModel.InstallUpdateAsync())
        {
            (Application.Current as App)?.ExitApp();
        }
    }

    private bool askingAboutFiles;

    /// <summary>The first time file watching is switched on, explain what it watches (as v1 did).</summary>
    private async void ScanAllFiles_Toggled(object sender, RoutedEventArgs e)
    {
        if (loading || askingAboutFiles || !ScanAllFilesSwitch.IsOn || ViewModel.ScanAllFilesAcknowledged)
        {
            return;
        }

        askingAboutFiles = true;
        try
        {
            var dialog = new ContentDialog
            {
                XamlRoot = XamlRoot,
                Title = "Scan files you open or select?",
                Content = "HashGuard watches the files Windows lists as recently opened, and every 15 seconds the file selected in each File Explorer window. It checks them by hash only, when no other scan is running, and never uploads them. Pictures, video, audio and camera raw files are skipped.",
                PrimaryButtonText = "Turn on",
                CloseButtonText = "Cancel",
                DefaultButton = ContentDialogButton.Primary,
            };
            if (await dialog.ShowAsync() == ContentDialogResult.Primary)
            {
                ViewModel.AcceptFileWatching();
            }
            else
            {
                ViewModel.ScanAllFiles = false;
            }
        }
        finally
        {
            askingAboutFiles = false;
        }
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

    public static Visibility VisibleWhenText(string? value) => string.IsNullOrEmpty(value) ? Visibility.Collapsed : Visibility.Visible;

    public static string OwnerText(string? owner) => owner is null ? "" : $"Managed by another copy of HashGuard: {owner}";

    public static Visibility RestartNote(bool runElevated, bool isElevated) => runElevated != isElevated ? Visibility.Visible : Visibility.Collapsed;
}
