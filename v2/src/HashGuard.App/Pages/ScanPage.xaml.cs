using HashGuard.App.ViewModels;
using HashGuard.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;

namespace HashGuard.App.Pages;

public sealed partial class ScanPage : Page
{
    public ScanViewModel ViewModel { get; } = new();

    public ScanPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        ViewModel.Load();
        if (ViewModel.IsScanning)
        {
            return;
        }

        if (e.Parameter is "start")
        {
            RunningAppsChoice.IsChecked = true;
            _ = ViewModel.ScanOrStopAsync();
        }
        else if (e.Parameter is IReadOnlyList<string> { Count: > 0 } files)
        {
            // Files from Explorer's right-click menu.
            ViewModel.SetChosenFiles(files);
            _ = ViewModel.ScanOrStopAsync();
        }
    }

    private async void Scan_Click(object sender, RoutedEventArgs e) => await ViewModel.ScanOrStopAsync();

    private void RunningAppsChoice_Checked(object sender, RoutedEventArgs e) => ViewModel.ScanFilesMode = false;

    private async void ChooseFiles_Click(object sender, RoutedEventArgs e)
    {
        var window = App.MainWindow;
        if (window is null)
        {
            return;
        }

        var picker = new Microsoft.Windows.Storage.Pickers.FileOpenPicker(window.AppWindow.Id)
        {
            ViewMode = Microsoft.Windows.Storage.Pickers.PickerViewMode.List,
        };
        picker.FileTypeFilter.Add("*");
        var files = await picker.PickMultipleFilesAsync();
        if (files is { Count: > 0 })
        {
            ViewModel.SetChosenFiles(files.Select(f => f.Path).ToList());
        }
    }

    private void IgnoreHash_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is FindingViewModel finding)
        {
            ViewModel.Ignore(finding, byPath: false);
        }
    }

    private void IgnorePath_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is FindingViewModel finding)
        {
            ViewModel.Ignore(finding, byPath: true);
        }
    }

    private async void Quarantine_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not FindingViewModel finding)
        {
            return;
        }

        var running = await ScanViewModel.CountRunningAsync(finding);
        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = $"Quarantine {finding.Name}?",
            Content = running == 0
                ? "HashGuard moves the file into its quarantine folder, where it can't run. You can restore it from Quarantine at any time."
                : $"{finding.Name} is running now ({(running == 1 ? "1 process" : $"{running} processes")}). HashGuard stops it, then moves the file into its quarantine folder, where it can't run. Anything unsaved in that app is lost. You can restore the file from Quarantine at any time.",
            PrimaryButtonText = running == 0 ? "Quarantine" : "Stop and quarantine",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary)
        {
            return;
        }

        var error = await ViewModel.QuarantineAsync(finding, stopRunning: running > 0);
        if (error is not null)
        {
            await new ContentDialog
            {
                XamlRoot = XamlRoot,
                Title = "Couldn't quarantine the file",
                Content = error,
                CloseButtonText = "OK",
            }.ShowAsync();
        }
    }

    private async void SendToVirusTotal_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not FindingViewModel finding)
        {
            return;
        }

        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = "Send this file to VirusTotal?",
            Content = $"{finding.Name} will be uploaded to VirusTotal so its engines can analyse it. Uploaded files can be seen by VirusTotal's partners, so don't send files with personal data.",
            PrimaryButtonText = "Send",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await dialog.ShowAsync() == ContentDialogResult.Primary)
        {
            await ViewModel.SendToVirusTotalAsync(finding);
        }
    }

    // x:Bind helpers.
    public static bool Not(bool value) => !value;

    public static Visibility VisibleWhenNot(bool value) => value ? Visibility.Collapsed : Visibility.Visible;

    public static bool HasText(string? value) => !string.IsNullOrWhiteSpace(value);

    public static Brush ChipBackground(bool isOn) => Resource(isOn ? "GoodTintBrush" : "NeutralTintBrush");

    public static Brush ChipForeground(bool isOn) => Resource(isOn ? "GoodTextBrush" : "NeutralTextBrush");

    public static Brush CountBackground(bool hasFindings) => Resource(hasFindings ? "AttentionTintBrush" : "GoodTintBrush");

    public static Brush CountForeground(bool hasFindings) => Resource(hasFindings ? "AttentionTextBrush" : "GoodTextBrush");

    public static Brush KindTint(ActivityKind kind) => Resource(kind switch
    {
        ActivityKind.Threat => "DangerTintBrush",
        ActivityKind.Suspicious or ActivityKind.Unknown or ActivityKind.Error => "AttentionTintBrush",
        ActivityKind.Clean => "GoodTintBrush",
        _ => "NeutralTintBrush",
    });

    public static Brush KindText(ActivityKind kind) => Resource(kind switch
    {
        ActivityKind.Threat => "DangerTextBrush",
        ActivityKind.Suspicious or ActivityKind.Unknown or ActivityKind.Error => "AttentionTextBrush",
        ActivityKind.Clean => "GoodTextBrush",
        _ => "NeutralTextBrush",
    });

    private static Brush Resource(string key) => (Brush)Application.Current.Resources[key];
}
