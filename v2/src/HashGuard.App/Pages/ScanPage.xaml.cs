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
        if (e.Parameter is "start" && !ViewModel.IsScanning)
        {
            RunningAppsChoice.IsChecked = true;
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
