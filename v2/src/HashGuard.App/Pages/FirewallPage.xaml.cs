using HashGuard.App.Services;
using HashGuard.App.ViewModels;
using HashGuard.Core;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;

namespace HashGuard.App.Pages;

public sealed partial class FirewallPage : Page
{
    private readonly DispatcherQueueTimer searchTimer;
    private string pendingSearch = "";

    public FirewallViewModel ViewModel { get; } = new();

    public FirewallPage()
    {
        InitializeComponent();
        searchTimer = DispatcherQueue.CreateTimer();
        searchTimer.Interval = TimeSpan.FromMilliseconds(200);
        searchTimer.IsRepeating = false;
        searchTimer.Tick += (_, _) => ViewModel.Search = pendingSearch;
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        var monitor = AppServices.Instance.Network;
        monitor.PageOpen = true;
        monitor.Polled += OnPolled;
        if (e.Parameter is string path)
        {
            SelectWhenListed(path);
        }

        await ViewModel.LoadAsync();
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        var monitor = AppServices.Instance.Network;
        monitor.PageOpen = false;
        monitor.Polled -= OnPolled;
    }

    private string? pendingSelection;

    /// <summary>Selects a program (from an alert) once it appears in the list.</summary>
    public void SelectWhenListed(string path) => pendingSelection = path;

    private void OnPolled() => DispatcherQueue.TryEnqueue(async () =>
    {
        await ViewModel.RefreshAsync();
        if (pendingSelection is { } path && ViewModel.Apps.FirstOrDefault(a => FirewallRules.PathsEqual(a.Path, path)) is { } app)
        {
            ViewModel.Selected = app;
            pendingSelection = null;
        }
    });

    private void Search_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
    {
        pendingSearch = sender.Text;
        searchTimer.Stop();
        searchTimer.Start();
    }

    private async void RowBlock_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not FirewallAppViewModel app)
        {
            return;
        }

        ViewModel.Selected = app;
        if (app.Blocked)
        {
            await UnblockAsync(app);
        }
        else
        {
            await BlockAsync(app);
        }
    }

    private async void Block_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.Selected is { } app)
        {
            await BlockAsync(app);
        }
    }

    private async Task BlockAsync(FirewallAppViewModel app)
    {
        var sensitive = AppServices.Instance.Network.IsSensitive(app.Path);
        var inbound = new CheckBox { Content = "Also block incoming connections" };
        var content = new StackPanel { Spacing = 12 };
        content.Children.Add(new TextBlock
        {
            Text = "HashGuard adds a Windows Firewall rule that stops this program's outgoing connections. Connections already open may continue until it reconnects. Unblock undoes it.",
            TextWrapping = TextWrapping.WrapWholeWords,
        });
        if (sensitive)
        {
            content.Children.Add(new InfoBar
            {
                IsOpen = true,
                IsClosable = false,
                Severity = InfoBarSeverity.Warning,
                Title = "Part of Windows or HashGuard",
                Message = "Blocking it can break Windows Update, DNS, sign-in or HashGuard's own lookups.",
            });
        }

        content.Children.Add(inbound);
        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = $"Block {app.Name}?",
            Content = content,
            PrimaryButtonText = "Block",
            CloseButtonText = "Cancel",
            DefaultButton = sensitive ? ContentDialogButton.Close : ContentDialogButton.Primary,
        };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary)
        {
            return;
        }

        if (await ViewModel.BlockAsync(app, inbound.IsChecked == true) is { } error)
        {
            await Tell("Couldn't block the program", error);
        }
    }

    private async void Unblock_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.Selected is { } app)
        {
            await UnblockAsync(app);
        }
    }

    private async Task UnblockAsync(FirewallAppViewModel app)
    {
        if (await ViewModel.UnblockAsync(app) is { } error)
        {
            await Tell("Couldn't unblock the program", error);
        }
    }

    private void Scan_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.Selected is { } app && File.Exists(app.Path))
        {
            App.MainWindow?.QueueScanFile(app.Path);
        }
    }

    private void ShowFile_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.Selected is { } app && File.Exists(app.Path))
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe") { ArgumentList = { $"/select,{app.Path}" } });
        }
    }

    private async void RemoveAll_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = "Remove all HashGuard rules?",
            Content = "Every program HashGuard blocked can connect again. Only rules HashGuard added are removed; your own Windows Firewall rules aren't touched.",
            PrimaryButtonText = "Remove all",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await dialog.ShowAsync() == ContentDialogResult.Primary)
        {
            await Tell("HashGuard rules", await ViewModel.RemoveAllAsync());
        }
    }

    private void OpenLog_Click(object sender, RoutedEventArgs e)
    {
        var log = AppPaths.GetNetworkActionLogPath();
        var target = File.Exists(log) ? $"/select,{log}" : AppPaths.GetLogDirectory();
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe") { ArgumentList = { target } });
    }

    private async Task Tell(string title, string message) =>
        await new ContentDialog { XamlRoot = XamlRoot, Title = title, Content = message, CloseButtonText = "OK" }.ShowAsync();

    // x:Bind helpers.
    public static bool Not(bool value) => !value;

    public static bool HasText(string? value) => !string.IsNullOrWhiteSpace(value);

    public static Visibility VisibleWhenNot(bool value) => value ? Visibility.Collapsed : Visibility.Visible;

    public static Visibility ShowBlock(bool blocked) => blocked ? Visibility.Collapsed : Visibility.Visible;

    public static Visibility ShowUnblock(bool blocked) => blocked ? Visibility.Visible : Visibility.Collapsed;

    public static Brush ToneTint(ActivityKind kind) => Resource(kind switch
    {
        ActivityKind.Threat => "DangerTintBrush",
        ActivityKind.Suspicious => "AttentionTintBrush",
        ActivityKind.Clean => "GoodTintBrush",
        _ => "NeutralTintBrush",
    });

    public static Brush ToneText(ActivityKind kind) => Resource(kind switch
    {
        ActivityKind.Threat => "DangerTextBrush",
        ActivityKind.Suspicious => "AttentionTextBrush",
        ActivityKind.Clean => "GoodTextBrush",
        _ => "NeutralTextBrush",
    });

    private static Brush Resource(string key) => (Brush)Application.Current.Resources[key];
}
