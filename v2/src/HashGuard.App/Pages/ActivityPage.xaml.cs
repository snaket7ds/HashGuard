using HashGuard.App.Services;
using HashGuard.App.ViewModels;
using HashGuard.Core;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;

namespace HashGuard.App.Pages;

/// <summary>Picks the day-header or row template for each item in the Activity list.</summary>
public sealed partial class ActivityTemplateSelector : DataTemplateSelector
{
    public DataTemplate? DayTemplate { get; set; }

    public DataTemplate? EntryTemplate { get; set; }

    protected override DataTemplate? SelectTemplateCore(object item) => item is ActivityDayHeader ? DayTemplate : EntryTemplate;

    protected override DataTemplate? SelectTemplateCore(object item, DependencyObject container) => SelectTemplateCore(item);
}

public sealed partial class ActivityPage : Page
{
    private readonly DispatcherQueueTimer searchTimer;
    private readonly DispatcherQueueTimer refreshTimer;
    private string pendingSearch = "";

    public ActivityViewModel ViewModel { get; } = new();

    public ActivityPage()
    {
        InitializeComponent();
        searchTimer = DispatcherQueue.CreateTimer();
        searchTimer.Interval = TimeSpan.FromMilliseconds(200);
        searchTimer.IsRepeating = false;
        searchTimer.Tick += (_, _) => ViewModel.Search = pendingSearch;

        // New scan rows arrive in bursts; refresh once they settle.
        refreshTimer = DispatcherQueue.CreateTimer();
        refreshTimer.Interval = TimeSpan.FromSeconds(1);
        refreshTimer.IsRepeating = false;
        refreshTimer.Tick += async (_, _) => await ViewModel.LoadAsync();

        Loaded += (_, _) =>
        {
            ScanLog.Changed += OnHistoryChanged;
            AppServices.Instance.OutcomeChanged += OnHistoryChanged;
        };
        Unloaded += (_, _) =>
        {
            ScanLog.Changed -= OnHistoryChanged;
            AppServices.Instance.OutcomeChanged -= OnHistoryChanged;
        };
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e) => await ViewModel.LoadAsync();

    private void OnHistoryChanged() => DispatcherQueue.TryEnqueue(() =>
    {
        refreshTimer.Stop();
        refreshTimer.Start();
    });

    private void Search_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
    {
        pendingSearch = sender.Text;
        searchTimer.Stop();
        searchTimer.Start();
    }

    private void Filters_SelectionChanged(SelectorBar sender, SelectorBarSelectionChangedEventArgs args)
    {
        if (sender.SelectedItem?.Tag is string tag && Enum.TryParse<ActivityShow>(tag, out var show))
        {
            ViewModel.Show = show;
        }
    }

    private void Fold_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is ActivityItemViewModel item)
        {
            ViewModel.ToggleBatch(item);
        }
    }

    private void ShowInFolder_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is ActivityItemViewModel item)
        {
            var path = ActivityText.FriendlyPath(item.Entry.Path);
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe") { ArgumentList = { $"/select,{path}" } });
        }
    }

    private void OpenLogs_Click(object sender, RoutedEventArgs e)
    {
        var folder = AppPaths.GetLogDirectory();
        Directory.CreateDirectory(folder);
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe") { ArgumentList = { folder } });
    }

    // x:Bind helpers.
    public static Visibility HasText(string? value) => string.IsNullOrEmpty(value) ? Visibility.Collapsed : Visibility.Visible;

    public static Visibility EmptyVisible(bool isEmpty, bool isLoading) => isEmpty && !isLoading ? Visibility.Visible : Visibility.Collapsed;

    public static Brush KindTint(ActivityKind kind, bool isSummary) => Resource(isSummary ? "NeutralTintBrush" : kind switch
    {
        ActivityKind.Threat => "DangerTintBrush",
        ActivityKind.Suspicious or ActivityKind.Unknown or ActivityKind.Error => "AttentionTintBrush",
        ActivityKind.Clean => "GoodTintBrush",
        _ => "NeutralTintBrush",
    });

    public static Brush KindText(ActivityKind kind, bool isSummary) => Resource(isSummary ? "NeutralTextBrush" : kind switch
    {
        ActivityKind.Threat => "DangerTextBrush",
        ActivityKind.Suspicious or ActivityKind.Unknown or ActivityKind.Error => "AttentionTextBrush",
        ActivityKind.Clean => "GoodTextBrush",
        _ => "NeutralTextBrush",
    });

    private static Brush Resource(string key) => (Brush)Application.Current.Resources[key];
}
