using System.ComponentModel;
using HashGuard.App.Services;
using HashGuard.App.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;

namespace HashGuard.App.Pages;

public sealed partial class HomePage : Page
{
    public HomeViewModel ViewModel { get; } = new();

    public HomePage()
    {
        InitializeComponent();
        ViewModel.PropertyChanged += OnViewModelChanged;
        Loaded += (_, _) => ApplyTone(useTransitions: false);
        AppServices.Instance.OutcomeChanged += () => DispatcherQueue.TryEnqueue(ViewModel.Refresh);
        ViewModel.Refresh();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e) => ViewModel.Refresh();

    private void OnViewModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(HomeViewModel.Tone))
        {
            ApplyTone(useTransitions: true);
        }
    }

    private void ApplyTone(bool useTransitions) =>
        VisualStateManager.GoToState(this, ViewModel.Tone.ToString(), useTransitions);

    private void ScanNow_Click(object sender, RoutedEventArgs e) => App.MainWindow?.ShowScanPage(startScan: true);

    private void Decisions_Click(object sender, RoutedEventArgs e) => App.MainWindow?.ShowScanPage(startScan: false);

    public static Brush ChipBackground(bool good) => (Brush)Application.Current.Resources[good ? "GoodTintBrush" : "AttentionTintBrush"];

    public static Brush ChipForeground(bool good) => (Brush)Application.Current.Resources[good ? "GoodTextBrush" : "AttentionTextBrush"];
}
