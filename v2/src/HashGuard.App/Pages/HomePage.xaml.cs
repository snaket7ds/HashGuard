using System.ComponentModel;
using HashGuard.App.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HashGuard.App.Pages;

public sealed partial class HomePage : Page
{
    public HomeViewModel ViewModel { get; } = new();

    public HomePage()
    {
        InitializeComponent();
        ViewModel.PropertyChanged += OnViewModelChanged;
        Loaded += (_, _) => ApplyTone(useTransitions: false);
    }

    private void OnViewModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(HomeViewModel.Tone))
        {
            ApplyTone(useTransitions: true);
        }
    }

    private void ApplyTone(bool useTransitions) =>
        VisualStateManager.GoToState(this, ViewModel.Tone.ToString(), useTransitions);

    private void PreviewPicker_SelectionChanged(object sender, SelectionChangedEventArgs e) =>
        ViewModel.ApplyPreviewState(PreviewPicker.SelectedIndex);
}
