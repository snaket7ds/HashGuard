using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace HashGuard.App.Pages;

public sealed partial class PlaceholderPage : Page
{
    public PlaceholderPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        Tag = e.Parameter;
        PageTitle.Text = e.Parameter as string ?? "";
    }
}
