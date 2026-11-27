using HashGuard.App.ViewModels;
using HashGuard.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace HashGuard.App.Pages;

public sealed partial class QuarantinePage : Page
{
    public QuarantineViewModel ViewModel { get; } = new();

    public QuarantinePage()
    {
        InitializeComponent();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e) => await ViewModel.LoadAsync();

    private async void RestoreOriginal_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not QuarantineItemViewModel item)
        {
            return;
        }

        var target = item.Entry.OriginalPath;
        var replace = false;
        if (File.Exists(target))
        {
            var choice = await Ask(
                "A file is already there",
                $"Something else now exists at {target}. Replace it with the quarantined copy, or put the quarantined copy on the Desktop instead?",
                primary: "Replace",
                secondary: "Restore to the Desktop");
            if (choice == ContentDialogResult.None)
            {
                return;
            }

            if (choice == ContentDialogResult.Secondary)
            {
                await RestoreAsync(item, QuarantineStore.DesktopRestorePath(item.Entry), replace: false);
                return;
            }

            replace = true;
        }
        else if (await Ask(
                     $"Restore {item.Name}?",
                     $"It goes back to {target} and can run again.",
                     primary: "Restore") != ContentDialogResult.Primary)
        {
            return;
        }

        if (RiskScorer.IsWindowsOrProgramFilesPath(target)
            && await Ask("Restore into a protected folder?", $"{target} is inside Windows or Program Files. Restore there anyway?", primary: "Restore") != ContentDialogResult.Primary)
        {
            return;
        }

        await RestoreAsync(item, target, replace);
    }

    private async void RestoreDesktop_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is QuarantineItemViewModel item
            && await Ask($"Restore {item.Name} to the Desktop?", "It's put on your Desktop under its own name and can run again.", primary: "Restore") == ContentDialogResult.Primary)
        {
            await RestoreAsync(item, QuarantineStore.DesktopRestorePath(item.Entry), replace: false);
        }
    }

    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not QuarantineItemViewModel item)
        {
            return;
        }

        if (await Ask($"Delete {item.Name} permanently?", "The quarantined file is deleted for good. This can't be undone.", primary: "Delete") != ContentDialogResult.Primary)
        {
            return;
        }

        if (ViewModel.Delete(item) is { } error)
        {
            await Tell("Couldn't delete the file", error);
        }
    }

    private void RemoveMissing_Click(object sender, RoutedEventArgs e) => ViewModel.RemoveMissing();

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        var folder = AppPaths.GetQuarantineDirectory();
        Directory.CreateDirectory(folder);
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe") { ArgumentList = { folder } });
    }

    private async Task RestoreAsync(QuarantineItemViewModel item, string target, bool replace)
    {
        if (await ViewModel.RestoreAsync(item, target, replace) is { } error)
        {
            await Tell("Couldn't restore the file", error);
        }
    }

    private async Task<ContentDialogResult> Ask(string title, string content, string primary, string? secondary = null) =>
        await new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = title,
            Content = content,
            PrimaryButtonText = primary,
            SecondaryButtonText = secondary ?? "",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
        }.ShowAsync();

    private async Task Tell(string title, string content) =>
        await new ContentDialog { XamlRoot = XamlRoot, Title = title, Content = content, CloseButtonText = "OK" }.ShowAsync();

    // x:Bind helper.
    public static bool Not(bool value) => !value;
}
