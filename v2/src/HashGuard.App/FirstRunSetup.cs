using HashGuard.App.Services;
using HashGuard.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HashGuard.App;

/// <summary>
/// The first start without settings: welcome, then install for this PC (recommended; Windows asks
/// for administrator permission) or keep running from this folder, then on to Settings for keys.
/// </summary>
internal static class FirstRunSetup
{
    public static async Task ShowAsync(MainWindow window, XamlRoot root)
    {
        var services = AppServices.Instance;
        var installed = AppServices.IsInstalledCopy;
        var install = new RadioButton { Content = "Install for this PC (recommended)", GroupName = "Setup", IsChecked = !installed };
        var portable = new RadioButton { Content = "Run from this folder", GroupName = "Setup" };
        var desktop = new CheckBox { Content = "Add a Desktop shortcut" };
        var content = new StackPanel { Spacing = 12, MaxWidth = 460 };
        content.Children.Add(new TextBlock
        {
            Text = "HashGuard checks the programs on your PC with reputation services, watches which programs use the network, and lets you quarantine or block what you don't trust.",
            TextWrapping = TextWrapping.WrapWholeWords,
        });
        if (!installed)
        {
            content.Children.Add(new TextBlock
            {
                Text = $"Installing copies HashGuard to {Installer.DefaultInstallDirectory} and adds it to the Start menu. It starts with Windows in the tray, adds “Scan with HashGuard” to File Explorer and scans daily; you can turn each off in Settings. Windows asks for permission.",
                TextWrapping = TextWrapping.WrapWholeWords,
                Style = (Style)Application.Current.Resources["CaptionTextBlockStyle"],
            });
            content.Children.Add(install);
            content.Children.Add(portable);
            content.Children.Add(desktop);
        }

        var dialog = new ContentDialog
        {
            XamlRoot = root,
            Title = "Welcome to HashGuard",
            Content = content,
            PrimaryButtonText = "Continue",
            DefaultButton = ContentDialogButton.Primary,
        };
        await dialog.ShowAsync();
        services.FinishFirstRun();

        if (!installed && install.IsChecked == true && Environment.ProcessPath is { } exe)
        {
            try
            {
                var arguments = Installer.InstallArgument + (desktop.IsChecked == true ? " " + Installer.DesktopShortcutArgument : "");
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(exe, arguments) { UseShellExecute = true, Verb = "runas" });
                (Application.Current as App)?.ExitApp();
                return;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                await new ContentDialog
                {
                    XamlRoot = root,
                    Title = "Not installed",
                    Content = "Installing needs administrator permission, which wasn't given. HashGuard keeps running from this folder; you can install it later by starting it again from a fresh download.",
                    CloseButtonText = "OK",
                }.ShowAsync();
            }
        }
        else if (!installed && desktop.IsChecked == true && Environment.ProcessPath is { } portableExe)
        {
            try
            {
                Installer.CreateShortcut(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "HashGuard.lnk"), portableExe);
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.Runtime.InteropServices.COMException or IOException or UnauthorizedAccessException)
            {
                // A missing shortcut isn't worth interrupting setup for.
            }
        }

        // Reputation sources need keys: Settings is where they go.
        if (services.Keys.VirusTotal.Length == 0 && services.Keys.MetaDefender.Length == 0)
        {
            window.ShowSettings();
        }
    }
}
