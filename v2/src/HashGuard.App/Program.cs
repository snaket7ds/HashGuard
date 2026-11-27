using HashGuard.Core;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;

namespace HashGuard.App;

/// <summary>
/// Entry point. Before any window opens, checks whether HashGuard is already running for this
/// user; if so, hands this launch to it (show the window, scan a file, run the daily scan) and exits.
/// </summary>
public static class Program
{
    /// <summary>What this launch asked for, read by <see cref="App"/>.</summary>
    internal static LaunchRequest Launch { get; private set; } = new(LaunchKind.Show);

    /// <summary>This copy's claim on being the running HashGuard.</summary>
    internal static SingleInstance? Instance { get; private set; }

    [STAThread]
    private static int Main(string[] args)
    {
        Launch = LaunchRequest.Parse(args);
        Instance = SingleInstance.TryClaim();
        if (Instance is null)
        {
            // Another copy is running. If it can't be reached (still starting after the wait, or
            // stuck), exit anyway rather than open a second copy next to it.
            return SingleInstance.TrySend(Launch) ? 0 : 1;
        }

        if (TryRelaunchElevated(args))
        {
            return 0;
        }

        try
        {
            WinRT.ComWrappersSupport.InitializeComWrappers();
            Application.Start(callback =>
            {
                SynchronizationContext.SetSynchronizationContext(new DispatcherQueueSynchronizationContext(DispatcherQueue.GetForCurrentThread()));
                _ = new App();
            });
            return 0;
        }
        finally
        {
            Instance?.Dispose();
        }
    }

    /// <summary>
    /// "Run as administrator" is on but this copy isn't: start an elevated copy (Windows asks) and
    /// let it take over. Declining the prompt keeps this copy running, not elevated.
    /// </summary>
    private static bool TryRelaunchElevated(string[] args)
    {
        bool runElevated;
        try
        {
            runElevated = new SettingsStore().Load().RunElevated;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }

        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        if (!runElevated || new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator)
            || Environment.ProcessPath is not { } exe)
        {
            return false;
        }

        // Free the single-instance claim so the elevated copy can take it.
        Instance?.Dispose();
        Instance = null;
        try
        {
            var arguments = string.Join(' ', args.Select(arg => arg.Length > 0 && !arg.Contains(' ') && !arg.Contains('"') ? arg : $"\"{arg.Replace("\"", "\\\"")}\""));
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(exe, arguments) { UseShellExecute = true, Verb = "runas" });
            return true;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // Declined: carry on without administrator rights.
            Instance = SingleInstance.TryClaim();
            return Instance is null && SingleInstance.TrySend(Launch);
        }
    }
}
