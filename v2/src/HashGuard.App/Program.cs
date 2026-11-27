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
            Instance.Dispose();
        }
    }
}
