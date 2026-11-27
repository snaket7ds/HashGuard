using HashGuard.Core;

namespace HashGuard.App.Services;

/// <summary>
/// The scans HashGuard runs by itself, as v1 did: a full scan when it starts (if switched on), then
/// every 5 seconds a check of programs that started or changed since, and, when "Scan files I open
/// or select" is on, files you open or select every 15 seconds. Background checks wait for any
/// other scan and never upload files.
/// </summary>
public sealed class BackgroundScanner : IDisposable
{
    private static readonly TimeSpan Tick = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan FileActivityInterval = TimeSpan.FromSeconds(15);

    private readonly AppServices services;
    private readonly FileActivityQueue fileQueue = new();
    private readonly FileActivityWatcher fileWatcher;
    private readonly CancellationTokenSource stop = new();
    private DateTime lastFileScanUtc = DateTime.MinValue;

    public BackgroundScanner(AppServices services)
    {
        this.services = services;
        fileWatcher = new FileActivityWatcher(fileQueue);
    }

    /// <summary>Starts the loop; <paramref name="startupScan"/> runs a full scan first.</summary>
    public void Start(bool startupScan) => _ = Task.Run(() => RunAsync(startupScan, stop.Token));

    private async Task RunAsync(bool startupScan, CancellationToken cancellationToken)
    {
        if (startupScan)
        {
            await RunQuietlyAsync(async () =>
            {
                if (await services.Scans.ScanRunningAppsAsync(cancellationToken: cancellationToken) is not null)
                {
                    services.MarkFullScan(DateTime.Now);
                }
            });
        }

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(Tick, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            var settings = services.Settings;
            if (settings.ScanAllFiles && !fileWatcher.IsRunning)
            {
                fileWatcher.Start();
            }
            else if (!settings.ScanAllFiles && fileWatcher.IsRunning)
            {
                fileWatcher.Stop();
            }

            if (services.Scans.IsBusy)
            {
                continue;
            }

            // New or changed running programs, once a full scan has set the baseline.
            if (services.Scans.HasBaseline)
            {
                await RunQuietlyAsync(() => services.Scans.ScanChangedAppsAsync(cancellationToken: cancellationToken));
            }

            if (settings.ScanAllFiles && fileQueue.Count > 0 && DateTime.UtcNow - lastFileScanUtc >= FileActivityInterval && !services.Scans.IsBusy)
            {
                lastFileScanUtc = DateTime.UtcNow;
                var files = fileQueue.TakeAll();
                if (files.Count > 0)
                {
                    await RunQuietlyAsync(() => services.Scans.ScanFileActivityAsync(files, cancellationToken));
                }
            }
        }
    }

    private static async Task RunQuietlyAsync(Func<Task> scan)
    {
        try
        {
            await scan();
        }
        catch (OperationCanceledException)
        {
            // Shutting down.
        }
        catch (Exception ex)
        {
            App.WriteCrashLog(ex);
        }
    }

    public void Dispose()
    {
        stop.Cancel();
        stop.Dispose();
        fileWatcher.Dispose();
    }
}
