using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml.Linq;
using Microsoft.Win32;

namespace HashGuard.Core;

/// <summary>Running programs grouped by executable file, plus processes whose file couldn't be read.</summary>
public sealed record ProcessCollection(IReadOnlyDictionary<string, List<ProcessFile>> Files, IReadOnlyList<SkippedProcess> Skipped);

/// <summary>
/// Finds the executable files to scan: every running process, and optionally everything that
/// starts automatically (Run keys, Startup folders, services, scheduled tasks). Auto-start
/// entries appear as pseudo-processes with pid 0 named after their source, for example
/// "Startup: HKCU\Run\OneDrive".
/// </summary>
public static partial class ProcessCollector
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const uint QueryLimitedInformation = 0x1000;

    public static Task<ProcessCollection> CollectAsync(bool includeAutoStart, CancellationToken cancellationToken = default) =>
        Task.Run(
            () =>
            {
                var (grouped, skipped) = CollectRunningCore();
                cancellationToken.ThrowIfCancellationRequested();
                if (includeAutoStart)
                {
                    AddAutoStart(grouped);
                }

                return new ProcessCollection(grouped, skipped);
            },
            cancellationToken);

    /// <summary>
    /// Running processes. Uses QueryFullProcessImageName, which needs only limited query rights,
    /// so it reads the file of many protected and elevated processes that v1 (Process.MainModule) skipped.
    /// </summary>
    public static ProcessCollection CollectRunning()
    {
        var (grouped, skipped) = CollectRunningCore();
        return new ProcessCollection(grouped, skipped);
    }

    private static (Dictionary<string, List<ProcessFile>> Grouped, List<SkippedProcess> Skipped) CollectRunningCore()
    {
        var grouped = new Dictionary<string, List<ProcessFile>>(StringComparer.OrdinalIgnoreCase);
        var skipped = new List<SkippedProcess>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                int pid;
                string name;
                try
                {
                    pid = process.Id;
                    name = process.ProcessName;
                }
                catch
                {
                    continue;
                }

                if (pid is 0 or 4)
                {
                    continue; // Idle and System have no executable file.
                }

                var path = TryGetImagePath(pid, out var error);
                if (string.IsNullOrWhiteSpace(path) || !System.IO.Path.IsPathFullyQualified(path))
                {
                    skipped.Add(new SkippedProcess(pid, name, error ?? "NoImagePath"));
                    continue;
                }

                path = System.IO.Path.GetFullPath(path);
                if (!grouped.TryGetValue(path, out var files))
                {
                    files = [];
                    grouped[path] = files;
                }

                files.Add(new ProcessFile(pid, name, path));
            }
        }

        return (grouped, skipped);
    }

    public static IEnumerable<PersistenceTarget> CollectAutoStartTargets()
    {
        foreach (var target in RunKeyTargets(Registry.CurrentUser, "HKCU"))
        {
            yield return target;
        }

        foreach (var target in RunKeyTargets(Registry.LocalMachine, "HKLM"))
        {
            yield return target;
        }

        foreach (var folder in new[] { Environment.GetFolderPath(Environment.SpecialFolder.Startup), Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup) })
        {
            foreach (var target in StartupFolderTargets(folder))
            {
                yield return target;
            }
        }

        foreach (var target in ServiceTargets())
        {
            yield return target;
        }

        foreach (var target in ScheduledTaskTargets())
        {
            yield return target;
        }
    }

    private static void AddAutoStart(Dictionary<string, List<ProcessFile>> grouped)
    {
        foreach (var target in CollectAutoStartTargets())
        {
            if (!File.Exists(target.Path))
            {
                continue;
            }

            if (!grouped.TryGetValue(target.Path, out var files))
            {
                files = [];
                grouped[target.Path] = files;
            }

            if (!files.Any(f => f.Pid == 0 && string.Equals(f.Name, target.Source, StringComparison.OrdinalIgnoreCase)))
            {
                files.Add(new ProcessFile(0, target.Source, target.Path));
            }
        }
    }

    private static IEnumerable<PersistenceTarget> RunKeyTargets(RegistryKey root, string rootName)
    {
        using var key = root.OpenSubKey(RunKeyPath);
        if (key is null)
        {
            yield break;
        }

        foreach (var valueName in key.GetValueNames())
        {
            var path = HashGuardLogic.TryExtractExecutablePath(key.GetValue(valueName)?.ToString());
            if (!string.IsNullOrWhiteSpace(path))
            {
                yield return new PersistenceTarget(path, $"Startup: {rootName}\\Run\\{valueName}");
            }
        }
    }

    private static IEnumerable<PersistenceTarget> StartupFolderTargets(string folder)
    {
        if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
        {
            yield break;
        }

        foreach (var file in Directory.EnumerateFiles(folder))
        {
            var target = System.IO.Path.GetExtension(file).Equals(".lnk", StringComparison.OrdinalIgnoreCase)
                ? TryResolveShortcut(file)
                : file;
            if (!string.IsNullOrWhiteSpace(target))
            {
                yield return new PersistenceTarget(target, $"Startup folder: {System.IO.Path.GetFileName(file)}");
            }
        }
    }

    private static IEnumerable<PersistenceTarget> ServiceTargets()
    {
        using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (services is null)
        {
            yield break;
        }

        foreach (var serviceName in services.GetSubKeyNames())
        {
            using var service = services.OpenSubKey(serviceName);
            var imagePath = service?.GetValue("ImagePath")?.ToString();
            var path = HashGuardLogic.TryExtractExecutablePath(Environment.ExpandEnvironmentVariables(imagePath ?? ""));
            if (!string.IsNullOrWhiteSpace(path))
            {
                yield return new PersistenceTarget(path, $"Service: {serviceName}");
            }
        }
    }

    /// <summary>
    /// Scheduled tasks from their XML definitions. When that folder can't be read (HashGuard not
    /// elevated), falls back to asking schtasks.exe, which is slower.
    /// </summary>
    private static IEnumerable<PersistenceTarget> ScheduledTaskTargets()
    {
        var taskRoot = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
        var readAny = false;
        var denied = false;
        var targets = new List<PersistenceTarget>();
        if (Directory.Exists(taskRoot))
        {
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(taskRoot, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true });
            }
            catch
            {
                files = [];
            }

            foreach (var taskFile in files)
            {
                XDocument document;
                try
                {
                    document = XDocument.Load(taskFile);
                    readAny = true;
                }
                catch (UnauthorizedAccessException)
                {
                    denied = true;
                    continue;
                }
                catch
                {
                    continue;
                }

                foreach (var exec in document.Descendants().Where(e => e.Name.LocalName == "Exec"))
                {
                    var command = exec.Elements().FirstOrDefault(e => e.Name.LocalName == "Command")?.Value;
                    var arguments = exec.Elements().FirstOrDefault(e => e.Name.LocalName == "Arguments")?.Value;
                    var path = HashGuardLogic.TryExtractExecutablePath(Environment.ExpandEnvironmentVariables($"{command} {arguments}".Trim()));
                    if (!string.IsNullOrWhiteSpace(path))
                    {
                        targets.Add(new PersistenceTarget(path, $"Scheduled task: {System.IO.Path.GetRelativePath(taskRoot, taskFile)}"));
                    }
                }
            }
        }

        return readAny && !denied ? targets : targets.Concat(SchtasksTargets());
    }

    private static IEnumerable<PersistenceTarget> SchtasksTargets()
    {
        string output;
        try
        {
            using var process = Process.Start(new ProcessStartInfo("schtasks.exe", "/query /fo csv /v")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
            });
            if (process is null)
            {
                return [];
            }

            output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(10000);
            if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output))
            {
                return [];
            }
        }
        catch
        {
            return [];
        }

        var lines = output.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length < 2)
        {
            return [];
        }

        var columns = HashGuardLogic.ParseCsvLine(lines[0])
            .Select((name, index) => (Name: name.Trim(), Index: index))
            .GroupBy(c => c.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Index, StringComparer.OrdinalIgnoreCase);
        if (!columns.TryGetValue("TaskName", out var nameColumn) || !columns.TryGetValue("Task To Run", out var actionColumn))
        {
            return [];
        }

        var targets = new List<PersistenceTarget>();
        foreach (var line in lines.Skip(1))
        {
            var row = HashGuardLogic.ParseCsvLine(line);
            if (row.Count <= Math.Max(nameColumn, actionColumn))
            {
                continue;
            }

            var path = HashGuardLogic.TryExtractExecutablePath(row[actionColumn]);
            if (!string.IsNullOrWhiteSpace(path))
            {
                targets.Add(new PersistenceTarget(path, $"Scheduled task: {row[nameColumn].TrimStart('\\')}"));
            }
        }

        return targets;
    }

    private static string? TryResolveShortcut(string shortcutPath)
    {
        try
        {
            var shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType is null)
            {
                return null;
            }

            dynamic shell = Activator.CreateInstance(shellType)!;
            dynamic shortcut = shell.CreateShortcut(shortcutPath);
            return HashGuardLogic.TryExtractExecutablePath((string?)shortcut.TargetPath);
        }
        catch
        {
            return null;
        }
    }

    private static string? TryGetImagePath(int pid, out string? error)
    {
        error = null;
        var handle = OpenProcess(QueryLimitedInformation, false, pid);
        if (handle == 0)
        {
            error = $"OpenProcess error {Marshal.GetLastPInvokeError()}";
            return null;
        }

        try
        {
            var buffer = new char[1024];
            var size = (uint)buffer.Length;
            bool ok;
            unsafe
            {
                fixed (char* pointer = buffer)
                {
                    ok = QueryFullProcessImageName(handle, 0, pointer, ref size);
                }
            }

            if (!ok)
            {
                error = $"QueryFullProcessImageName error {Marshal.GetLastPInvokeError()}";
                return null;
            }

            return new string(buffer, 0, (int)size);
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, int processId);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryFullProcessImageName(nint process, uint flags, char* buffer, ref uint size);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);
}
