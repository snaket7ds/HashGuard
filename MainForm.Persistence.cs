using System.Diagnostics;
using System.Drawing;
using System.IO.Pipes;
using System.Net;
using System.Net.Http.Headers;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows.Forms;
using System.Xml.Linq;
using Microsoft.Win32;

namespace HashGuardScanner;

public sealed partial class MainForm : Form
{
    private static Task<ProcessCollectionResult> CollectProcessFilesAsync(CancellationToken cancellationToken = default) =>
        Task.Run(CollectProcessFiles, cancellationToken);

    private static Task<ProcessCollectionResult> CollectProcessFilesWithPersistenceAsync(CancellationToken cancellationToken = default) =>
        Task.Run(
            () =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                var collection = CollectProcessFiles();
                cancellationToken.ThrowIfCancellationRequested();
                AddPersistenceTargets(collection.Files);
                return collection;
            },
            cancellationToken);

    private static ProcessCollectionResult CollectProcessFiles()
    {
        var grouped = new Dictionary<string, List<ProcessFile>>(StringComparer.OrdinalIgnoreCase);
        var skipped = new List<SkippedProcess>();
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                var path = process.MainModule?.FileName;
                if (string.IsNullOrWhiteSpace(path))
                {
                    continue;
                }

                path = Path.GetFullPath(path);
                if (!grouped.TryGetValue(path, out var files))
                {
                    files = [];
                    grouped[path] = files;
                }

                files.Add(new ProcessFile(process.Id, process.ProcessName, path));
            }
            catch (Exception ex)
            {
                skipped.Add(GetSkippedProcess(process, ex));
            }
            finally
            {
                process.Dispose();
            }
        }

        return new ProcessCollectionResult(grouped, skipped);
    }

    private static void AddPersistenceTargets(Dictionary<string, List<ProcessFile>> grouped)
    {
        foreach (var target in CollectPersistenceTargets())
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

            files.Add(new ProcessFile(0, target.Source, target.Path));
        }
    }

    private static IEnumerable<PersistenceTarget> CollectPersistenceTargets()
    {
        foreach (var target in CollectRunKeyPersistenceTargets(Registry.CurrentUser, "HKCU", RunRegistryPath))
        {
            yield return target;
        }

        foreach (var target in CollectRunKeyPersistenceTargets(Registry.LocalMachine, "HKLM", RunRegistryPath))
        {
            yield return target;
        }

        foreach (var folder in GetStartupFolders())
        {
            foreach (var target in CollectStartupFolderTargets(folder))
            {
                yield return target;
            }
        }

        foreach (var target in CollectServiceTargets())
        {
            yield return target;
        }

        foreach (var target in CollectScheduledTaskTargets())
        {
            yield return target;
        }
    }

    private static IEnumerable<PersistenceTarget> CollectRunKeyPersistenceTargets(RegistryKey root, string rootName, string subKeyPath)
    {
        using var key = root.OpenSubKey(subKeyPath);
        if (key is null)
        {
            yield break;
        }

        foreach (var valueName in key.GetValueNames())
        {
            var value = key.GetValue(valueName)?.ToString();
            var path = TryExtractExecutablePath(value);
            if (!string.IsNullOrWhiteSpace(path))
            {
                yield return new PersistenceTarget(path, $"Startup: {rootName}\\Run\\{valueName}");
            }
        }
    }

    private static IEnumerable<string> GetStartupFolders()
    {
        yield return Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        yield return Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
    }

    private static IEnumerable<PersistenceTarget> CollectStartupFolderTargets(string folder)
    {
        if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
        {
            yield break;
        }

        foreach (var file in Directory.EnumerateFiles(folder))
        {
            var targetPath = Path.GetExtension(file).Equals(".lnk", StringComparison.OrdinalIgnoreCase)
                ? TryResolveShortcutTarget(file)
                : file;
            if (!string.IsNullOrWhiteSpace(targetPath))
            {
                yield return new PersistenceTarget(targetPath, $"Startup folder: {Path.GetFileName(file)}");
            }
        }
    }

    private static IEnumerable<PersistenceTarget> CollectServiceTargets()
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
            var path = TryExtractExecutablePath(Environment.ExpandEnvironmentVariables(imagePath ?? ""));
            if (!string.IsNullOrWhiteSpace(path))
            {
                yield return new PersistenceTarget(path, $"Service: {serviceName}");
            }
        }
    }

    private static IEnumerable<PersistenceTarget> CollectScheduledTaskTargets()
    {
        if (!OperatingSystem.IsWindows())
        {
            yield break;
        }

        foreach (var target in CollectScheduledTaskXmlTargets())
        {
            yield return target;
        }

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
                yield break;
            }

            output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(10000);
            if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output))
            {
                yield break;
            }
        }
        catch
        {
            yield break;
        }

        var lines = output.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length < 2)
        {
            yield break;
        }

        var headers = ParseCsvLine(lines[0]);
        var columns = headers
            .Select((name, index) => new { Name = name.Trim(), Index = index })
            .ToDictionary(item => item.Name, item => item.Index, StringComparer.OrdinalIgnoreCase);

        foreach (var line in lines.Skip(1))
        {
            var row = ParseCsvLine(line);
            var taskName = GetCsvValue(row, columns, "TaskName");
            var action = GetCsvValue(row, columns, "Task To Run");
            var path = TryExtractExecutablePath(action);
            if (!string.IsNullOrWhiteSpace(path))
            {
                yield return new PersistenceTarget(path, $"Scheduled task: {taskName}");
            }
        }
    }

    private static IEnumerable<PersistenceTarget> CollectScheduledTaskXmlTargets()
    {
        var taskRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
        if (!Directory.Exists(taskRoot))
        {
            yield break;
        }

        foreach (var taskFile in Directory.EnumerateFiles(taskRoot, "*", SearchOption.AllDirectories))
        {
            XDocument document;
            try
            {
                document = XDocument.Load(taskFile);
            }
            catch
            {
                continue;
            }

            var execNodes = document.Descendants().Where(element => element.Name.LocalName == "Exec");
            foreach (var exec in execNodes)
            {
                var command = exec.Elements().FirstOrDefault(element => element.Name.LocalName == "Command")?.Value;
                var arguments = exec.Elements().FirstOrDefault(element => element.Name.LocalName == "Arguments")?.Value;
                var path = TryExtractExecutablePath($"{command} {arguments}".Trim());
                if (!string.IsNullOrWhiteSpace(path))
                {
                    yield return new PersistenceTarget(path, $"Scheduled task: {Path.GetRelativePath(taskRoot, taskFile)}");
                }
            }
        }
    }

    private static string? TryResolveShortcutTarget(string shortcutPath)
    {
        try
        {
            var shell = Type.GetTypeFromProgID("WScript.Shell");
            if (shell is null)
            {
                return null;
            }

            dynamic shellObject = Activator.CreateInstance(shell)!;
            dynamic shortcut = shellObject.CreateShortcut(shortcutPath);
            return TryExtractExecutablePath((string?)shortcut.TargetPath);
        }
        catch
        {
            return null;
        }
    }

    private static string? TryExtractExecutablePath(string? command)
    {
        return HashGuardLogic.TryExtractExecutablePath(command);
    }

    private static SkippedProcess GetSkippedProcess(Process process, Exception ex)
    {
        var pid = 0;
        var name = "Unknown process";
        try
        {
            pid = process.Id;
        }
        catch
        {
            // Process metadata is best-effort after collection failures.
        }

        try
        {
            if (!string.IsNullOrWhiteSpace(process.ProcessName))
            {
                name = process.ProcessName;
            }
        }
        catch
        {
            // Process metadata is best-effort after collection failures.
        }

        return new SkippedProcess(pid, name, ex.GetType().Name);
    }
}
