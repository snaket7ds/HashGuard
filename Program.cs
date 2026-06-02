using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;

namespace HashGuardScanner;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        if (TrySendScanToRunningInstance(Environment.GetCommandLineArgs()))
        {
            return;
        }

        if (FirstRunSetup.RelaunchElevatedIfInstalled())
        {
            return;
        }

        if (!FirstRunSetup.EnsureConfigured())
        {
            return;
        }

        Application.Run(new MainForm(Environment.GetCommandLineArgs()));
    }

    private static bool TrySendScanToRunningInstance(string[] args)
    {
        var scanFile = ParseScanFile(args);
        if (string.IsNullOrWhiteSpace(scanFile))
        {
            return false;
        }

        try
        {
            using var pipe = new NamedPipeClientStream(".", MainForm.ScanPipeName, PipeDirection.Out);
            pipe.Connect(700);
            using var writer = new StreamWriter(pipe, Encoding.UTF8) { AutoFlush = true };
            writer.WriteLine(scanFile);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string? ParseScanFile(string[] args)
    {
        for (var index = 0; index < args.Length - 1; index++)
        {
            if (string.Equals(args[index], "--scan-file", StringComparison.OrdinalIgnoreCase))
            {
                return args[index + 1];
            }
        }

        return null;
    }
}

internal static class FirstRunSetup
{
    private const string InstallDirectory = @"C:\Program Files\HashGuard";

    public static bool EnsureConfigured()
    {
        var args = Environment.GetCommandLineArgs();
        if (args.Any(arg => string.Equals(arg, "--post-install", StringComparison.OrdinalIgnoreCase)))
        {
            MainForm.RepairRightClickScanIfNeeded();
            DeleteOriginalFromArgs(args);
            return File.Exists(MainForm.GetAppSettingsPath()) || ConfigurePortable();
        }

        if (args.Any(arg => string.Equals(arg, "--install", StringComparison.OrdinalIgnoreCase)))
        {
            return IsAdministrator() ? InstallAndRelaunch() : RelaunchElevated("--install");
        }

        if (File.Exists(MainForm.GetAppSettingsPath()))
        {
            return true;
        }

        var choice = ShowTopMostMessageBox(
            "HashGuard is not configured yet. Install to C:\\Program Files\\HashGuard and create Desktop/Start Menu shortcuts?\n\nChoose No to run portable from this folder.",
            "HashGuard First Run",
            MessageBoxButtons.YesNoCancel,
            MessageBoxIcon.Question);

        if (choice == DialogResult.Cancel)
        {
            return false;
        }

        if (choice == DialogResult.Yes)
        {
            return IsAdministrator() ? InstallAndRelaunch() : RelaunchElevated("--install");
        }

        return ConfigurePortable();
    }

    public static bool RelaunchElevatedIfInstalled()
    {
        if (IsAdministrator())
        {
            return false;
        }

        if (!IsInstalledUnderProgramFiles() && !MainForm.ShouldRunElevatedFromSettings())
        {
            return false;
        }

        RelaunchElevated(BuildCurrentArguments());
        return true;
    }

    private static bool ConfigurePortable()
    {
        var apiKey = PromptForApiKey("Portable setup");
        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            SaveInitialSettings(apiKey);
        }

        return true;
    }

    private static bool InstallAndRelaunch()
    {
        try
        {
            var currentExe = Application.ExecutablePath;
            Directory.CreateDirectory(InstallDirectory);
            var targetExe = Path.Combine(InstallDirectory, "HashGuard.exe");
            if (!PathsEqual(currentExe, targetExe))
            {
                CloseOtherInstallInstances(currentExe);
                File.Copy(currentExe, targetExe, overwrite: true);
                CopyExistingDataDirectory("config", currentExe);
                CopyExistingDataDirectory("logs", currentExe);
            }

            Directory.CreateDirectory(Path.Combine(InstallDirectory, "config"));
            if (ShouldCreateDesktopShortcut())
            {
                CreateShortcut(
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "HashGuard.lnk"),
                    targetExe);
            }

            CreateShortcut(
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs", "HashGuard.lnk"),
                targetExe);

            Process.Start(new ProcessStartInfo(targetExe, $"--post-install --delete-original \"{currentExe}\"") { UseShellExecute = true });
            DeleteOriginalAfterExit(currentExe, targetExe);
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return RelaunchElevated("--install");
        }
        catch (Exception ex)
        {
            ShowTopMostMessageBox($"Install failed:\n{ex.Message}", "HashGuard Install", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
    }

    private static void CloseOtherInstallInstances(string currentExe)
    {
        var current = Process.GetCurrentProcess();

        foreach (var process in Process.GetProcessesByName("HashGuard"))
        {
            if (process.Id == current.Id)
            {
                continue;
            }

            try
            {
                var otherExe = GetProcessPath(process);
                if (!string.IsNullOrWhiteSpace(otherExe) && PathsEqual(otherExe, currentExe))
                {
                    continue;
                }

                if (process.CloseMainWindow() && process.WaitForExit(3000))
                {
                    continue;
                }

                process.Kill(entireProcessTree: true);
                process.WaitForExit(3000);
            }
            catch
            {
                // The other HashGuard instance may already be closed or inaccessible.
            }
            finally
            {
                process.Dispose();
            }
        }
    }

    private static bool RelaunchElevated(string arguments)
    {
        try
        {
            Process.Start(new ProcessStartInfo(Application.ExecutablePath, arguments) { UseShellExecute = true, Verb = "runas" });
        }
        catch (Exception ex)
        {
            ShowTopMostMessageBox($"Could not relaunch HashGuard as administrator:\n{ex.Message}", "HashGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        return false;
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string? GetProcessPath(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsInstalledUnderProgramFiles()
    {
        var baseDirectory = Path.GetFullPath(AppContext.BaseDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        var programFilesPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        };

        return programFilesPaths
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(path => Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
            .Any(path => baseDirectory.Equals(path, StringComparison.OrdinalIgnoreCase)
                || baseDirectory.StartsWith(path + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || baseDirectory.StartsWith(path + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
    }

    private static string BuildCurrentArguments()
    {
        return string.Join(" ", Environment.GetCommandLineArgs().Skip(1).Select(QuoteArgument));
    }

    private static string QuoteArgument(string argument)
    {
        return argument.Contains(' ') || argument.Contains('"')
            ? $"\"{argument.Replace("\"", "\\\"")}\""
            : argument;
    }

    private static bool ShouldCreateDesktopShortcut()
    {
        var choice = ShowTopMostMessageBox(
            "Create a Desktop shortcut for HashGuard?",
            "HashGuard Install",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        return choice == DialogResult.Yes;
    }

    private static void CopyExistingDataDirectory(string directoryName, string currentExe)
    {
        var source = Path.Combine(Path.GetDirectoryName(currentExe) ?? "", directoryName);
        var target = Path.Combine(InstallDirectory, directoryName);
        if (!Directory.Exists(source) || PathsEqual(source, target))
        {
            return;
        }

        Directory.CreateDirectory(target);
        foreach (var sourcePath in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            var relativePath = Path.GetRelativePath(source, sourcePath);
            var targetPath = Path.Combine(target, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
            if (!File.Exists(targetPath))
            {
                File.Copy(sourcePath, targetPath);
            }
        }
    }

    private static void DeleteOriginalAfterExit(string originalExe, string installedExe)
    {
        if (PathsEqual(originalExe, installedExe) || !File.Exists(originalExe))
        {
            return;
        }

        try
        {
            var command = $"/c for /l %i in (1,1,60) do @(del /f /q \"{originalExe}\" 2>nul && exit /b 0 || timeout /t 1 /nobreak >nul)";
            Process.Start(new ProcessStartInfo("cmd.exe", command)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden,
            });
        }
        catch
        {
            // Installation already succeeded; leaving the original copy behind is non-fatal.
        }
    }

    private static void DeleteOriginalFromArgs(string[] args)
    {
        for (var index = 0; index < args.Length - 1; index++)
        {
            if (string.Equals(args[index], "--delete-original", StringComparison.OrdinalIgnoreCase))
            {
                DeleteOriginalAfterExit(args[index + 1], Application.ExecutablePath);
                return;
            }
        }
    }

    private static bool PathsEqual(string first, string second)
    {
        return string.Equals(
            Path.GetFullPath(first).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            Path.GetFullPath(second).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            StringComparison.OrdinalIgnoreCase);
    }

    private static string? PromptForApiKey(string title)
    {
        using var dialog = new Form
        {
            Text = title,
            StartPosition = FormStartPosition.CenterScreen,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            ClientSize = new Size(520, 150),
            MaximizeBox = false,
            MinimizeBox = false,
            TopMost = true,
            ShowInTaskbar = true,
        };

        var label = new Label { Text = "VirusTotal API key", AutoSize = true, Location = new Point(16, 18) };
        var input = new TextBox { UseSystemPasswordChar = true, Width = 480, Location = new Point(16, 44) };
        var ok = new Button { Text = "Save", DialogResult = DialogResult.OK, Location = new Point(332, 100), Width = 80 };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Location = new Point(416, 100), Width = 80 };
        dialog.Controls.Add(label);
        dialog.Controls.Add(input);
        dialog.Controls.Add(ok);
        dialog.Controls.Add(cancel);
        dialog.AcceptButton = ok;
        dialog.CancelButton = cancel;

        dialog.Shown += (_, _) =>
        {
            dialog.Activate();
            input.Focus();
        };

        using var owner = CreateTopMostOwner();
        owner.Show();
        owner.Activate();
        if (dialog.ShowDialog(owner) != DialogResult.OK)
        {
            return null;
        }

        var apiKey = input.Text.Trim();
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            ShowTopMostMessageBox("API key is required to finish setup.", "HashGuard Setup", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return null;
        }

        return apiKey;
    }

    private static DialogResult ShowTopMostMessageBox(string text, string caption, MessageBoxButtons buttons, MessageBoxIcon icon)
    {
        using var owner = CreateTopMostOwner();
        owner.Show();
        owner.Activate();
        owner.BringToFront();
        return MessageBox.Show(owner, text, caption, buttons, icon);
    }

    private static Form CreateTopMostOwner()
    {
        var owner = new Form
        {
            StartPosition = FormStartPosition.Manual,
            Location = new Point(-32000, -32000),
            Size = new Size(1, 1),
            ShowInTaskbar = false,
            TopMost = true,
        };
        owner.Load += (_, _) =>
        {
            owner.Activate();
            owner.BringToFront();
        };
        return owner;
    }

    private static void SaveInitialSettings(string apiKey)
    {
        var settings = new MainForm.AppSettings
        {
            ApiKeyEncrypted = MainForm.EncryptApiKey(apiKey),
        };
        Directory.CreateDirectory(MainForm.GetConfigDirectory());
        File.WriteAllText(MainForm.GetAppSettingsPath(), JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true }), Encoding.UTF8);
    }

    private static void CreateShortcut(string shortcutPath, string targetPath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(shortcutPath)!);
        var shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")!);
        var shortcut = shell!.GetType().InvokeMember("CreateShortcut", System.Reflection.BindingFlags.InvokeMethod, null, shell, [shortcutPath]);
        shortcut!.GetType().InvokeMember("TargetPath", System.Reflection.BindingFlags.SetProperty, null, shortcut, [targetPath]);
        shortcut.GetType().InvokeMember("WorkingDirectory", System.Reflection.BindingFlags.SetProperty, null, shortcut, [Path.GetDirectoryName(targetPath)]);
        shortcut.GetType().InvokeMember("IconLocation", System.Reflection.BindingFlags.SetProperty, null, shortcut, [$"{targetPath},0"]);
        shortcut.GetType().InvokeMember("Save", System.Reflection.BindingFlags.InvokeMethod, null, shortcut, null);
        Marshal.FinalReleaseComObject(shortcut);
        Marshal.FinalReleaseComObject(shell);
    }
}
