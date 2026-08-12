using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
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
            using var pipe = new NamedPipeClientStream(".", AppPaths.ScanPipeName, PipeDirection.Out);
            pipe.Connect(2500);
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

    public static void EnsureCodeSigningCertificateTrusted(bool promptBeforeInstall = true, bool showSuccessMessage = true)
    {
        X509Certificate2? certificate = null;
        try
        {
            certificate = GetCurrentExecutableCertificate();
            if (certificate is null || IsCertificateTrustedForCurrentUser(certificate))
            {
                return;
            }

            if (promptBeforeInstall)
            {
                var choice = ShowTopMostMessageBox(
                    "HashGuard is signed with a local code-signing certificate that is not trusted by this Windows account yet.\n\nHashGuard can install this certificate into your Current User Trusted Root and Trusted Publishers stores so Windows can identify this build as signed by HashGuard on this PC.\n\nInstall the HashGuard local signing certificate now?",
                    "HashGuard Code Signing",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question);
                if (choice != DialogResult.Yes)
                {
                    return;
                }
            }

            InstallCertificateForCurrentUser(certificate);
            if (showSuccessMessage)
            {
                ShowTopMostMessageBox(
                    "The HashGuard local signing certificate was installed for the current Windows user.",
                    "HashGuard Code Signing",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
        }
        catch (Exception ex)
        {
            ShowTopMostMessageBox(
                $"HashGuard could not check or install its signing certificate:\n{ex.Message}",
                "HashGuard Code Signing",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
        }
        finally
        {
            certificate?.Dispose();
        }
    }

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
            var installOptions = SetupOptions.FromArgs(args);
            if (installOptions.TrustSigningCertificate)
            {
                EnsureCodeSigningCertificateTrusted(promptBeforeInstall: false, showSuccessMessage: false);
            }

            return IsAdministrator() ? InstallAndRelaunch(installOptions) : RelaunchElevated(BuildInstallArguments(installOptions));
        }

        if (File.Exists(MainForm.GetAppSettingsPath()))
        {
            EnsureCodeSigningCertificateTrusted();
            return true;
        }

        var options = ShowFirstRunOptionsDialog();
        if (options is null)
        {
            return false;
        }

        if (options.TrustSigningCertificate)
        {
            EnsureCodeSigningCertificateTrusted(promptBeforeInstall: false, showSuccessMessage: false);
        }

        if (options.InstallToProgramFiles)
        {
            return IsAdministrator() ? InstallAndRelaunch(options) : RelaunchElevated(BuildInstallArguments(options));
        }

        if (options.CreateDesktopShortcut)
        {
            CreateShortcut(
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "HashGuard.lnk"),
                Application.ExecutablePath);
        }

        return ConfigurePortable();
    }

    private static X509Certificate2? GetCurrentExecutableCertificate()
    {
        try
        {
            return new X509Certificate2(X509Certificate.CreateFromSignedFile(Application.ExecutablePath));
        }
        catch
        {
            return null;
        }
    }

    private static bool IsCurrentExecutableCertificateTrustNeeded()
    {
        using var certificate = GetCurrentExecutableCertificate();
        return certificate is not null && !IsCertificateTrustedForCurrentUser(certificate);
    }

    private static bool IsCertificateTrustedForCurrentUser(X509Certificate2 certificate)
    {
        return CertificateExists(StoreName.Root, certificate.Thumbprint)
            && CertificateExists(StoreName.TrustedPublisher, certificate.Thumbprint);
    }

    private static bool CertificateExists(StoreName storeName, string thumbprint)
    {
        using var store = new X509Store(storeName, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        return store.Certificates
            .Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
            .Count > 0;
    }

    private static void InstallCertificateForCurrentUser(X509Certificate2 certificate)
    {
        AddCertificate(StoreName.Root, certificate);
        AddCertificate(StoreName.TrustedPublisher, certificate);
    }

    private static void AddCertificate(StoreName storeName, X509Certificate2 certificate)
    {
        using var store = new X509Store(storeName, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        if (store.Certificates.Find(X509FindType.FindByThumbprint, certificate.Thumbprint, validOnly: false).Count == 0)
        {
            store.Add(certificate);
        }
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

    private static SetupOptions? ShowFirstRunOptionsDialog()
    {
        using var dialog = new Form
        {
            Text = "HashGuard First Run",
            StartPosition = FormStartPosition.CenterScreen,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            ClientSize = new Size(660, 270),
            MaximizeBox = false,
            MinimizeBox = false,
            TopMost = true,
            ShowInTaskbar = true,
        };

        var title = new Label
        {
            Text = "Choose how HashGuard should set up this build.",
            Dock = DockStyle.Top,
            Height = 40,
            Padding = new Padding(16, 12, 16, 0),
            Font = new Font("Segoe UI", 10, FontStyle.Bold),
        };
        var note = new Label
        {
            Text = "You can run portable, install to Program Files, trust the local signing certificate, and create a shortcut from one place.",
            Dock = DockStyle.Top,
            Height = 48,
            Padding = new Padding(16, 2, 16, 0),
            ForeColor = Color.DimGray,
        };
        var install = new CheckBox
        {
            Text = "Install HashGuard to C:\\Program Files\\HashGuard (If unchecked, app will run as portable)",
            Checked = true,
            AutoSize = false,
            Height = 28,
            Dock = DockStyle.Top,
            Padding = new Padding(16, 0, 0, 0),
        };
        var trustCert = new CheckBox
        {
            Text = "Trust this build's local code-signing certificate for this Windows user",
            Checked = IsCurrentExecutableCertificateTrustNeeded(),
            Enabled = IsCurrentExecutableCertificateTrustNeeded(),
            AutoSize = false,
            Height = 28,
            Dock = DockStyle.Top,
            Padding = new Padding(16, 0, 0, 0),
        };
        var shortcut = new CheckBox
        {
            Text = "Create a Desktop shortcut",
            Checked = false,
            AutoSize = false,
            Height = 28,
            Dock = DockStyle.Top,
            Padding = new Padding(16, 0, 0, 0),
        };
        var deleteOriginal = new CheckBox
        {
            Text = "Delete this original executable after installing",
            Checked = false,
            AutoSize = false,
            Height = 28,
            Dock = DockStyle.Top,
            Padding = new Padding(16, 0, 0, 0),
        };
        var ok = new Button { Text = "Continue", DialogResult = DialogResult.OK, Width = 96, Height = 32 };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Width = 86, Height = 32 };
        var buttons = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Bottom,
            Height = 54,
            Padding = new Padding(16, 10, 16, 10),
        };
        buttons.Controls.Add(ok);
        buttons.Controls.Add(cancel);

        void RefreshDeleteOriginal()
        {
            deleteOriginal.Enabled = install.Checked;
            if (!install.Checked)
            {
                deleteOriginal.Checked = false;
            }
        }

        install.CheckedChanged += (_, _) => RefreshDeleteOriginal();
        RefreshDeleteOriginal();

        dialog.Controls.Add(buttons);
        dialog.Controls.Add(deleteOriginal);
        dialog.Controls.Add(shortcut);
        dialog.Controls.Add(trustCert);
        dialog.Controls.Add(install);
        dialog.Controls.Add(note);
        dialog.Controls.Add(title);
        dialog.AcceptButton = ok;
        dialog.CancelButton = cancel;

        using var owner = CreateTopMostOwner();
        owner.Show();
        owner.Activate();
        if (dialog.ShowDialog(owner) != DialogResult.OK)
        {
            return null;
        }

        return new SetupOptions
        {
            InstallToProgramFiles = install.Checked,
            TrustSigningCertificate = trustCert.Checked,
            CreateDesktopShortcut = shortcut.Checked,
            DeleteOriginalAfterInstall = deleteOriginal.Checked,
        };
    }

    private static bool InstallAndRelaunch(SetupOptions options)
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
            if (options.CreateDesktopShortcut)
            {
                CreateShortcut(
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "HashGuard.lnk"),
                    targetExe);
            }

            CreateShortcut(
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs", "HashGuard.lnk"),
                targetExe);

            var postInstallArgs = options.DeleteOriginalAfterInstall
                ? $"--post-install --delete-original \"{currentExe}\""
                : "--post-install";
            Process.Start(new ProcessStartInfo(targetExe, postInstallArgs) { UseShellExecute = true });
            if (options.DeleteOriginalAfterInstall)
            {
                DeleteOriginalAfterExit(currentExe, targetExe);
            }

            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return RelaunchElevated(BuildInstallArguments(options));
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

    private static string BuildInstallArguments(SetupOptions options)
    {
        var args = new List<string> { "--install" };
        if (options.CreateDesktopShortcut)
        {
            args.Add("--create-desktop-shortcut");
        }

        if (options.DeleteOriginalAfterInstall)
        {
            args.Add("--delete-original-after-install");
        }

        if (options.TrustSigningCertificate)
        {
            args.Add("--trust-signing-cert");
        }

        return string.Join(" ", args);
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
        var settings = new AppSettings
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

    private sealed class SetupOptions
    {
        public bool InstallToProgramFiles { get; init; }
        public bool TrustSigningCertificate { get; init; }
        public bool CreateDesktopShortcut { get; init; }
        public bool DeleteOriginalAfterInstall { get; init; }

        public static SetupOptions FromArgs(string[] args)
        {
            return new SetupOptions
            {
                InstallToProgramFiles = true,
                TrustSigningCertificate = args.Any(arg => string.Equals(arg, "--trust-signing-cert", StringComparison.OrdinalIgnoreCase)),
                CreateDesktopShortcut = args.Any(arg => string.Equals(arg, "--create-desktop-shortcut", StringComparison.OrdinalIgnoreCase)),
                DeleteOriginalAfterInstall = args.Any(arg => string.Equals(arg, "--delete-original-after-install", StringComparison.OrdinalIgnoreCase)),
            };
        }
    }
}
