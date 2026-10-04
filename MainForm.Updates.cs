using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;

namespace HashGuardScanner;

// Update checking, download, and install. Split out of MainForm.cs (item 11) so the
// update path can be read and reviewed on its own.
public sealed partial class MainForm : Form
{
    private async Task CheckForUpdatesAsync(bool automatic = false)
    {
        if (updateCheckRunning)
        {
            return;
        }

        updateCheckRunning = true;
        if (!automatic)
        {
            updateButton.Enabled = false;
            statusLabel.Text = "Checking for updates...";
        }
        try
        {
            var releasesApiUrl = $"https://api.github.com/repos/{AppConstants.GitHubOwner}/{AppConstants.GitHubRepo}/releases";
            var latestReleaseApiUrl = $"{releasesApiUrl}/latest";
            using var http = AppHttp.Create(TimeSpan.FromSeconds(30));
            http.DefaultRequestHeaders.UserAgent.ParseAdd($"HashGuard/{CurrentVersion}");
            http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");

            var release = await GetLatestGitHubReleaseAsync(http, latestReleaseApiUrl, releasesApiUrl);
            if (release is null || string.IsNullOrWhiteSpace(release.TagName))
            {
                throw new InvalidOperationException("GitHub release data is missing a tag name.");
            }

            var releaseVersionText = release.TagName.Trim().TrimStart('v', 'V');
            if (!Version.TryParse(releaseVersionText, out var latestVersion) || !Version.TryParse(CurrentVersion, out var currentVersion))
            {
                throw new InvalidOperationException("GitHub release version is invalid.");
            }

            if (latestVersion <= currentVersion)
            {
                if (!automatic)
                {
                    statusLabel.Text = $"HashGuard is up to date ({CurrentVersion}).";
                    MessageBox.Show(
                        this,
                        $"HashGuard is up to date.{Environment.NewLine}Current version: {CurrentVersion}{Environment.NewLine}Latest GitHub version: {latestVersion}",
                        "Update",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }
                return;
            }

            var exeAsset = release.Assets.FirstOrDefault(asset => string.Equals(asset.Name, "HashGuard.exe", StringComparison.OrdinalIgnoreCase));
            if (exeAsset is null || string.IsNullOrWhiteSpace(exeAsset.BrowserDownloadUrl))
            {
                throw new InvalidOperationException("GitHub release is missing the HashGuard.exe asset.");
            }

            var shaAsset = release.Assets.FirstOrDefault(asset =>
                string.Equals(asset.Name, "HashGuard.exe.sha256", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(asset.Name, "HashGuard.sha256", StringComparison.OrdinalIgnoreCase));
            var expectedSha256 = UpdateVerifier.GetReleaseAssetSha256(exeAsset);
            if (string.IsNullOrWhiteSpace(expectedSha256) && shaAsset is not null && !string.IsNullOrWhiteSpace(shaAsset.BrowserDownloadUrl))
            {
                var shaText = await DownloadGitHubUrlTextAsync(http, shaAsset.BrowserDownloadUrl, "download the checksum asset");
                expectedSha256 = UpdateVerifier.ParseSha256Text(shaText);
            }

            if (string.IsNullOrWhiteSpace(expectedSha256))
            {
                throw new InvalidOperationException("GitHub release is missing SHA-256 verification. Add a HashGuard.exe.sha256 release asset.");
            }

            if (automatic)
            {
                if (!IsRunningElevated())
                {
                    if (!string.Equals(lastAutoPromptedUpdateVersion, latestVersion.ToString(), StringComparison.OrdinalIgnoreCase))
                    {
                        lastAutoPromptedUpdateVersion = latestVersion.ToString();
                        statusLabel.Text = $"HashGuard {latestVersion} is available. Run elevated or click Update to install.";
                    }

                    return;
                }
            }
            else
            {
                var notes = string.IsNullOrWhiteSpace(release.Body) ? "" : $"{Environment.NewLine}{Environment.NewLine}{release.Body}";
                var accepted = MessageBox.Show(
                    this,
                    $"HashGuard {latestVersion} is available from GitHub. Install it now?{notes}",
                    "Update available",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question);
                if (accepted != DialogResult.Yes)
                {
                    statusLabel.Text = "Update canceled.";
                    return;
                }
            }

            var updateDir = Path.Combine(AppContext.BaseDirectory, "updates");
            Directory.CreateDirectory(updateDir);
            var downloadPath = Path.Combine(updateDir, "HashGuard.exe.new");
            statusLabel.Text = "Downloading update...";
            await DownloadGitHubUrlToFileAsync(http, exeAsset.BrowserDownloadUrl, downloadPath, "download the HashGuard.exe asset");

            statusLabel.Text = "Verifying update...";
            var actualSha256 = await FileHash.Sha256FileAsync(downloadPath);
            if (!string.Equals(actualSha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(downloadPath);
                throw new InvalidOperationException("Downloaded update hash did not match the GitHub release checksum. Update was not installed.");
            }

            if (!UpdateVerifier.PublisherMatchesCurrentBuild(Application.ExecutablePath, downloadPath, out var publisherDetail))
            {
                File.Delete(downloadPath);
                throw new InvalidOperationException($"Update Authenticode publisher check failed. {publisherDetail}");
            }

            InstallDownloadedUpdate(downloadPath);
        }
        catch (Exception ex)
        {
            if (automatic)
            {
                statusLabel.Text = $"Automatic update check failed: {ex.Message}";
            }
            else
            {
                statusLabel.Text = "Update failed";
                MessageBox.Show(this, $"Update failed:{Environment.NewLine}{ex.Message}", "Update", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        finally
        {
            updateButton.Enabled = true;
            updateCheckRunning = false;
        }
    }

    private void UpdateAutomaticUpdateTimer()
    {
        updateCheckTimer.Enabled = autoUpdateChecksBox.Checked;
    }

    private static bool IsRunningElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private void InstallDownloadedUpdate(string downloadPath)
    {
        var currentExe = Application.ExecutablePath;
        var backupPath = Path.Combine(Path.GetDirectoryName(currentExe)!, "HashGuard.exe.update-bak");
        var scriptPath = Path.Combine(Path.GetDirectoryName(currentExe)!, "HashGuard.update.cmd");

        // A small script with explicit rollback: copy the running exe aside, copy the verified
        // update over it, and only delete the backup once the swap succeeded. If the copy fails
        // (still locked, disk error) the backup is restored instead of being deleted.
        var script = string.Join(Environment.NewLine,
        [
            "@echo off",
            "setlocal",
            "for /l %%i in (1,1,60) do (",
            $"  copy /y \"{currentExe}\" \"{backupPath}\" >nul 2>nul",
            $"  copy /y \"{downloadPath}\" \"{currentExe}\" >nul 2>nul",
            "  if not errorlevel 1 goto ok",
            "  timeout /t 1 /nobreak >nul",
            " )",
            $"copy /y \"{backupPath}\" \"{currentExe}\" >nul 2>nul",
            "exit /b 1",
            ":ok",
            $"del /f /q \"{downloadPath}\" >nul 2>nul",
            $"del /f /q \"{backupPath}\" >nul 2>nul",
            $"start \"\" \"{currentExe}\"",
        ]);
        File.WriteAllText(scriptPath, script);
        Process.Start(new ProcessStartInfo("cmd.exe", $"/c \"{scriptPath}\"")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            WindowStyle = ProcessWindowStyle.Hidden,
        });

        exitRequested = true;
        trayIcon.Visible = false;
        Application.Exit();
    }

    private static async Task<Stream> GetGitHubStreamAsync(HttpClient http, string url, string action)
    {
        using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
        if (!response.IsSuccessStatusCode)
        {
            var details = await response.Content.ReadAsStringAsync();
            throw new InvalidOperationException(BuildGitHubHttpError(action, response.StatusCode, details));
        }

        var memory = new MemoryStream();
        await response.Content.CopyToAsync(memory);
        memory.Position = 0;
        return memory;
    }

    private static async Task<GitHubRelease?> GetLatestGitHubReleaseAsync(HttpClient http, string latestReleaseApiUrl, string releasesApiUrl)
    {
        try
        {
            await using var latestStream = await GetGitHubStreamAsync(http, latestReleaseApiUrl, "read the latest release");
            return await JsonSerializer.DeserializeAsync<GitHubRelease>(latestStream, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("404 Not Found", StringComparison.OrdinalIgnoreCase))
        {
            await using var releasesStream = await GetGitHubStreamAsync(http, releasesApiUrl, "read the releases list");
            var releases = await JsonSerializer.DeserializeAsync<List<GitHubRelease>>(releasesStream, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? [];
            return releases
                .Where(release => !release.Draft)
                .Select(release => new
                {
                    Release = release,
                    Parsed = Version.TryParse(release.TagName.Trim().TrimStart('v', 'V'), out var version),
                    Version = version
                })
                .Where(item => item.Parsed)
                .OrderByDescending(item => item.Version)
                .Select(item => item.Release)
                .FirstOrDefault();
        }
    }

    private static async Task<Stream> DownloadGitHubAssetStreamAsync(HttpClient http, string assetApiUrl)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, assetApiUrl);
        request.Headers.Accept.Clear();
        request.Headers.Accept.ParseAdd("application/octet-stream");
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
        if (!response.IsSuccessStatusCode)
        {
            var details = await response.Content.ReadAsStringAsync();
            throw new InvalidOperationException(BuildGitHubHttpError("download the release asset", response.StatusCode, details));
        }

        var memory = new MemoryStream();
        await response.Content.CopyToAsync(memory);
        memory.Position = 0;
        return memory;
    }

    private static async Task<Stream> DownloadGitHubUrlStreamAsync(HttpClient http, string url, string action)
    {
        using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
        if (!response.IsSuccessStatusCode)
        {
            var details = await response.Content.ReadAsStringAsync();
            throw new InvalidOperationException(BuildGitHubHttpError(action, response.StatusCode, details));
        }

        var memory = new MemoryStream();
        await response.Content.CopyToAsync(memory);
        memory.Position = 0;
        return memory;
    }

    /// <summary>
    /// Streams a GitHub asset straight to disk. The release asset is ~160 MB, so buffering it
    /// into a MemoryStream (as the generic stream helper does) doubled peak memory for nothing.
    /// </summary>
    private static async Task DownloadGitHubUrlToFileAsync(HttpClient http, string url, string destinationPath, string action)
    {
        using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
        if (!response.IsSuccessStatusCode)
        {
            var details = await response.Content.ReadAsStringAsync();
            throw new InvalidOperationException(BuildGitHubHttpError(action, response.StatusCode, details));
        }

        await using var output = File.Create(destinationPath);
        await response.Content.CopyToAsync(output);
    }

    private static async Task<string> DownloadGitHubUrlTextAsync(HttpClient http, string url, string action)
    {
        await using var stream = await DownloadGitHubUrlStreamAsync(http, url, action);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return await reader.ReadToEndAsync();
    }

    private static async Task<string> DownloadGitHubAssetTextAsync(HttpClient http, string assetApiUrl)
    {
        await using var stream = await DownloadGitHubAssetStreamAsync(http, assetApiUrl);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return await reader.ReadToEndAsync();
    }

    private static string BuildGitHubHttpError(string action, HttpStatusCode statusCode, string details)
    {
        var note = statusCode switch
        {
            HttpStatusCode.Unauthorized => "GitHub returned 401 Unauthorized.",
            HttpStatusCode.Forbidden => "GitHub returned 403 Forbidden. Verify the repository is public and release assets are available.",
            HttpStatusCode.NotFound => "GitHub returned 404 Not Found. Verify the repository, release, and asset names.",
            _ => $"GitHub returned {(int)statusCode} {statusCode}."
        };

        var detailText = string.IsNullOrWhiteSpace(details) ? "" : $"{Environment.NewLine}{details}";
        return $"Could not {action}. {note}{detailText}";
    }
}
