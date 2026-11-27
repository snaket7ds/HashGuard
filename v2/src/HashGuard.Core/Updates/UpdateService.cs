using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;

namespace HashGuard.Core;

/// <summary>A release version: "1.1.8", "v2.0.0", "2.0.0-beta.2" (build metadata after '+' ignored).</summary>
public sealed record ReleaseVersion(Version Number, string Prerelease) : IComparable<ReleaseVersion>
{
    public bool IsPrerelease => Prerelease.Length > 0;

    public static ReleaseVersion? TryParse(string? text)
    {
        var value = (text ?? "").Trim().TrimStart('v', 'V');
        var plus = value.IndexOf('+');
        if (plus >= 0)
        {
            value = value[..plus];
        }

        var dash = value.IndexOf('-');
        var numberText = dash >= 0 ? value[..dash] : value;
        var prerelease = dash >= 0 ? value[(dash + 1)..] : "";
        if (!Version.TryParse(numberText, out var number))
        {
            return null;
        }

        // 2.0 and 2.0.0 are the same release.
        number = new Version(number.Major, number.Minor, Math.Max(0, number.Build));
        return new ReleaseVersion(number, prerelease);
    }

    /// <summary>Numbers first; then a release beats its previews; previews compare part by part (beta.10 &gt; beta.9).</summary>
    public int CompareTo(ReleaseVersion? other)
    {
        if (other is null)
        {
            return 1;
        }

        var byNumber = Number.CompareTo(other.Number);
        if (byNumber != 0 || Prerelease == other.Prerelease)
        {
            return byNumber;
        }

        if (!IsPrerelease || !other.IsPrerelease)
        {
            return IsPrerelease ? -1 : 1;
        }

        var mine = Prerelease.Split('.');
        var theirs = other.Prerelease.Split('.');
        for (var i = 0; i < Math.Min(mine.Length, theirs.Length); i++)
        {
            var a = int.TryParse(mine[i], out var x);
            var b = int.TryParse(theirs[i], out var y);
            var part = a && b ? x.CompareTo(y) : a ? -1 : b ? 1 : string.CompareOrdinal(mine[i], theirs[i]);
            if (part != 0)
            {
                return part;
            }
        }

        return mine.Length.CompareTo(theirs.Length);
    }

    public override string ToString() => IsPrerelease ? $"{Number}-{Prerelease}" : Number.ToString();
}

/// <summary>A newer release that can be installed.</summary>
public sealed record UpdateOffer(ReleaseVersion Version, string Notes, string ExeUrl, string ExpectedSha256, string? Sha256Url, string SignatureUrl);

/// <summary>
/// Updates from the GitHub releases, as v1 did and with v1's rules: the release must have a
/// HashGuard.exe asset, its SHA-256 (the asset digest or a .sha256 asset), and HashGuard.exe.sig,
/// a detached signature by the release key; a download is installed only when all three check out
/// and its Authenticode publisher (if signed) matches this build's. A preview build is also
/// offered newer previews; a release build only releases.
/// </summary>
public sealed class UpdateService(HttpClient http, ReleaseVersion current)
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };

    private static string ReleasesUrl => $"https://api.github.com/repos/{AppConstants.GitHubOwner}/{AppConstants.GitHubRepo}/releases";

    /// <summary>This build's version, from its informational version ("2.0.0-alpha.1+commit").</summary>
    public static ReleaseVersion CurrentVersion() =>
        ReleaseVersion.TryParse(typeof(UpdateService).Assembly
            .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .OfType<System.Reflection.AssemblyInformationalVersionAttribute>()
            .FirstOrDefault()?.InformationalVersion) ?? new ReleaseVersion(new Version(0, 0, 0), "");

    public static HttpClient CreateClient(ReleaseVersion current)
    {
        var http = AppHttp.Create(TimeSpan.FromSeconds(30));
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"HashGuard/{current.Number}");
        http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        return http;
    }

    /// <summary>The newest release above this build, or null when this build is up to date.</summary>
    public async Task<UpdateOffer?> CheckAsync(CancellationToken cancellationToken = default)
    {
        var releases = await GetJsonAsync<List<GitHubRelease>>(ReleasesUrl, "read the releases list", cancellationToken) ?? [];
        var newest = releases
            .Where(release => !release.Draft)
            .Select(release => (Release: release, Version: ReleaseVersion.TryParse(release.TagName)))
            .Where(item => item.Version is not null && (current.IsPrerelease || !item.Version.IsPrerelease))
            .OrderByDescending(item => item.Version)
            .FirstOrDefault();
        if (newest.Version is null || newest.Version.CompareTo(current) <= 0)
        {
            return null;
        }

        var assets = newest.Release.Assets;
        var exe = assets.FirstOrDefault(a => a.Name.Equals("HashGuard.exe", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException($"Release {newest.Version} has no HashGuard.exe.");
        var sha = assets.FirstOrDefault(a => a.Name.Equals("HashGuard.exe.sha256", StringComparison.OrdinalIgnoreCase) || a.Name.Equals("HashGuard.sha256", StringComparison.OrdinalIgnoreCase));
        var sig = assets.FirstOrDefault(a => a.Name.Equals("HashGuard.exe.sig", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException($"Release {newest.Version} has no HashGuard.exe.sig. Unsigned updates are refused.");
        var expected = UpdateVerifier.GetReleaseAssetSha256(exe);
        if (expected.Length == 0 && sha is null)
        {
            throw new InvalidOperationException($"Release {newest.Version} has no SHA-256 for HashGuard.exe.");
        }

        return new UpdateOffer(newest.Version, newest.Release.Body ?? "", exe.BrowserDownloadUrl, expected, sha?.BrowserDownloadUrl, sig.BrowserDownloadUrl);
    }

    /// <summary>
    /// Downloads the update next to this build (updates\HashGuard.exe.new) and checks its SHA-256,
    /// release signature and publisher. Returns the verified file; anything that fails is deleted.
    /// </summary>
    public async Task<string> DownloadAsync(UpdateOffer offer, string currentExe, IProgress<string>? status = null, CancellationToken cancellationToken = default)
    {
        var directory = Path.Combine(Path.GetDirectoryName(currentExe)!, "updates");
        Directory.CreateDirectory(directory);
        var download = Path.Combine(directory, "HashGuard.exe.new");
        try
        {
            var expected = offer.ExpectedSha256;
            if (expected.Length == 0 && offer.Sha256Url is { } shaUrl)
            {
                expected = UpdateVerifier.ParseSha256Text(Encoding.UTF8.GetString(await GetBytesAsync(shaUrl, "download the checksum", cancellationToken)));
            }

            if (expected.Length == 0)
            {
                throw new InvalidOperationException("The release checksum couldn't be read.");
            }

            status?.Report("Downloading…");
            using (var response = await http.GetAsync(offer.ExeUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken))
            {
                await EnsureOkAsync(response, "download HashGuard.exe", cancellationToken);
                await using var output = File.Create(download);
                await response.Content.CopyToAsync(output, cancellationToken);
            }

            status?.Report("Checking the download…");
            var actual = await FileHash.Sha256FileAsync(download, cancellationToken);
            if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("The download doesn't match the release checksum, so it wasn't installed.");
            }

            var signature = await GetBytesAsync(offer.SignatureUrl, "download HashGuard.exe.sig", cancellationToken);
            if (!UpdateVerifier.VerifyDetachedSignature(download, signature, UpdateVerifier.ReleasePublicKeyBase64, out var signatureDetail))
            {
                throw new InvalidOperationException($"The release signature didn't check out ({signatureDetail}), so it wasn't installed.");
            }

            if (!UpdateVerifier.PublisherMatchesCurrentBuild(currentExe, download, out var publisherDetail))
            {
                throw new InvalidOperationException($"{publisherDetail} The update wasn't installed.");
            }

            return download;
        }
        catch
        {
            TryDelete(download);
            throw;
        }
    }

    /// <summary>
    /// The swap script v1 used: back up the running exe, copy the update over it (retrying while it
    /// is still locked), restore the backup if that fails, then start the new build.
    /// </summary>
    public static string BuildInstallScript(string currentExe, string download, string backup) => string.Join("\r\n",
    [
        "@echo off",
        "setlocal",
        "for /l %%i in (1,1,60) do (",
        $"  copy /y \"{currentExe}\" \"{backup}\" >nul 2>nul",
        $"  copy /y \"{download}\" \"{currentExe}\" >nul 2>nul",
        "  if not errorlevel 1 goto ok",
        "  timeout /t 1 /nobreak >nul",
        " )",
        $"copy /y \"{backup}\" \"{currentExe}\" >nul 2>nul",
        "exit /b 1",
        ":ok",
        $"del /f /q \"{download}\" >nul 2>nul",
        $"del /f /q \"{backup}\" >nul 2>nul",
        $"start \"\" \"{currentExe}\"",
        "",
    ]);

    /// <summary>
    /// Starts the swap script; the caller then exits so the exe is free. When the install folder
    /// isn't writable (Program Files without administrator rights) the script runs elevated, so
    /// Windows asks. Returns false when that prompt was declined.
    /// </summary>
    public static bool StartInstall(string currentExe, string download)
    {
        var folder = Path.GetDirectoryName(currentExe)!;
        var script = Path.Combine(Path.GetDirectoryName(download)!, "HashGuard.update.cmd");
        File.WriteAllText(script, BuildInstallScript(currentExe, download, Path.Combine(folder, "HashGuard.exe.update-bak")));
        var start = CanWrite(folder)
            ? new ProcessStartInfo("cmd.exe", $"/c \"{script}\"") { CreateNoWindow = true, UseShellExecute = false, WindowStyle = ProcessWindowStyle.Hidden }
            : new ProcessStartInfo("cmd.exe", $"/c \"{script}\"") { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
        try
        {
            Process.Start(start);
            return true;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    private static bool CanWrite(string folder)
    {
        try
        {
            var probe = Path.Combine(folder, $".hashguard-write-{Guid.NewGuid():N}");
            File.WriteAllText(probe, "");
            File.Delete(probe);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private async Task<T?> GetJsonAsync<T>(string url, string action, CancellationToken cancellationToken)
    {
        using var response = await http.GetAsync(url, cancellationToken);
        await EnsureOkAsync(response, action, cancellationToken);
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        return await JsonSerializer.DeserializeAsync<T>(stream, Json, cancellationToken);
    }

    private async Task<byte[]> GetBytesAsync(string url, string action, CancellationToken cancellationToken)
    {
        using var response = await http.GetAsync(url, cancellationToken);
        await EnsureOkAsync(response, action, cancellationToken);
        return await response.Content.ReadAsByteArrayAsync(cancellationToken);
    }

    private static async Task EnsureOkAsync(HttpResponseMessage response, string action, CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var why = response.StatusCode switch
        {
            HttpStatusCode.Forbidden => "GitHub refused the request (403); its rate limit may be reached. Try again later.",
            HttpStatusCode.NotFound => "GitHub returned 404 Not Found.",
            _ => $"GitHub returned {(int)response.StatusCode} {response.StatusCode}.",
        };
        _ = await response.Content.ReadAsStringAsync(cancellationToken);
        throw new InvalidOperationException($"Couldn't {action}. {why}");
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Leftover download in updates\; harmless and replaced next time.
        }
    }
}
