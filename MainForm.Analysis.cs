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
    private async Task<ScanResult> ScanPathAsync(
        HttpClient http,
        string path,
        List<ProcessFile> processFiles,
        CancellationToken cancellationToken = default,
        bool allowVirusTotalUploads = true)
    {
        var names = string.Join(", ", processFiles.Select(p => p.Name).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(n => n));
        var pids = string.Join(", ", processFiles.Select(p => p.Pid).OrderBy(pid => pid));
        var result = new ScanResult(path, names, pids);
        await ApplyLocalFileIntelligenceAsync(result, processFiles, cancellationToken);
        // Capture WinForms state before any await — later continuations may be off the UI thread.
        var hashCacheEnabled = hashCacheEnabledBox.Checked;
        var metaEnabled = metaDefenderEnabledBox.Checked;
        var virusTotalEnabled = virusTotalEnabledBox.Checked;
        var mhrEnabled = mhrEnabledBox.Checked;
        var uploadUnknown = uploadUnknownBox.Checked;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (hashCacheEnabled && hashCache.TryGetUnchangedFile(path, out var cachedSha256, out var cachedEntry))
            {
                result.Sha256 = cachedSha256;
                result.Link = string.Format(AppConstants.VirusTotalGuiReportUrl, result.Sha256);
                result.ApplyCache(cachedEntry, "Skipped unchanged file");
                result.Status = "clean/seen";
                ApplyIgnoredHash(result);
                ApplyRiskAndTrust(result);
                return result;
            }

            // Delta scan: the file is unchanged on disk (size + last-write time) but the clean
            // provider entry has aged out. Reuse the cached hash so the file is not re-read, and
            // reuse the entry when it is still provider-reusable. Otherwise re-query providers
            // with the known hash instead of re-hashing the file.
            var knownHashSha256 = "";
            var knownHashAvailable = hashCacheEnabled
                && appSettings.DeltaScanEnabled
                && hashCache.TryGetKnownHash(path, out knownHashSha256);
            if (HashGuardLogic.ShouldReuseCachedHashForUnchangedFile(
                    appSettings.DeltaScanEnabled,
                    hashCacheEnabled,
                    knownHashAvailable,
                    knownHashSha256)
                && hashCache.TryGet(knownHashSha256, out var knownEntry))
            {
                var knownSha256 = knownHashSha256;
                result.Sha256 = knownSha256;
                result.Link = string.Format(AppConstants.VirusTotalGuiReportUrl, result.Sha256);
                if (HashCache.IsReusableCleanEntry(knownEntry))
                {
                    result.ApplyCache(knownEntry, "Skipped unchanged file");
                    result.Status = "clean/seen";
                    hashCache.SetFileState(result);
                    await hashCache.FlushIfDueAsync();
                    ApplyIgnoredHash(result);
                    ApplyRiskAndTrust(result);
                    return result;
                }

                AppendResultNote(result, "Delta scan: unchanged file, hash reused (provider re-check).");
            }

            result.Sha256 = await FileHash.Sha256FileAsync(path, cancellationToken);
            result.Link = string.Format(AppConstants.VirusTotalGuiReportUrl, result.Sha256);
            if (hashCacheEnabled && hashCache.TryGet(result.Sha256, out var cached))
            {
                if (HashCache.IsReusableCleanEntry(cached))
                {
                    result.ApplyCache(cached);
                    result.Status = "clean/seen";
                    hashCache.SetFileState(result);
                    await hashCache.FlushIfDueAsync();
                    ApplyIgnoredHash(result);
                    ApplyRiskAndTrust(result);
                    return result;
                }

                if (HashCache.IsReusablePendingEntry(cached))
                {
                    result.ApplyCache(cached, "Recent cached provider state");
                    result.Status = cached.Status;
                    if (virusTotalEnabled
                        && HashGuardLogic.IsPendingVirusTotalUploadStatus(cached.Status)
                        && File.Exists(path))
                    {
                        result.NeedsVirusTotalUpload = true;
                    }

                    AppendResultNote(result, "Provider lookups skipped temporarily to reduce repeat API usage.");
                    ApplyIgnoredHash(result);
                    ApplyRiskAndTrust(result);
                    return result;
                }
            }

            var checkedAnyService = false;
            if (metaEnabled)
            {
                checkedAnyService = true;
                await ApplyMetaDefenderReportAsync(result, cancellationToken);
            }

            if (virusTotalEnabled)
            {
                checkedAnyService = true;
                await ApplyVirusTotalReportAsync(http, result, path, allowVirusTotalUploads, uploadUnknown, cancellationToken);
            }

            if (mhrEnabled)
            {
                checkedAnyService = true;
                await ApplyCymruReputationAsync(result, cancellationToken);
            }

            if (!checkedAnyService)
            {
                result.Status = "unknown";
                AddProviderResult(result, "Local", ProviderState.Unknown, "No reputation services are enabled.");
                AppendResultNote(result, "No reputation services are enabled.");
            }
            else if (string.IsNullOrWhiteSpace(result.Status))
            {
                result.Status = HashGuardLogic.ClassifyAggregateStatus(
                    result.IsAlert,
                    result.ProviderResults.Select(provider => provider.State).ToList());
            }

            ApplyIgnoredHash(result);
            ApplyRiskAndTrust(result);
            await SaveResultToCacheAsync(result);
            return result;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            result.Status = "error";
            result.Notes = FormatScanError(ex);
            ApplyIgnoredHash(result);
            ApplyRiskAndTrust(result);
            return result;
        }
    }

    private static async Task ApplyLocalFileIntelligenceAsync(
        ScanResult result,
        List<ProcessFile> processFiles,
        CancellationToken cancellationToken)
    {
        result.PersistenceSources = processFiles
            .Where(file => file.Pid == 0 && file.Name.Contains(':', StringComparison.Ordinal))
            .Select(file => file.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(source => source, StringComparer.OrdinalIgnoreCase)
            .ToList();

        try
        {
            var info = new FileInfo(result.Path);
            if (info.Exists)
            {
                result.FileSizeBytes = info.Length;
                result.LastWriteTimeUtc = info.LastWriteTimeUtc;
                result.FileAgeDays = Math.Max(0, (DateTime.UtcNow - info.LastWriteTimeUtc).TotalDays);
            }
        }
        catch
        {
            // Local metadata is best-effort and should not block reputation checks.
        }

        // Signature/chain checks touch certificate stores and used to run on the UI thread for
        // every file. Run them on the pool so the scan loop stays responsive.
        var signature = await Task.Run(() => GetSignatureInfo(result.Path), cancellationToken).ConfigureAwait(true);
        result.SignatureSummary = signature.Summary;
        result.SignaturePublisher = signature.Publisher;
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, SignatureInfo> SignatureCache =
        new(StringComparer.OrdinalIgnoreCase);

    private static SignatureInfo GetSignatureInfo(string path)
    {
        string cacheKey;
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                return new SignatureInfo("Unsigned or signature unavailable", "");
            }

            cacheKey = $"{path}|{info.Length}|{info.LastWriteTimeUtc.Ticks}";
        }
        catch
        {
            return new SignatureInfo("Unsigned or signature unavailable", "");
        }

        if (SignatureCache.TryGetValue(cacheKey, out var cached))
        {
            return cached;
        }

        var signature = ReadSignatureInfo(path);
        if (SignatureCache.Count > 20000)
        {
            SignatureCache.Clear();
        }

        SignatureCache[cacheKey] = signature;
        return signature;
    }

    private static SignatureInfo ReadSignatureInfo(string path)
    {
        try
        {
            var certificate = X509Certificate.CreateFromSignedFile(path);
            using var cert2 = new X509Certificate2(certificate);
            var publisher = cert2.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            var expired = DateTime.Now < cert2.NotBefore || DateTime.Now > cert2.NotAfter;
            using var chain = new X509Chain();
            // Offline: online CRL/OCSP lookups added a network round trip (up to seconds) per
            // file. Offline uses the local cache and is sufficient for the risk heuristic.
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(1);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            var chainValid = chain.Build(cert2);
            var chainStatus = chainValid
                ? "chain valid"
                : string.Join(", ", chain.ChainStatus.Select(status => status.Status.ToString()).Distinct());
            var summary = expired
                ? $"Signed by {publisher}; certificate outside validity period; {chainStatus}"
                : $"Signed by {publisher}; {chainStatus}";
            return new SignatureInfo(summary, publisher);
        }
        catch
        {
            return new SignatureInfo("Unsigned or signature unavailable", "");
        }
    }

    private void ApplyRiskAndTrust(ScanResult result)
    {
        var score = 0;
        var reasons = new List<string>();
        var trust = new List<string>();

        if (result.Malicious > 0)
        {
            score += 80;
            reasons.Add($"{result.Malicious} malicious detection(s)");
        }

        if (result.Suspicious > 0)
        {
            score += Math.Min(50, result.Suspicious * 15);
            reasons.Add($"{result.Suspicious} suspicious detection(s)");
        }

        if (string.Equals(result.Status, "unknown", StringComparison.OrdinalIgnoreCase)
            || string.Equals(result.Status, "uploaded", StringComparison.OrdinalIgnoreCase))
        {
            score += 20;
            reasons.Add("hash not known clean");
        }

        if (string.Equals(result.Status, "error", StringComparison.OrdinalIgnoreCase))
        {
            score += 25;
            reasons.Add("scan error needs review");
        }

        if (IsRiskyUserWritablePath(result.Path))
        {
            score += 25;
            reasons.Add("user-writable/risky path");
        }

        if (result.PersistenceSources.Count > 0)
        {
            score += 25;
            reasons.Add("starts automatically");
            trust.Add(string.Join("; ", result.PersistenceSources));
        }

        var trustedPublisher = IsTrustedPublisher(result.SignaturePublisher);
        if (result.SignatureSummary.StartsWith("Unsigned", StringComparison.OrdinalIgnoreCase))
        {
            score += 15;
            reasons.Add("unsigned");
        }
        else if (trustedPublisher)
        {
            score = Math.Max(0, score - 20);
            trust.Add($"trusted publisher: {result.SignaturePublisher}");
        }
        else if (!string.IsNullOrWhiteSpace(result.SignatureSummary))
        {
            trust.Add(result.SignatureSummary);
        }

        if (result.FileAgeDays is >= 0 and < 7)
        {
            score += 10;
            reasons.Add("recently modified");
        }

        if (IsWindowsOrProgramFilesPath(result.Path) && !result.SignatureSummary.StartsWith("Unsigned", StringComparison.OrdinalIgnoreCase))
        {
            score = Math.Max(0, score - 15);
            trust.Add("trusted install location");
        }

        result.RiskScore = Math.Clamp(score, 0, 100);
        result.RiskLevel = result.RiskScore >= 70 ? "High"
            : result.RiskScore >= 40 ? "Medium"
            : result.RiskScore >= 15 ? "Low"
            : "Low";
        result.TrustSummary = trust.Count == 0 ? result.SignatureSummary : string.Join("; ", trust.Distinct(StringComparer.OrdinalIgnoreCase));

        if (reasons.Count > 0)
        {
            AppendResultNote(result, $"Risk: {string.Join(", ", reasons.Distinct(StringComparer.OrdinalIgnoreCase))}.");
        }
    }

    private bool IsTrustedPublisher(string publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher))
        {
            return false;
        }

        return appSettings.TrustedPublishers.Any(trusted =>
            publisher.Contains(trusted, StringComparison.OrdinalIgnoreCase)
            || trusted.Contains(publisher, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsRiskyUserWritablePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var lower = path.ToLowerInvariant();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).ToLowerInvariant();
        return lower.Contains(@"\appdata\", StringComparison.Ordinal)
            || lower.Contains(@"\temp\", StringComparison.Ordinal)
            || lower.Contains(@"\downloads\", StringComparison.Ordinal)
            || (!string.IsNullOrWhiteSpace(userProfile) && lower.StartsWith(userProfile, StringComparison.OrdinalIgnoreCase) && !IsWindowsOrProgramFilesPath(path));
    }

    private static bool IsWindowsOrProgramFilesPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var fullPath = path.ToLowerInvariant();
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).ToLowerInvariant();
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).ToLowerInvariant();
        return (!string.IsNullOrWhiteSpace(windows) && fullPath.StartsWith(windows, StringComparison.OrdinalIgnoreCase))
            || (!string.IsNullOrWhiteSpace(programFiles) && fullPath.StartsWith(programFiles, StringComparison.OrdinalIgnoreCase))
            || (!string.IsNullOrWhiteSpace(programFilesX86) && fullPath.StartsWith(programFilesX86, StringComparison.OrdinalIgnoreCase));
    }

    private static string FormatScanError(Exception ex)
    {
        if (ex is HttpRequestException { StatusCode: HttpStatusCode.Unauthorized })
        {
            return "A reputation service returned 401 Unauthorized. Verify the saved API key in Settings.";
        }

        return ex.Message;
    }
}
