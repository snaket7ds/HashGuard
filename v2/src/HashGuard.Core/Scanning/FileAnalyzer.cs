namespace HashGuard.Core;

/// <summary>The settings one analysis needs, captured when a scan starts.</summary>
public sealed record AnalyzerSettings
{
    public bool HashCacheEnabled { get; init; } = true;
    public bool DeltaScanEnabled { get; init; } = true;
    public bool UploadUnknown { get; init; }
    public IReadOnlyCollection<string> TrustedPublishers { get; init; } = [];
    public IReadOnlySet<string> IgnoredHashes { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    public IReadOnlySet<string> IgnoredPaths { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Checks one file: local facts (size, age, signer, auto-start), then the hash cache, then each
/// enabled reputation provider, then ignore rules and the risk score. The cache is tried in order:
/// an unchanged file already known clean, an unchanged file whose hash can be reused, then the hash.
/// </summary>
public sealed class FileAnalyzer(
    HashCache hashCache,
    IReadOnlyList<IReputationProvider> providers,
    AnalyzerSettings settings,
    Func<string, SignatureInfo>? readSignature = null,
    Func<string, CancellationToken, Task<string>>? hashFile = null)
{
    private readonly Func<string, SignatureInfo> readSignature = readSignature ?? SignatureReader.Read;
    private readonly Func<string, CancellationToken, Task<string>> hashFile = hashFile ?? FileHash.Sha256FileAsync;

    public async Task<ScanResult> AnalyzeAsync(
        string path,
        IReadOnlyCollection<ProcessFile> processFiles,
        bool allowVirusTotalUploads = true,
        CancellationToken cancellationToken = default)
    {
        var names = string.Join(", ", processFiles.Select(p => p.Name).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(n => n));
        var pids = string.Join(", ", processFiles.Select(p => p.Pid).OrderBy(pid => pid));
        var result = new ScanResult(path, names, pids);
        await ApplyLocalFactsAsync(result, processFiles, cancellationToken);

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (settings.HashCacheEnabled && hashCache.TryGetUnchangedFile(path, out var unchangedSha256, out var unchangedEntry))
            {
                SetHash(result, unchangedSha256);
                result.ApplyCache(unchangedEntry, "Skipped unchanged file");
                result.Status = "clean/seen";
                return Finish(result);
            }

            // Delta scan: the file is unchanged on disk but its clean entry aged out. Reuse the
            // cached hash instead of re-reading the file, and the entry itself when still reusable.
            var knownSha256 = "";
            var knownHashAvailable = settings.HashCacheEnabled && settings.DeltaScanEnabled && hashCache.TryGetKnownHash(path, out knownSha256);
            if (HashGuardLogic.ShouldReuseCachedHashForUnchangedFile(settings.DeltaScanEnabled, settings.HashCacheEnabled, knownHashAvailable, knownSha256)
                && hashCache.TryGet(knownSha256, out var knownEntry))
            {
                SetHash(result, knownSha256);
                if (HashCache.IsReusableCleanEntry(knownEntry))
                {
                    result.ApplyCache(knownEntry, "Skipped unchanged file");
                    result.Status = "clean/seen";
                    hashCache.SetFileState(result);
                    await hashCache.FlushIfDueAsync();
                    return Finish(result);
                }

                result.AppendNote("Delta scan: unchanged file, hash reused (provider re-check).");
            }
            else
            {
                SetHash(result, await hashFile(path, cancellationToken));
            }

            if (settings.HashCacheEnabled && hashCache.TryGet(result.Sha256, out var cached))
            {
                if (HashCache.IsReusableCleanEntry(cached))
                {
                    result.ApplyCache(cached);
                    result.Status = "clean/seen";
                    hashCache.SetFileState(result);
                    await hashCache.FlushIfDueAsync();
                    return Finish(result);
                }

                if (HashCache.IsReusablePendingEntry(cached))
                {
                    result.ApplyCache(cached, "Recent cached provider state");
                    result.Status = cached.Status;
                    if (providers.Any(p => p is VirusTotalProvider)
                        && HashGuardLogic.IsPendingVirusTotalUploadStatus(cached.Status)
                        && File.Exists(path))
                    {
                        result.NeedsVirusTotalUpload = true;
                    }

                    result.AppendNote("Provider lookups skipped temporarily to reduce repeat API usage.");
                    return Finish(result);
                }
            }

            var request = new LookupRequest(path, allowVirusTotalUploads, settings.UploadUnknown);
            foreach (var provider in providers)
            {
                await provider.LookupAsync(result, request, cancellationToken);
            }

            if (providers.Count == 0)
            {
                result.Status = "unknown";
                result.SetProviderResult("Local", ProviderState.Unknown, "No reputation services are enabled.");
                result.AppendNote("No reputation services are enabled.");
            }
            else if (string.IsNullOrWhiteSpace(result.Status))
            {
                result.Status = HashGuardLogic.ClassifyAggregateStatus(result.IsAlert, result.ProviderResults.Select(p => p.State).ToList());
            }

            Finish(result);
            if (settings.HashCacheEnabled && !string.IsNullOrWhiteSpace(result.Sha256))
            {
                hashCache.Set(result);
                await hashCache.FlushIfDueAsync();
            }

            return result;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            result.Status = "error";
            result.Notes = ScanResultNotes.FormatError(ex);
            return Finish(result);
        }
    }

    /// <summary>Marks the result ignored when its hash or path is on the user's ignore list.</summary>
    public static void ApplyIgnoreRules(ScanResult result, IReadOnlySet<string> ignoredHashes, IReadOnlySet<string> ignoredPaths)
    {
        var byHash = !string.IsNullOrWhiteSpace(result.Sha256) && ignoredHashes.Contains(result.Sha256);
        var byPath = !string.IsNullOrWhiteSpace(result.Path) && ignoredPaths.Contains(result.Path);
        if (!byHash && !byPath)
        {
            return;
        }

        result.StatusBeforeIgnore = result.Status;
        result.Status = "ignored";
        var note = byHash ? "File hash ignored by user." : "File path ignored by user.";
        if (string.IsNullOrWhiteSpace(result.Notes))
        {
            result.Notes = note;
        }
        else if (!HashGuardLogic.HasIgnoreNote(result.Notes))
        {
            result.AppendNote(note);
        }
    }

    private ScanResult Finish(ScanResult result)
    {
        ApplyIgnoreRules(result, settings.IgnoredHashes, settings.IgnoredPaths);
        RiskScorer.Apply(result, settings.TrustedPublishers);
        return result;
    }

    private static void SetHash(ScanResult result, string sha256)
    {
        result.Sha256 = sha256;
        result.Link = string.Format(AppConstants.VirusTotalGuiReportUrl, sha256);
    }

    private async Task ApplyLocalFactsAsync(ScanResult result, IReadOnlyCollection<ProcessFile> processFiles, CancellationToken cancellationToken)
    {
        // Persistence entries arrive as pseudo-processes with pid 0 and a "Source: detail" name.
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
            // Local metadata is best effort and must not block reputation checks.
        }

        // Signature and chain checks touch certificate stores; keep them off the caller's thread.
        var signature = await Task.Run(() => readSignature(result.Path), cancellationToken);
        result.SignatureSummary = signature.Summary;
        result.SignaturePublisher = signature.Publisher;
    }
}
