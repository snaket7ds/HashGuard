using System.Text.Json;
using System.Xml.Linq;
using HashGuardScanner;

var tests = new (string Name, Action Test)[]
{
    ("extracts quoted executable path", () =>
    {
        var path = HashGuardLogic.TryExtractExecutablePath("\"C:\\Program Files\\HashGuard\\HashGuard.exe\" --minimized");
        AssertEqual("C:\\Program Files\\HashGuard\\HashGuard.exe", path);
    }),
    ("extracts unquoted executable path with arguments", () =>
    {
        var path = HashGuardLogic.TryExtractExecutablePath("C:\\Tools\\thing.exe /quiet");
        AssertEqual("C:\\Tools\\thing.exe", path);
    }),
    ("parses quoted csv fields", () =>
    {
        var values = HashGuardLogic.ParseCsvLine("\"a,b\",\"c\"\"d\",e");
        AssertEqual(3, values.Count);
        AssertEqual("a,b", values[0]);
        AssertEqual("c\"d", values[1]);
        AssertEqual("e", values[2]);
    }),
    ("extracts matching changelog section", () =>
    {
        var changelog = "# Changelog\n\n## v1.0.2\n\n- two\n\n## v1.0.1\n\n- one\n";
        var section = HashGuardLogic.ExtractChangelogSection(changelog, "v1.0.2");
        AssertEqual("## v1.0.2\n\n- two\n".Replace("\n", Environment.NewLine, StringComparison.Ordinal), section);
    }),
    ("reuses unknown cache for short window", () =>
    {
        var now = DateTimeOffset.Parse("2026-06-04T12:00:00Z");
        AssertTrue(HashGuardLogic.CanReuseProviderCache("unknown", false, now.AddHours(-2), now));
        AssertFalse(HashGuardLogic.CanReuseProviderCache("unknown", false, now.AddHours(-13), now));
        AssertFalse(HashGuardLogic.CanReuseProviderCache("unknown", false, now.AddHours(-2), now, uploadUnknownEnabled: true));
        AssertFalse(HashGuardLogic.CanReuseProviderCache("uploaded", false, now.AddHours(-1), now, uploadUnknownEnabled: true));
    }),
    ("detects virus total not-found and analysis id", () =>
    {
        AssertTrue(HashGuardLogic.IsVirusTotalNotFound(404, null));
        AssertTrue(HashGuardLogic.IsVirusTotalNotFound(400, """{"error":{"code":"NotFoundError"}}"""));
        AssertFalse(HashGuardLogic.IsVirusTotalNotFound(401, """{"error":{"code":"AuthenticationRequiredError"}}"""));
        AssertTrue(HashGuardLogic.IsVirusTotalAlreadyExists(409, null));
        AssertEqual("abc123", HashGuardLogic.TryReadVirusTotalAnalysisId("""{"data":{"type":"analysis","id":"abc123"}}"""));
        AssertTrue(HashGuardLogic.TryReadVirusTotalAnalysisId("not-json") is null);
    }),
    ("reuses deferred cache for shorter window", () =>
    {
        var now = DateTimeOffset.Parse("2026-06-04T12:00:00Z");
        AssertTrue(HashGuardLogic.CanReuseProviderCache("clean", true, now.AddMinutes(-20), now));
        AssertFalse(HashGuardLogic.CanReuseProviderCache("clean", true, now.AddMinutes(-45), now));
    }),
    ("matches activity filters", () =>
    {
        AssertTrue(HashGuardLogic.MatchesActivityFilter(ActivityFilter.ActionNeeded, "detected", "High 90", 1, 0));
        AssertTrue(HashGuardLogic.MatchesActivityFilter(ActivityFilter.Unknown, "unknown", "Medium 45", 0, 0));
        AssertTrue(HashGuardLogic.MatchesActivityFilter(ActivityFilter.Clean, "clean/seen", "Low 5", 0, 0));
        AssertTrue(HashGuardLogic.MatchesActivityFilter(ActivityFilter.Errors, "error", "Medium 35", 0, 0));
        AssertFalse(HashGuardLogic.MatchesActivityFilter(ActivityFilter.ActionNeeded, "clean", "Low 5", 0, 0));
    }),
    ("ignored detections are handled, not action needed", () =>
    {
        AssertFalse(HashGuardLogic.MatchesActivityFilter(ActivityFilter.ActionNeeded, "ignored", "High 90", 3, 1));
        AssertTrue(HashGuardLogic.MatchesActivityFilter(ActivityFilter.Clean, "ignored", "High 90", 3, 1));
        AssertFalse(HashGuardLogic.NeedsAction("ignored", "High 90", 3, 1));
        AssertTrue(HashGuardLogic.IsIgnoredStatus("ignored"));
    }),
    ("needs action for high risk without detections", () =>
    {
        AssertTrue(HashGuardLogic.NeedsAction("clean", "High 80", 0, 0));
        AssertFalse(HashGuardLogic.NeedsAction("clean", "Low 5", 0, 0));
    }),
    ("needs action when virus total upload is pending", () =>
    {
        AssertTrue(HashGuardLogic.NeedsAction("unknown", "Low 20", 0, 0, needsVirusTotalUpload: true));
        AssertFalse(HashGuardLogic.NeedsAction("unknown", "Low 20", 0, 0, needsVirusTotalUpload: false));
        AssertFalse(HashGuardLogic.NeedsAction("ignored", "Low 20", 0, 0, needsVirusTotalUpload: true));
    }),
    ("quarantine notes are detected", () =>
    {
        AssertTrue(HashGuardLogic.NoteIndicatesQuarantined("Quarantined to C:\\q\\file.bin"));
        AssertTrue(HashGuardLogic.NoteIndicatesQuarantined("File Quarantined"));
        AssertFalse(HashGuardLogic.NoteIndicatesQuarantined("No issues"));
        AssertFalse(HashGuardLogic.NoteIndicatesQuarantined(null));
    }),
    ("quarantine manager lists restorable files and matches search", () =>
    {
        var entries = new[]
        {
            new QuarantineEntry { OriginalPath = @"C:\Temp\bad.exe", QuarantinePath = @"C:\q\bad.exe.quarantine", Sha256 = "abc123" },
            new QuarantineEntry { OriginalPath = @"C:\Temp\gone.dll", QuarantinePath = @"C:\q\missing.quarantine", Sha256 = "def456" },
        };
        bool Exists(string path) => path.EndsWith("bad.exe.quarantine", StringComparison.OrdinalIgnoreCase);
        AssertEqual(1, HashGuardLogic.CountRestorableQuarantineEntries(entries, Exists));
        AssertEqual("bad.exe", HashGuardLogic.QuarantineDisplayName(entries[0]));
        AssertTrue(HashGuardLogic.QuarantineEntryMatchesFilter(entries[0], "bad"));
        AssertTrue(HashGuardLogic.QuarantineEntryMatchesFilter(entries[0], "ABC"));
        AssertFalse(HashGuardLogic.QuarantineEntryMatchesFilter(entries[0], "gone"));
    }),
    ("can ignore by hash or path", () =>
    {
        AssertTrue(HashGuardLogic.CanIgnoreTarget("abc", null, out var kind, out var value));
        AssertEqual("hash", kind);
        AssertEqual("abc", value);
        AssertTrue(HashGuardLogic.CanIgnoreTarget(null, "C:\\x.exe", out kind, out value));
        AssertEqual("path", kind);
        AssertEqual("C:\\x.exe", value);
        AssertFalse(HashGuardLogic.CanIgnoreTarget(" ", "  ", out _, out _));
    }),
    ("risk buckets", () =>
    {
        AssertEqual("High", HashGuardLogic.RiskBucket(70));
        AssertEqual("Medium", HashGuardLogic.RiskBucket(40));
        AssertEqual("Low", HashGuardLogic.RiskBucket(10));
    }),
    ("scan gate is non-reentrant", () =>
    {
        var gate = new ScanGate();
        AssertTrue(gate.TryEnter());
        AssertTrue(gate.IsBusy);
        AssertFalse(gate.TryEnter());
        gate.Exit();
        AssertFalse(gate.IsBusy);
        AssertTrue(gate.TryEnter());
        gate.Exit();
    }),
    ("ignore note helpers strip and detect", () =>
    {
        AssertTrue(HashGuardLogic.HasIgnoreNote("File hash ignored by user."));
        AssertTrue(HashGuardLogic.HasIgnoreNote("x; Detection ignored by user."));
        AssertEqual("Risk: unsigned", HashGuardLogic.RemoveIgnoreNote("Risk: unsigned; File hash ignored by user."));
    }),
    ("tray alert signature is stable and ordered", () =>
    {
        var a = HashGuardLogic.BuildTrayAlertSignature([("bbb", @"C:\b.exe"), ("aaa", @"C:\a.exe")]);
        var b = HashGuardLogic.BuildTrayAlertSignature([("aaa", @"C:\a.exe"), ("bbb", @"C:\b.exe")]);
        AssertEqual(a, b);
        AssertTrue(HashGuardLogic.ShouldShowTrayAlert(true, "", a));
        AssertFalse(HashGuardLogic.ShouldShowTrayAlert(true, a, a));
        AssertTrue(HashGuardLogic.ShouldShowTrayAlert(false, a, a));
    }),
    ("publisher match for ignore is bidirectional contains", () =>
    {
        AssertTrue(HashGuardLogic.PublisherMatchesForIgnore("Microsoft Corporation", " microsoft   corporation "));
        AssertFalse(HashGuardLogic.PublisherMatchesForIgnore("Microsoft Corporation", "Microsoft"));
        AssertFalse(HashGuardLogic.PublisherMatchesForIgnore("Microsoft", "Microsoft Corporation"));
        AssertFalse(HashGuardLogic.PublisherMatchesForIgnore("Adobe Inc.", "Microsoft"));
    }),
    ("telemetry scan payload is aggregate-only", () =>
    {
        var payload = HashGuardLogic.BuildScanCompleteTelemetry(10, 2, 1, 3, 0);
        AssertEqual(10, payload["items_scanned"]);
        AssertEqual(2, payload["action_needed"]);
        var json = JsonSerializer.Serialize(TelemetryClient.BuildPayload("scan_complete", "install123456", "1.0.51", "Windows", payload));
        AssertTrue(HashGuardLogic.TelemetryPayloadLooksSafe(json));
        AssertTrue(TelemetryClient.IsSafeEventType("app_ping"));
        AssertFalse(TelemetryClient.IsSafeEventType("file_path"));
    }),
    ("virus total file report stats map correctly", () =>
    {
        using var doc = JsonDocument.Parse("""
            {"data":{"attributes":{"last_analysis_stats":{"malicious":2,"suspicious":1,"harmless":50,"undetected":10}}}}
            """);
        var result = new ScanResult(@"C:\a.exe", "a", "1");
        ProviderStats.ApplyVirusTotalFileReport(result, doc.RootElement);
        AssertEqual(2, result.Malicious);
        AssertEqual(1, result.Suspicious);
        AssertEqual("detected", result.Status);
    }),
    ("virus total analysis completed clean maps correctly", () =>
    {
        using var doc = JsonDocument.Parse("""
            {"data":{"attributes":{"status":"completed","stats":{"malicious":0,"suspicious":0,"harmless":40,"undetected":5}}}}
            """);
        var result = new ScanResult(@"C:\a.exe", "a", "1");
        ProviderStats.ApplyVirusTotalAnalysis(result, doc.RootElement);
        AssertEqual(0, result.Malicious);
        AssertEqual("clean", result.Status);
    }),
    ("metadefender clean and infected mapping", () =>
    {
        using var clean = JsonDocument.Parse("""
            {"scan_results":{"total_detected_avs":0,"total_avs":30,"scan_all_result_a":"No Threat Detected"}}
            """);
        var cleanResult = new ScanResult(@"C:\a.exe", "a", "1") { Status = "unknown" };
        var cleanMap = ProviderStats.ApplyMetaDefender(cleanResult, clean.RootElement);
        AssertEqual(ProviderState.Clean, cleanMap.State);
        AssertEqual("clean", cleanResult.Status);

        using var bad = JsonDocument.Parse("""
            {"scan_results":{"total_detected_avs":3,"total_avs":30,"scan_all_result_a":"Infected","threat_name":"EICAR"}}
            """);
        var badResult = new ScanResult(@"C:\b.exe", "b", "2");
        var badMap = ProviderStats.ApplyMetaDefender(badResult, bad.RootElement);
        AssertEqual(ProviderState.Detected, badMap.State);
        AssertEqual("detected", badResult.Status);
    }),
    ("cymru txt and query name parse", () =>
    {
        var rep = ProviderStats.ParseCymruTxt("\"1717200000 85\"");
        AssertTrue(rep is not null);
        AssertEqual(85, rep!.DetectionPercent);
        var name = ProviderStats.BuildCymruQueryName(new string('a', 32) + new string('b', 32));
        AssertTrue(name.EndsWith(".hash.cymru.com", StringComparison.Ordinal));
        AssertTrue(name.Contains('.', StringComparison.Ordinal));
    }),
    ("scan path security rejects unsafe inputs", () =>
    {
        AssertTrue(ScanPathSecurity.TryNormalizeScanPath(null, out var reason) is null);
        AssertEqual("empty path", reason);
        AssertTrue(ScanPathSecurity.TryNormalizeScanPath(new string('x', 600), out reason) is null);
        AssertEqual("path length", reason);
        AssertTrue(ScanPathSecurity.TryNormalizeScanPath(@"\\.\\C:", out reason) is null);
        AssertEqual("device path", reason);
    }),
    ("update verifier parses sha256 text and digest", () =>
    {
        AssertEqual("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            UpdateVerifier.ParseSha256Text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  HashGuard.exe"));
        var asset = new GitHubAsset { Digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" };
        AssertEqual("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", UpdateVerifier.GetReleaseAssetSha256(asset));
    }),
    ("release signature verifies only the signed file and the right key", () =>
    {
        var dir = Path.Combine(Path.GetTempPath(), "hashguard-sig-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var exe = Path.Combine(dir, "HashGuard.exe");
            File.WriteAllBytes(exe, System.Text.Encoding.UTF8.GetBytes("genuine release bytes"));
            using var signer = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            var publicKey = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo());
            var hash = System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(exe));
            var signature = signer.SignHash(hash, System.Security.Cryptography.DSASignatureFormat.Rfc3279DerSequence);

            AssertTrue(UpdateVerifier.VerifyDetachedSignature(exe, signature, publicKey, out _));

            File.WriteAllBytes(exe, System.Text.Encoding.UTF8.GetBytes("tampered release bytes"));
            AssertFalse(UpdateVerifier.VerifyDetachedSignature(exe, signature, publicKey, out _));

            File.WriteAllBytes(exe, System.Text.Encoding.UTF8.GetBytes("genuine release bytes"));
            using var other = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            var otherKey = Convert.ToBase64String(other.ExportSubjectPublicKeyInfo());
            AssertFalse(UpdateVerifier.VerifyDetachedSignature(exe, signature, otherKey, out _));

            AssertFalse(UpdateVerifier.VerifyDetachedSignature(exe, signature, "", out var noKeyDetail));
            AssertTrue(noKeyDetail.Contains("No release signing key"));
            AssertFalse(UpdateVerifier.VerifyDetachedSignature(exe, Array.Empty<byte>(), publicKey, out _));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }),
    ("config path is next to the app (not LocalAppData)", () =>
    {
        var config = Path.GetFullPath(AppPaths.GetConfigDirectory());
        var baseDir = Path.GetFullPath(AppContext.BaseDirectory);
        AssertTrue(config.StartsWith(baseDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), StringComparison.OrdinalIgnoreCase));
        AssertTrue(config.EndsWith($"{Path.DirectorySeparatorChar}config", StringComparison.OrdinalIgnoreCase)
            || config.EndsWith("/config", StringComparison.OrdinalIgnoreCase)
            || config.EndsWith("\\config", StringComparison.OrdinalIgnoreCase));
    }),
    ("legacy LocalAppData bug folder is merged then removed", () =>
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localAppData))
        {
            return;
        }

        var legacyRoot = Path.Combine(localAppData, "HashGuard");
        var legacyConfig = Path.Combine(legacyRoot, "config");
        Directory.CreateDirectory(legacyConfig);
        var uniqueName = $"migrate-test-{Guid.NewGuid():N}.json";
        var marker = Path.Combine(legacyConfig, uniqueName);
        File.WriteAllText(marker, """{"ok":true}""");

        var primary = AppPaths.GetConfigDirectory(); // merges + deletes leftover LocalAppData\HashGuard
        var migrated = Path.Combine(primary, uniqueName);
        AssertTrue(File.Exists(migrated));
        AssertFalse(Directory.Exists(legacyRoot));
        try { File.Delete(migrated); } catch { /* cleanup */ }
    }),
    ("hash cache reusable clean entry respects age", () =>
    {
        var fresh = new CacheEntry
        {
            Status = "clean",
            CheckedAtUtc = DateTimeOffset.UtcNow.AddHours(-1),
        };
        AssertTrue(HashCache.IsReusableCleanEntry(fresh));
        var stale = new CacheEntry
        {
            Status = "clean",
            CheckedAtUtc = DateTimeOffset.UtcNow.AddDays(-10),
        };
        AssertFalse(HashCache.IsReusableCleanEntry(stale));
        var pending = new CacheEntry
        {
            Status = "unknown",
            CheckedAtUtc = DateTimeOffset.UtcNow.AddHours(-2),
        };
        AssertTrue(HashCache.IsReusablePendingEntry(pending));
    }),
    ("hash cache stays warm and skips redundant log import", () =>
    {
        var cache = new HashCache();
        AssertFalse(cache.IsLoaded);
        cache.EnsureLoadedAsync().GetAwaiter().GetResult();
        AssertTrue(cache.IsLoaded);
        var countAfterLoad = cache.Count;
        // Second ensure must not clear in-memory entries.
        cache.EnsureLoadedAsync().GetAwaiter().GetResult();
        AssertEqual(countAfterLoad, cache.Count);

        var emptyDir = Path.Combine(Path.GetTempPath(), "hashguard-empty-logs-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(emptyDir);
        try
        {
            cache.ImportScanLogsIfChanged([emptyDir]);
            cache.ImportScanLogsIfChanged([emptyDir]); // no-op when signature unchanged
            AssertTrue(cache.IsLoaded);
        }
        finally
        {
            try { Directory.Delete(emptyDir, recursive: true); } catch { /* ignore */ }
        }
    }),
    ("scan report export includes rows", () =>
    {
        var results = new[]
        {
            new ScanResult(@"C:\a.exe", "a", "1")
            {
                Status = "clean",
                Sha256 = new string('a', 64),
                RiskScore = 5,
                RiskLevel = "Low",
            },
        };
        var csv = ScanReportExport.ToCsv(results);
        AssertTrue(csv.Contains("sha256", StringComparison.OrdinalIgnoreCase));
        AssertTrue(csv.Contains("C:\\a.exe", StringComparison.Ordinal));
        var html = ScanReportExport.ToHtml(results, "1.0.51", DateTimeOffset.UtcNow);
        AssertTrue(html.Contains("HashGuard Scan Report", StringComparison.Ordinal));
    }),
    ("delta scan reuses the cached hash only when enabled and unchanged", () =>
    {
        var sha = new string('a', 64);
        AssertTrue(HashGuardLogic.ShouldReuseCachedHashForUnchangedFile(true, true, true, sha));
        AssertFalse(HashGuardLogic.ShouldReuseCachedHashForUnchangedFile(false, true, true, sha));
        AssertFalse(HashGuardLogic.ShouldReuseCachedHashForUnchangedFile(true, false, true, sha));
        AssertFalse(HashGuardLogic.ShouldReuseCachedHashForUnchangedFile(true, true, false, sha));
        AssertFalse(HashGuardLogic.ShouldReuseCachedHashForUnchangedFile(true, true, true, ""));
        AssertFalse(HashGuardLogic.ShouldReuseCachedHashForUnchangedFile(true, true, true, null));
    }),
    ("aggregate status surfaces provider errors instead of clean", () =>
    {
        AssertEqual("detected", HashGuardLogic.ClassifyAggregateStatus(true, [ProviderState.Clean]));
        AssertEqual("clean", HashGuardLogic.ClassifyAggregateStatus(false, [ProviderState.Clean, ProviderState.Error]));
        AssertEqual("error", HashGuardLogic.ClassifyAggregateStatus(false, [ProviderState.Error]));
        AssertEqual("error", HashGuardLogic.ClassifyAggregateStatus(false, [ProviderState.Error, ProviderState.NotChecked]));
        AssertEqual("unknown", HashGuardLogic.ClassifyAggregateStatus(false, [ProviderState.Deferred]));
        AssertEqual("unknown", HashGuardLogic.ClassifyAggregateStatus(false, []));
        AssertEqual("detected", HashGuardLogic.ClassifyAggregateStatus(false, [ProviderState.Detected]));
    }),
    ("hash cache flush is due after 25 mutations or 5 seconds", () =>
    {
        var saved = DateTimeOffset.Parse("2026-08-12T12:00:00Z");
        AssertFalse(HashCache.IsFlushDue(false, 25, saved, saved));
        AssertFalse(HashCache.IsFlushDue(true, 24, saved, saved.AddSeconds(4)));
        AssertTrue(HashCache.IsFlushDue(true, 25, saved, saved.AddSeconds(1)));
        AssertTrue(HashCache.IsFlushDue(true, 1, saved, saved.AddSeconds(5)));
    }),
    ("scan snapshot marks new paths and hashes", () =>
    {
        var previous = new ScanSnapshot
        {
            Paths = [@"C:\old.exe"],
            Sha256Hashes = [new string('1', 64)],
        };
        var results = new List<ScanResult>
        {
            new(@"C:\old.exe", "old", "1") { Sha256 = new string('1', 64) },
            new(@"C:\new.exe", "new", "2") { Sha256 = new string('2', 64) },
        };
        ScanSnapshotStore.MarkNewSinceLastScan(results, previous);
        AssertFalse(results[0].IsNewSinceLastScan);
        AssertTrue(results[1].IsNewSinceLastScan);
    }),
    ("apply ignored status is handled by needs-action", () =>
    {
        var result = new ScanResult(@"C:\x.exe", "x", "1")
        {
            Status = "detected",
            Malicious = 2,
            StatusBeforeIgnore = "detected",
        };
        result.Status = "ignored";
        AssertFalse(HashGuardLogic.NeedsAction(result.Status, "High 90", result.Malicious, result.Suspicious));
        AssertTrue(HashGuardLogic.IsIgnoredStatus(result.Status));
    }),
    ("ordered concurrency keeps input order and caps tasks in flight", () =>
    {
        var items = Enumerable.Range(0, 10).ToList();
        var inFlight = 0;
        var peak = 0;
        var seen = new List<int>();
        OrderedConcurrency.ForEachAsync(
            items,
            3,
            async item =>
            {
                var now = Interlocked.Increment(ref inFlight);
                lock (seen) { peak = Math.Max(peak, now); }
                // Later items finish first, so ordering cannot come from completion order.
                await Task.Delay(30 - item * 3);
                Interlocked.Decrement(ref inFlight);
                return item * 10;
            },
            (index, result) =>
            {
                AssertEqual(index * 10, result);
                seen.Add(result);
                return Task.CompletedTask;
            }).GetAwaiter().GetResult();
        AssertEqual(10, seen.Count);
        AssertTrue(peak <= 3);
        AssertTrue(peak >= 2);
    }),
    ("ordered concurrency waits for running tasks before rethrowing", () =>
    {
        var finished = 0;
        var threw = false;
        try
        {
            OrderedConcurrency.ForEachAsync(
                new[] { 0, 1, 2 },
                3,
                async item =>
                {
                    if (item == 0)
                    {
                        throw new InvalidOperationException("boom");
                    }

                    await Task.Delay(50);
                    Interlocked.Increment(ref finished);
                    return item;
                },
                (_, _) => Task.CompletedTask).GetAwaiter().GetResult();
        }
        catch (InvalidOperationException)
        {
            threw = true;
        }

        AssertTrue(threw);
        AssertEqual(2, finished);
    }),
    ("scan request queue drops duplicates, quick repeats, and overflow", () =>
    {
        var queue = new ScanRequestQueue();
        var now = DateTimeOffset.Parse("2026-10-12T12:00:00Z");
        AssertEqual(ScanRequestOutcome.Queued, queue.TryEnqueue(@"C:\a.exe", now));
        AssertEqual(ScanRequestOutcome.Duplicate, queue.TryEnqueue(@"c:\A.EXE", now));
        AssertEqual(1, queue.DequeueAll().Count);
        AssertEqual(ScanRequestOutcome.Duplicate, queue.TryEnqueue(@"C:\a.exe", now.AddSeconds(2)));
        AssertEqual(ScanRequestOutcome.Queued, queue.TryEnqueue(@"C:\a.exe", now.AddSeconds(6)));
        for (var i = 1; i < ScanRequestQueue.MaxQueued; i++)
        {
            AssertEqual(ScanRequestOutcome.Queued, queue.TryEnqueue($@"C:\f{i}.exe", now));
        }

        AssertEqual(ScanRequestOutcome.Full, queue.TryEnqueue(@"C:\one-too-many.exe", now));
        var drained = queue.DequeueAll();
        AssertEqual(ScanRequestQueue.MaxQueued, drained.Count);
        AssertEqual(@"C:\a.exe", drained[0]);
        AssertEqual(0, queue.Count);
    }),
    ("storage falls back to LocalAppData only when the app folder is read-only", () =>
    {
        var writable = AppPaths.ChooseStorageRoot(@"C:\Apps\HashGuard", @"C:\Users\u\AppData\Local", _ => true);
        AssertFalse(writable.UsingFallback);
        AssertEqual(@"C:\Apps\HashGuard", writable.Path);

        var readOnly = AppPaths.ChooseStorageRoot(@"C:\Apps\HashGuard", @"C:\Users\u\AppData\Local", _ => false);
        AssertTrue(readOnly.UsingFallback);
        AssertTrue(readOnly.Path.EndsWith(AppPaths.FallbackFolderName, StringComparison.Ordinal));
        AssertFalse(string.Equals(AppPaths.FallbackFolderName, "HashGuard", StringComparison.OrdinalIgnoreCase));

        var noProfile = AppPaths.ChooseStorageRoot(@"C:\Apps\HashGuard", "", _ => false);
        AssertFalse(noProfile.UsingFallback);
    }),
    ("fallback seeding copies settings but not the quarantine manifest", () =>
    {
        var root = Path.Combine(Path.GetTempPath(), $"hg-seed-{Guid.NewGuid():N}");
        var appConfig = Path.Combine(root, "app", "config");
        var fallbackConfig = Path.Combine(root, "fallback", "config");
        try
        {
            Directory.CreateDirectory(appConfig);
            File.WriteAllText(Path.Combine(appConfig, AppPaths.AppSettingsFileName), "{\"old\":true}");
            File.WriteAllText(Path.Combine(appConfig, AppPaths.IgnoredHashesFileName), "[]");
            File.WriteAllText(Path.Combine(appConfig, AppPaths.QuarantineManifestFileName), "[]");
            Directory.CreateDirectory(fallbackConfig);
            File.WriteAllText(Path.Combine(fallbackConfig, AppPaths.IgnoredHashesFileName), "[\"keep\"]");

            AppPaths.SeedFallbackConfig(appConfig, fallbackConfig);

            AssertEqual("{\"old\":true}", File.ReadAllText(Path.Combine(fallbackConfig, AppPaths.AppSettingsFileName)));
            AssertEqual("[\"keep\"]", File.ReadAllText(Path.Combine(fallbackConfig, AppPaths.IgnoredHashesFileName)));
            AssertFalse(File.Exists(Path.Combine(fallbackConfig, AppPaths.QuarantineManifestFileName)));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }),
    ("startup task runs elevated at logon for the given user", () =>
    {
        var xml = ElevatedStartupTask.BuildTaskXml(@"C:\Program Files\HashGuard\HashGuard.exe", "S-1-5-21-1-2-3-1001");
        var doc = System.Xml.Linq.XDocument.Parse(xml);
        System.Xml.Linq.XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        AssertEqual("HighestAvailable", doc.Descendants(ns + "RunLevel").Single().Value);
        AssertEqual("InteractiveToken", doc.Descendants(ns + "LogonType").Single().Value);
        AssertEqual("S-1-5-21-1-2-3-1001", doc.Descendants(ns + "LogonTrigger").Elements(ns + "UserId").Single().Value);
        AssertEqual("S-1-5-21-1-2-3-1001", doc.Descendants(ns + "Principal").Elements(ns + "UserId").Single().Value);
        AssertEqual(@"C:\Program Files\HashGuard\HashGuard.exe", doc.Descendants(ns + "Command").Single().Value);
        AssertEqual("--minimized", doc.Descendants(ns + "Arguments").Single().Value);
        AssertEqual(@"C:\Program Files\HashGuard", doc.Descendants(ns + "WorkingDirectory").Single().Value);
    }),
    ("startup task is never killed by the 72h default or battery rules", () =>
    {
        var doc = System.Xml.Linq.XDocument.Parse(ElevatedStartupTask.BuildTaskXml(@"C:\HG\HashGuard.exe", "S-1-5-21-9"));
        System.Xml.Linq.XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        AssertEqual("PT0S", doc.Descendants(ns + "ExecutionTimeLimit").Single().Value);
        AssertEqual("false", doc.Descendants(ns + "DisallowStartIfOnBatteries").Single().Value);
        AssertEqual("false", doc.Descendants(ns + "StopIfGoingOnBatteries").Single().Value);
        AssertEqual("IgnoreNew", doc.Descendants(ns + "MultipleInstancesPolicy").Single().Value);
        AssertTrue(xmlDeclaresUtf16(ElevatedStartupTask.BuildTaskXml(@"C:\HG\HashGuard.exe", "S-1-5-21-9")));
    }),
    ("startup task xml escapes odd paths and round-trips the command", () =>
    {
        var path = @"C:\Users\R&D <test>\HashGuard.exe";
        var xml = ElevatedStartupTask.BuildTaskXml(path, "S-1-5-21-9");
        AssertEqual(path, ElevatedStartupTask.ReadCommand(xml));
        AssertEqual(null, ElevatedStartupTask.ReadCommand("not xml"));
        AssertEqual(null, ElevatedStartupTask.ReadCommand(""));
    }),
    ("startup task working directory is the exe folder", () =>
    {
        AssertEqual(@"C:\Program Files\HashGuard", ElevatedStartupTask.WindowsDirectoryOf(@"C:\Program Files\HashGuard\HashGuard.exe"));
        AssertEqual(@"C:\", ElevatedStartupTask.WindowsDirectoryOf(@"C:\HashGuard.exe"));
        AssertEqual("", ElevatedStartupTask.WindowsDirectoryOf("HashGuard.exe"));
    }),
    ("startup task requires a path and a user", () =>
    {
        AssertThrows<ArgumentException>(() => ElevatedStartupTask.BuildTaskXml("", "S-1-5-21-9"));
        AssertThrows<ArgumentException>(() => ElevatedStartupTask.BuildTaskXml(@"C:\HG\HashGuard.exe", " "));
    }),
    ("tcp4 table parser reads state, addresses, ports and pid", () =>
    {
        var buffer = new byte[4 + 24 * 2];
        WriteUInt32(buffer, 0, 2);
        WriteTcp4Row(buffer, 4, state: 5, local: [192, 168, 1, 10], localPort: 51000, remote: [142, 250, 72, 14], remotePort: 443, pid: 1234);
        WriteTcp4Row(buffer, 28, state: 2, local: [0, 0, 0, 0], localPort: 445, remote: [0, 0, 0, 0], remotePort: 0, pid: 4);
        var rows = ConnectionTable.ParseTcp4(buffer);
        AssertEqual(2, rows.Count);
        AssertEqual(1234, rows[0].Pid);
        AssertEqual("192.168.1.10", rows[0].LocalAddress.ToString());
        AssertEqual(51000, rows[0].LocalPort);
        AssertEqual("142.250.72.14", rows[0].RemoteAddress.ToString());
        AssertEqual(443, rows[0].RemotePort);
        AssertEqual(TcpState.Established, rows[0].State);
        AssertEqual(TcpState.Listen, rows[1].State);
        AssertTrue(ConnectionTable.IsOutboundCandidate(rows[0]));
        AssertFalse(ConnectionTable.IsOutboundCandidate(rows[1]));
    }),
    ("tcp6 table parser reads 56-byte rows", () =>
    {
        var buffer = new byte[4 + 56];
        WriteUInt32(buffer, 0, 1);
        var remote = System.Net.IPAddress.Parse("2606:4700::1111").GetAddressBytes();
        var local = System.Net.IPAddress.Parse("2001:db8::5").GetAddressBytes();
        local.CopyTo(buffer, 4);
        buffer[24] = 0xC3; buffer[25] = 0x50; // local port 50000
        remote.CopyTo(buffer, 28);
        buffer[48] = 0x01; buffer[49] = 0xBB; // remote port 443
        WriteUInt32(buffer, 52, 3); // SYN_SENT
        WriteUInt32(buffer, 56, 99);
        var rows = ConnectionTable.ParseTcp6(buffer);
        AssertEqual(1, rows.Count);
        AssertEqual("2606:4700::1111", rows[0].RemoteAddress.ToString());
        AssertEqual("2001:db8::5", rows[0].LocalAddress.ToString());
        AssertEqual(50000, rows[0].LocalPort);
        AssertEqual(443, rows[0].RemotePort);
        AssertEqual(TcpState.SynSent, rows[0].State);
        AssertEqual(99, rows[0].Pid);
    }),
    ("tcp table parser tolerates short and truncated buffers", () =>
    {
        AssertEqual(0, ConnectionTable.ParseTcp4([]).Count);
        AssertEqual(0, ConnectionTable.ParseTcp6([1, 0]).Count);
        var buffer = new byte[4 + 24];
        WriteUInt32(buffer, 0, 5); // claims 5 rows, holds 1
        WriteTcp4Row(buffer, 4, state: 5, local: [10, 0, 0, 2], localPort: 1, remote: [1, 1, 1, 1], remotePort: 53, pid: 7);
        AssertEqual(1, ConnectionTable.ParseTcp4(buffer).Count);
    }),
    ("remote addresses are classified as loopback, lan or internet", () =>
    {
        foreach (var (address, scope) in new[]
        {
            ("127.0.0.1", RemoteScope.Loopback), ("::1", RemoteScope.Loopback),
            ("0.0.0.0", RemoteScope.Unspecified), ("::", RemoteScope.Unspecified),
            ("10.0.1.12", RemoteScope.Lan), ("172.16.0.1", RemoteScope.Lan), ("172.31.255.1", RemoteScope.Lan),
            ("192.168.1.1", RemoteScope.Lan), ("169.254.3.4", RemoteScope.Lan), ("100.64.0.1", RemoteScope.Lan),
            ("224.0.0.251", RemoteScope.Lan), ("fe80::1", RemoteScope.Lan), ("fd00::1", RemoteScope.Lan),
            ("::ffff:10.0.0.1", RemoteScope.Lan), ("::ffff:8.8.8.8", RemoteScope.Internet),
            ("172.32.0.1", RemoteScope.Internet), ("8.8.8.8", RemoteScope.Internet), ("2606:4700::1111", RemoteScope.Internet),
        })
        {
            AssertEqual(scope, ConnectionTable.Classify(System.Net.IPAddress.Parse(address)));
        }
    }),
    ("outbound candidates skip pid 0, loopback, listeners and time-wait", () =>
    {
        var internet = System.Net.IPAddress.Parse("8.8.8.8");
        var local = System.Net.IPAddress.Parse("10.0.0.2");
        AssertTrue(ConnectionTable.IsOutboundCandidate(new TcpConnection(10, local, 5000, internet, 443, TcpState.SynSent)));
        AssertFalse(ConnectionTable.IsOutboundCandidate(new TcpConnection(0, local, 5000, internet, 443, TcpState.Established)));
        AssertFalse(ConnectionTable.IsOutboundCandidate(new TcpConnection(10, local, 5000, internet, 443, TcpState.TimeWait)));
        AssertFalse(ConnectionTable.IsOutboundCandidate(new TcpConnection(10, local, 5000, System.Net.IPAddress.Loopback, 443, TcpState.Established)));
        AssertFalse(ConnectionTable.IsOutboundCandidate(new TcpConnection(10, local, 5000, internet, 0, TcpState.Established)));
    }),
    ("network tracker counts a long-lived connection once and new ones again", () =>
    {
        var tracker = new NetworkActivityTracker();
        var t0 = DateTimeOffset.Parse("2026-11-26T10:00:00Z");
        var app = @"C:\Apps\curl.exe";
        var first = Conn(10, 50000, "93.184.216.34", 443);
        var r1 = tracker.Update([(app, first)], t0);
        tracker.Update([(app, first)], t0.AddSeconds(1));
        tracker.Update([(app, first), (app, Conn(10, 50001, "93.184.216.34", 443))], t0.AddSeconds(2));
        AssertTrue(tracker.TryGetApp(app, out var activity));
        AssertEqual(2, activity.TotalConnections);
        AssertEqual(2, activity.CurrentConnections);
        AssertEqual(1, activity.Endpoints.Count);
        AssertEqual(1, r1.FirstEverSeen.Count);
        tracker.Update([], t0.AddSeconds(3));
        AssertEqual(0, activity.CurrentConnections);
        AssertEqual(t0.AddSeconds(2), activity.LastSeenUtc);
        AssertEqual("curl.exe", activity.Name);
    }),
    ("network tracker reports first-ever apps only once and remembers saved ones", () =>
    {
        var t0 = DateTimeOffset.Parse("2026-11-26T10:00:00Z");
        var seen = new Dictionary<string, SeenNetworkApp> { [@"C:\Old\app.exe"] = new() { FirstSeenUtc = t0.AddDays(-3), LastSeenUtc = t0.AddDays(-1) } };
        var tracker = new NetworkActivityTracker(seen);
        var r1 = tracker.Update([(@"c:\old\APP.exe", Conn(1, 1000, "1.1.1.1", 443)), (@"C:\New\tool.exe", Conn(2, 1001, "1.1.1.1", 443))], t0);
        AssertEqual(1, r1.FirstEverSeen.Count);
        AssertEqual(@"C:\New\tool.exe", r1.FirstEverSeen[0].Path);
        AssertTrue(r1.SeenAppsChanged);
        var r2 = tracker.Update([(@"C:\New\tool.exe", Conn(2, 1002, "1.1.1.1", 443))], t0.AddMinutes(1));
        AssertEqual(0, r2.FirstEverSeen.Count);
        AssertFalse(r2.SeenAppsChanged);
    }),
    ("network tracker caps seen apps and endpoints", () =>
    {
        var t0 = DateTimeOffset.Parse("2026-11-26T10:00:00Z");
        var tracker = new NetworkActivityTracker(maxSeenApps: 2);
        tracker.Update([(@"C:\a.exe", Conn(1, 1, "1.1.1.1", 443))], t0);
        tracker.Update([(@"C:\b.exe", Conn(2, 2, "1.1.1.1", 443))], t0.AddSeconds(1));
        tracker.Update([(@"C:\c.exe", Conn(3, 3, "1.1.1.1", 443))], t0.AddSeconds(2));
        AssertEqual(2, tracker.SeenApps.Count);
        AssertFalse(tracker.SeenApps.ContainsKey(@"C:\a.exe"));
        var many = Enumerable.Range(0, NetworkAppActivity.MaxEndpoints + 5)
            .Select(i => (@"C:\d.exe", Conn(4, 2000 + i, $"8.8.{i / 250}.{i % 250 + 1}", 443)))
            .ToList();
        tracker.Update(many, t0.AddSeconds(3));
        AssertTrue(tracker.TryGetApp(@"C:\d.exe", out var app));
        AssertEqual(NetworkAppActivity.MaxEndpoints, app.Endpoints.Count);
    }),
    ("network tracker writes endpoints with brackets for ipv6", () =>
    {
        AssertEqual("[2606:4700::1111]:443", NetworkEndpoint.FormatEndpoint("2606:4700::1111", 443));
        AssertEqual("example.com:443", NetworkEndpoint.FormatEndpoint("example.com", 443));
        AssertEqual("System", NetworkActivityTracker.DisplayName("System"));
    }),
    ("network verdict maps cache entries", () =>
    {
        AssertEqual(NetworkVerdictKind.NotScanned, NetworkVerdict.FromCache(null).Kind);
        AssertEqual("Malicious (3)", NetworkVerdict.FromCache(new CacheEntry { Status = "malicious", Malicious = 3 }).Label);
        AssertEqual(NetworkVerdictKind.Suspicious, NetworkVerdict.FromCache(new CacheEntry { Status = "suspicious", Suspicious = 1 }).Kind);
        AssertEqual(NetworkVerdictKind.Clean, NetworkVerdict.FromCache(new CacheEntry { Status = "clean/seen" }).Kind);
        AssertEqual(NetworkVerdictKind.Unknown, NetworkVerdict.FromCache(new CacheEntry { Status = "unknown" }).Kind);
    }),
    ("untrusted means flagged, or not a trusted publisher and unsigned or not known clean", () =>
    {
        AssertTrue(NetworkVerdict.IsUntrusted(NetworkVerdictKind.Malicious, signed: true, trustedPublisher: true));
        AssertFalse(NetworkVerdict.IsUntrusted(NetworkVerdictKind.NotScanned, signed: true, trustedPublisher: true));
        AssertFalse(NetworkVerdict.IsUntrusted(NetworkVerdictKind.Clean, signed: true, trustedPublisher: false));
        AssertTrue(NetworkVerdict.IsUntrusted(NetworkVerdictKind.Clean, signed: false, trustedPublisher: false));
        AssertTrue(NetworkVerdict.IsUntrusted(NetworkVerdictKind.NotScanned, signed: true, trustedPublisher: false));
        AssertEqual(NetworkNotifyModes.Untrusted, NetworkNotifyModes.Normalize(null));
        AssertEqual(NetworkNotifyModes.Never, NetworkNotifyModes.Normalize("never"));
        AssertEqual(NetworkNotifyModes.Untrusted, NetworkNotifyModes.Normalize("bogus"));
    }),
    ("firewall rule names are readable and unique per path", () =>
    {
        var a = FirewallRules.RuleName(@"C:\Tools\app.exe", inbound: false);
        var b = FirewallRules.RuleName(@"D:\Other\app.exe", inbound: false);
        AssertTrue(a.StartsWith("HashGuard block: app.exe (", StringComparison.Ordinal));
        AssertTrue(a != b);
        AssertEqual(FirewallRules.ShortPathHash(@"C:\Tools\app.exe"), FirewallRules.ShortPathHash("\"c:\\tools\\APP.exe\""));
        AssertTrue(FirewallRules.RuleName(@"C:\Tools\app.exe", inbound: true).StartsWith("HashGuard block inbound: app.exe", StringComparison.Ordinal));
        AssertEqual(8, FirewallRules.ShortPathHash(@"C:\Tools\app.exe").Length);
    }),
    ("firewall paths compare case-insensitively and ignore quotes and slashes", () =>
    {
        AssertTrue(FirewallRules.PathsEqual(@"C:\Tools\App.exe", "\"c:/tools/app.EXE\" "));
        AssertFalse(FirewallRules.PathsEqual(@"C:\Tools\app.exe", @"C:\Tools\app2.exe"));
        AssertFalse(FirewallRules.PathsEqual(null, @"C:\x.exe"));
    }),
    ("firewall warns before blocking windows parts and hashguard itself", () =>
    {
        const string windows = @"C:\Windows";
        const string self = @"C:\Program Files\HashGuard\HashGuard.exe";
        AssertTrue(FirewallRules.IsSensitivePath(@"C:\Windows\System32\svchost.exe", windows, self));
        AssertTrue(FirewallRules.IsSensitivePath("System", windows, self));
        AssertTrue(FirewallRules.IsSensitivePath(@"c:\program files\hashguard\hashguard.exe", windows, self));
        AssertFalse(FirewallRules.IsSensitivePath(@"C:\WindowsApps\thing.exe", windows, self));
        AssertFalse(FirewallRules.IsSensitivePath(@"C:\Program Files\Mozilla Firefox\firefox.exe", windows, self));
    }),
    ("anonymous usage data is on for new installs but saved choices are kept", () =>
    {
        AssertTrue(new AppSettings().TelemetryEnabled);
        var saved = System.Text.Json.JsonSerializer.Deserialize<AppSettings>("{\"TelemetryEnabled\":false}")!;
        AssertFalse(saved.TelemetryEnabled);
        var older = System.Text.Json.JsonSerializer.Deserialize<AppSettings>("{\"StartMinimized\":true}")!;
        AssertTrue(older.TelemetryEnabled);
    }),
    ("daily scan is on at noon for new installs but saved choices are kept", () =>
    {
        var fresh = new AppSettings();
        AssertTrue(fresh.ScheduledDailyScan);
        AssertEqual(12, fresh.ScheduledScanHour);
        var saved = System.Text.Json.JsonSerializer.Deserialize<AppSettings>("{\"ScheduledDailyScan\":false,\"ScheduledScanHour\":2}")!;
        AssertFalse(saved.ScheduledDailyScan);
        AssertEqual(2, saved.ScheduledScanHour);
    }),
    ("daily scan task catches up after a missed run and passes the scheduled-scan argument", () =>
    {
        var xml = ScheduledScan.BuildTaskXml(@"C:\Program Files\HashGuard\HashGuard.exe", "S-1-5-21-9", 12, highestPrivileges: true, new DateTime(2026, 11, 26));
        var doc = XDocument.Parse(xml);
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        AssertEqual("true", doc.Descendants(ns + "StartWhenAvailable").Single().Value);
        AssertEqual("2026-11-26T12:00:00", doc.Descendants(ns + "StartBoundary").Single().Value);
        AssertEqual("1", doc.Descendants(ns + "DaysInterval").Single().Value);
        AssertEqual("HighestAvailable", doc.Descendants(ns + "RunLevel").Single().Value);
        AssertEqual("--scheduled-scan --minimized", doc.Descendants(ns + "Arguments").Single().Value);
        AssertEqual("LeastPrivilege", XDocument.Parse(ScheduledScan.BuildTaskXml(@"C:\HG\HashGuard.exe", "S-1-5-21-9", 30, false, DateTime.Today)).Descendants(ns + "RunLevel").Single().Value);
        AssertTrue(ScheduledScan.BuildTaskXml(@"C:\HG\HashGuard.exe", "S-1-5-21-9", 30, false, new DateTime(2026, 1, 2)).Contains("2026-01-02T23:00:00", StringComparison.Ordinal));
    }),
    ("daily scan task is re-registered when it predates v1.1.0 or points elsewhere", () =>
    {
        var current = ScheduledScan.BuildTaskXml(@"C:\HG\HashGuard.exe", "S-1-5-21-9", 12, false, DateTime.Today);
        AssertTrue(ScheduledScan.IsCurrent(current, @"c:\hg\hashguard.exe"));
        AssertFalse(ScheduledScan.IsCurrent(current, @"D:\Other\HashGuard.exe"));
        AssertFalse(ScheduledScan.IsCurrent(current.Replace("--scheduled-scan ", ""), @"C:\HG\HashGuard.exe"));
        AssertFalse(ScheduledScan.IsCurrent("not xml", @"C:\HG\HashGuard.exe"));
    }),
    ("auto-block and background monitoring are on for new installs but saved choices are kept", () =>
    {
        var fresh = new AppSettings();
        AssertTrue(fresh.AutoBlockMalicious);
        AssertTrue(fresh.NetworkMonitorEnabled);
        var saved = System.Text.Json.JsonSerializer.Deserialize<AppSettings>("{\"AutoBlockMalicious\":false,\"NetworkMonitorEnabled\":false}")!;
        AssertFalse(saved.AutoBlockMalicious);
        AssertFalse(saved.NetworkMonitorEnabled);
    }),
    ("virustotal uploads are allowed for new installs but saved choices are kept", () =>
    {
        AssertTrue(new AppSettings().UploadUnknown);
        AssertFalse(System.Text.Json.JsonSerializer.Deserialize<AppSettings>("{\"UploadUnknown\":false}")!.UploadUnknown);
    }),
    ("trusted publisher needs an exact name and a valid signature chain", () =>
    {
        var trusted = new[] { "Microsoft Corporation" };
        AssertTrue(HashGuardLogic.IsTrustedPublisher("Microsoft Corporation", "Signed by Microsoft Corporation; chain valid", trusted));
        AssertFalse(HashGuardLogic.IsTrustedPublisher("Microsoft", "Signed by Microsoft; chain valid", trusted));
        AssertFalse(HashGuardLogic.IsTrustedPublisher("Microsoft Corporation Evil Ltd", "Signed by Microsoft Corporation Evil Ltd; chain valid", trusted));
        AssertFalse(HashGuardLogic.IsTrustedPublisher("Microsoft Corporation", "Signed by Microsoft Corporation; UntrustedRoot", trusted));
        AssertFalse(HashGuardLogic.IsTrustedPublisher("Microsoft Corporation", "Signed by Microsoft Corporation; certificate outside validity period; chain valid", trusted));
        AssertFalse(HashGuardLogic.IsTrustedPublisher("", "Unsigned or signature unavailable", trusted));
        AssertFalse(HashGuardLogic.IsTrustedPublisher("Micro", "Signed by Micro; chain valid", new[] { "Micro Systems" }));
    }),
    ("saved trust lists from before v1.1.0 gain the real certificate names once", () =>
    {
        var expanded = HashGuardLogic.ExpandLegacyTrustedPublishers(new[] { "Lenovo", "Advanced Micro Devices", " Contoso  Ltd " });
        AssertTrue(expanded.Contains("Lenovo (United States) Inc."));
        AssertTrue(expanded.Contains("Advanced Micro Devices, Inc."));
        AssertTrue(expanded.Contains("Contoso Ltd"));
        AssertTrue(expanded.Contains("Lenovo"));
        var again = HashGuardLogic.ExpandLegacyTrustedPublishers(expanded);
        AssertEqual(expanded.Count, again.Count);
        AssertTrue(new AppSettings().TrustedPublishers.Contains("Advanced Micro Devices, Inc."));
    }),
    ("home says protected only when scanned, clean and a source is on", () =>
    {
        var now = new DateTime(2026, 11, 26, 15, 0, 0);
        var ok = HomeStatusText.Build(false, 0, 0, 3, 3, now.AddHours(-1), now, true);
        AssertEqual(HomeTone.Protected, ok.Tone);
        AssertEqual("You're protected", ok.Title);
        AssertEqual("3 reputation sources online", ok.SourcesChip);
        AssertEqual("Last scan today 14:00", ok.LastScanChip);
        AssertEqual(HomeTone.NotScanned, HomeStatusText.Build(false, 0, 0, 3, 3, null, now, true).Tone);
        AssertEqual(HomeTone.Attention, HomeStatusText.Build(false, 0, 0, 0, 3, now, now, true).Tone);
        AssertEqual("2 of 3 reputation sources", HomeStatusText.Build(false, 0, 0, 2, 3, now, now, true).SourcesChip);
    }),
    ("home puts threats before decisions and scanning before both", () =>
    {
        var now = new DateTime(2026, 11, 26, 15, 0, 0);
        var threat = HomeStatusText.Build(false, 1, 3, 3, 3, now, now, true);
        AssertEqual(HomeTone.Danger, threat.Tone);
        AssertEqual("1 threat needs your attention", threat.Title);
        AssertEqual("2 threats need your attention", HomeStatusText.Build(false, 2, 2, 3, 3, now, now, true).Title);
        AssertEqual("3 files need your decision", HomeStatusText.Build(false, 0, 3, 3, 3, now, now, true).Title);
        AssertEqual(HomeTone.Scanning, HomeStatusText.Build(true, 4, 4, 3, 3, now, now, true).Tone);
        AssertTrue(HomeStatusText.Build(false, 0, 0, 3, 3, now, now, false).Subtitle.Contains("firewall monitor is off", StringComparison.Ordinal));
    }),
    ("last scan reads today, yesterday or a date", () =>
    {
        var now = new DateTime(2026, 11, 26, 15, 0, 0);
        AssertEqual("No scan yet", HomeStatusText.FormatLastScan(null, now));
        AssertTrue(HomeStatusText.FormatLastScan(now.AddDays(-1), now).StartsWith("Last scan yesterday", StringComparison.Ordinal));
        AssertFalse(HomeStatusText.FormatLastScan(now.AddDays(-5), now).Contains("today", StringComparison.Ordinal));
    }),
    ("sidebar badges hide zero and cap at 99+", () =>
    {
        AssertEqual("", HomeStatusText.BadgeText(0));
        AssertEqual("7", HomeStatusText.BadgeText(7));
        AssertEqual("99+", HomeStatusText.BadgeText(250));
    }),
    ("tray pop-up sits in the bottom-right corner of the working area", () =>
    {
        var area = new System.Drawing.Rectangle(0, 0, 1920, 1032);
        AssertEqual(new System.Drawing.Point(1520, 816), PopupPlacement.BottomRight(area, new System.Drawing.Size(384, 200), 16));
        var left = new System.Drawing.Rectangle(-1280, 0, 1280, 984);
        AssertEqual(new System.Drawing.Point(-400, 768), PopupPlacement.BottomRight(left, new System.Drawing.Size(384, 200), 16));
        AssertEqual(new System.Drawing.Point(0, 0), PopupPlacement.BottomRight(new System.Drawing.Rectangle(0, 0, 300, 100), new System.Drawing.Size(384, 200), 16));
    }),
};

var failures = new List<string>();
foreach (var test in tests)
{
    try
    {
        test.Test();
        Console.WriteLine($"PASS {test.Name}");
    }
    catch (Exception ex)
    {
        failures.Add($"{test.Name}: {ex.Message}");
        Console.WriteLine($"FAIL {test.Name}: {ex.Message}");
    }
}

if (failures.Count > 0)
{
    Console.Error.WriteLine(string.Join(Environment.NewLine, failures));
    return 1;
}

Console.WriteLine($"OK {tests.Length} tests");
return 0;

static void AssertEqual<T>(T expected, T actual)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
    {
        throw new Exception($"Expected {expected}, got {actual}");
    }
}

static void AssertTrue(bool value)
{
    if (!value)
    {
        throw new Exception("Expected true");
    }
}

static void AssertFalse(bool value)
{
    if (value)
    {
        throw new Exception("Expected false");
    }
}

static bool xmlDeclaresUtf16(string xml) =>
    xml.StartsWith("<?xml version=\"1.0\" encoding=\"UTF-16\"?>", StringComparison.Ordinal);

static void AssertThrows<TException>(Action action) where TException : Exception
{
    try
    {
        action();
    }
    catch (TException)
    {
        return;
    }

    throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
}

static void WriteUInt32(byte[] buffer, int offset, uint value) =>
    System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset), value);

static void WriteTcp4Row(byte[] buffer, int offset, uint state, byte[] local, int localPort, byte[] remote, int remotePort, uint pid)
{
    WriteUInt32(buffer, offset, state);
    local.CopyTo(buffer, offset + 4);
    buffer[offset + 8] = (byte)(localPort >> 8);
    buffer[offset + 9] = (byte)localPort;
    remote.CopyTo(buffer, offset + 12);
    buffer[offset + 16] = (byte)(remotePort >> 8);
    buffer[offset + 17] = (byte)remotePort;
    WriteUInt32(buffer, offset + 20, pid);
}

static TcpConnection Conn(int pid, int localPort, string remote, int remotePort) =>
    new(pid, System.Net.IPAddress.Parse("10.0.0.2"), localPort, System.Net.IPAddress.Parse(remote), remotePort, TcpState.Established);
