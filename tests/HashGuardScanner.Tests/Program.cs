using System.Text.Json;
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
    ("quarantine notes are detected", () =>
    {
        AssertTrue(HashGuardLogic.NoteIndicatesQuarantined("Quarantined to C:\\q\\file.bin"));
        AssertTrue(HashGuardLogic.NoteIndicatesQuarantined("File Quarantined"));
        AssertFalse(HashGuardLogic.NoteIndicatesQuarantined("No issues"));
        AssertFalse(HashGuardLogic.NoteIndicatesQuarantined(null));
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
        AssertTrue(HashGuardLogic.PublisherMatchesForIgnore("Microsoft Corporation", "Microsoft"));
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
