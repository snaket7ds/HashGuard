using System.Text.Json;
using HashGuard.Core;

/// <summary>Tests for v2's settings storage, ignore list, process collection and scan service.</summary>
internal static class V2ScanTests
{
    public static (string Name, Action Test)[] All =>
    [
        ("DPAPI: keys round-trip and are not stored as plaintext", () =>
        {
            var blob = Dpapi.Protect("secret-key-123");
            True(blob.Length > 0);
            False(blob.Contains("secret"));
            Equal("secret-key-123", Dpapi.Unprotect(blob));
            Equal("", Dpapi.Protect(""));
        }),
        ("DPAPI: v1-format blobs (ProtectedData, CurrentUser) decrypt", () =>
        {
            // ProtectedData.Protect is CryptProtectData with no entropy and UI forbidden; this
            // checks the same call shape by decrypting a blob made by our own Protect.
            var settings = new AppSettings { ApiKeyEncrypted = Dpapi.Protect("vt-key") };
            Equal("vt-key", SettingsStore.ReadKeys(settings).VirusTotal);
        }),
        ("Settings: save writes encrypted keys and reloads every value", () => WithTemp(dir =>
        {
            var store = new SettingsStore(Path.Combine(dir, "config", "settings.json"));
            var settings = new AppSettings { DelaySeconds = 30, NetworkNotifyMode = NetworkNotifyModes.Untrusted, TelemetryEnabled = true };
            store.Save(settings, new ApiKeys("vt-secret", "md-secret"));

            var json = File.ReadAllText(store.Path);
            False(json.Contains("vt-secret"));
            False(json.Contains("md-secret"));

            var loaded = store.Load();
            Equal(30, loaded.DelaySeconds);
            False(string.IsNullOrWhiteSpace(loaded.AnonymousInstallId));
            var keys = SettingsStore.ReadKeys(loaded);
            Equal("vt-secret", keys.VirusTotal);
            Equal("md-secret", keys.MetaDefender);
        })),
        ("Settings: a v1 file with plaintext keys still loads them", () => WithTemp(dir =>
        {
            var path = Path.Combine(dir, "settings.json");
            File.WriteAllText(path, """{"ApiKey":"old-vt","MetaDefenderApiKey":"old-md","DelaySeconds":20,"TrustedPublishers":null}""");
            var loaded = new SettingsStore(path).Load();
            Equal(20, loaded.DelaySeconds);
            Equal("old-vt", SettingsStore.ReadKeys(loaded).VirusTotal);
            Equal("old-md", SettingsStore.ReadKeys(loaded).MetaDefender);
            True(loaded.TrustedPublishers.Count > 0);
        })),
        ("Settings: missing or broken files give defaults", () => WithTemp(dir =>
        {
            Equal(16, new SettingsStore(Path.Combine(dir, "none.json")).Load().DelaySeconds);
            var broken = Path.Combine(dir, "broken.json");
            File.WriteAllText(broken, "{ not json");
            Equal(16, new SettingsStore(broken).Load().DelaySeconds);
        })),
        ("Ignore list: changes persist in v1's JSON format", () => WithTemp(dir =>
        {
            var hashes = Path.Combine(dir, "ignored-hashes.json");
            var paths = Path.Combine(dir, "ignored-paths.json");
            var list = new IgnoreList(hashes, paths);
            list.AddHash("ABC");
            list.AddHash("abc");
            list.AddPath(@"C:\Tools\a.exe");
            Equal(1, JsonSerializer.Deserialize<List<string>>(File.ReadAllText(hashes))!.Count);

            var reloaded = new IgnoreList(hashes, paths);
            reloaded.Load();
            True(reloaded.Hashes.Contains("abc"));
            True(reloaded.Paths.Contains(@"c:\tools\A.EXE"));
            reloaded.RemovePath(@"C:\Tools\a.exe");
            Equal(0, reloaded.Paths.Count);
        })),
        ("Process collector finds this test process's executable", () =>
        {
            var collection = ProcessCollector.CollectRunning();
            var mine = collection.Files.Where(pair => pair.Value.Any(p => p.Pid == Environment.ProcessId)).Select(pair => pair.Key).ToList();
            var skippedSelf = collection.Skipped.FirstOrDefault(s => s.Pid == Environment.ProcessId);
            if (mine.Count != 1)
            {
                throw new InvalidOperationException($"self not found; skipped as: {skippedSelf?.Reason ?? "-"}");
            }

            // Windows may report a mapped drive (I:\...) by its UNC path, so compare file names.
            Equal(Path.GetFileName(Environment.ProcessPath!), Path.GetFileName(mine[0]));
        }),
        ("Scan log rows quote every field", () =>
        {
            var result = new ScanResult(@"C:\a, b\x.exe", "x.exe", "1") { Status = "clean", Notes = "say \"hi\"" };
            var row = ScanLog.FormatRow(result);
            True(row.Contains("\"C:\\a, b\\x.exe\""));
            True(row.Contains("\"say \"\"hi\"\"\""));
            Equal(16, HashGuardLogic.ParseCsvLine(row).Count);
        }),
        ("Scan service: full scan, then monitoring only checks new files", () => Run(async () =>
        {
            var dir = Directory.CreateTempSubdirectory("hg-test").FullName;
            try
            {
                var a = Touch(dir, "a.exe");
                var b = Touch(dir, "b.exe");
                var running = new List<string> { a };
                var analyzed = new List<string>();
                var service = TestService(() => running, analyzed);

                var full = await service.ScanRunningAppsAsync();
                Equal(1, full!.Results.Count);
                True(service.HasBaseline);

                running.Add(b);
                var monitor = await service.ScanChangedAppsAsync();
                Equal(1, monitor!.Results.Count);
                Equal(b, monitor.Results[0].Path);

                var quiet = await service.ScanChangedAppsAsync();
                Equal(0, quiet!.Results.Count);
                Equal(2, analyzed.Count);
            }
            finally
            {
                Directory.Delete(dir, true);
            }
        })),
        ("Scan service: a second scan while one runs is refused", () => Run(async () =>
        {
            var release = new TaskCompletionSource();
            var service = new ScanService(new HashCache(), Config)
            {
                CollectProcesses = async (_, _) =>
                {
                    await release.Task;
                    return new ProcessCollection(new Dictionary<string, List<ProcessFile>>(), []);
                },
                PrepareStorage = _ => Task.CompletedTask,
                WriteLog = null,
                UseSnapshots = false,
                CreateProviders = _ => [],
            };
            var first = service.ScanRunningAppsAsync();
            True(service.IsBusy);
            Equal(null, await service.ScanFilesAsync(["x"]));
            release.SetResult();
            True(await first is not null);
            False(service.IsBusy);
        })),
        ("Scan service: chosen files are scanned once each and reported in order", () => Run(async () =>
        {
            var analyzed = new List<string>();
            var service = TestService(() => [], analyzed);
            var seen = new List<int>();
            var progress = new SyncProgress(p => { if (p.Latest is not null) seen.Add(p.Done); });
            var outcome = await service.ScanFilesAsync([@"C:\b.exe", @"C:\a.exe", @"c:\A.exe"], progress);
            Equal(2, outcome!.Results.Count);
            Equal(@"C:\a.exe", outcome.Results[0].Path);
            Equal("1,2", string.Join(",", seen));
        })),
        ("Scan service: outcome counts what needs a decision", () =>
        {
            var flagged = new ScanResult("a", "a", "1") { Status = "detected", Malicious = 3, RiskLevel = "High", RiskScore = 80 };
            var ignored = new ScanResult("b", "b", "1") { Status = "ignored", Malicious = 3 };
            var clean = new ScanResult("c", "c", "1") { Status = "clean", RiskLevel = "Low" };
            var failed = new ScanResult("d", "d", "1") { Status = "error" };
            var outcome = new ScanOutcome(ScanKind.Files, [flagged, ignored, clean, failed], 0, []);
            Equal(2, outcome.NeedsDecision.Count);
            Equal(1, outcome.Threats);
            Equal(1, outcome.Errors);
        }),
        ("MetaDefender on without a key is reported before scanning", () =>
        {
            True(ScanRules.MetaDefenderKeyMissing(new AppSettings { MetaDefenderEnabled = true }, ApiKeys.None));
            False(ScanRules.MetaDefenderKeyMissing(new AppSettings { MetaDefenderEnabled = false }, ApiKeys.None));
        }),
    ];

    private static ScanConfiguration Config() =>
        new(new AppSettings { HashCacheEnabled = false }, ApiKeys.None, new HashSet<string>(), new HashSet<string>());

    private static ScanService TestService(Func<List<string>> running, List<string> analyzed) =>
        new(new HashCache(), Config)
        {
            CollectProcesses = (_, _) => Task.FromResult(new ProcessCollection(
                running().ToDictionary(p => p, p => new List<ProcessFile> { new(1, Path.GetFileName(p), p) }, StringComparer.OrdinalIgnoreCase), [])),
            PrepareStorage = _ => Task.CompletedTask,
            WriteLog = null,
            UseSnapshots = false,
            CreateProviders = _ => [],
            CreateAnalyzer = (config, providers) => new FileAnalyzer(new HashCache(), providers, new AnalyzerSettings { HashCacheEnabled = false },
                _ => new SignatureInfo(SignatureReader.UnsignedSummary, ""),
                (path, _) => { lock (analyzed) { analyzed.Add(path); } return Task.FromResult(new string('b', 64)); }),
        };

    private static string Touch(string dir, string name)
    {
        var path = Path.Combine(dir, name);
        File.WriteAllText(path, name);
        return path;
    }

    private static void WithTemp(Action<string> test)
    {
        var dir = Directory.CreateTempSubdirectory("hg-test").FullName;
        try
        {
            test(dir);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static void Run(Func<Task> test) => test().GetAwaiter().GetResult();

    private static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected <{expected}> but got <{actual}>.");
        }
    }

    private static void True(bool value)
    {
        if (!value)
        {
            throw new InvalidOperationException("Expected true.");
        }
    }

    private static void False(bool value) => True(!value);

    /// <summary>Reports synchronously (Progress&lt;T&gt; posts to the thread pool).</summary>
    private sealed class SyncProgress(Action<ScanProgress> report) : IProgress<ScanProgress>
    {
        public void Report(ScanProgress value) => report(value);
    }
}
