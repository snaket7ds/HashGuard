using System.Net;
using System.Text;
using HashGuard.Core;

/// <summary>Tests for code new in v2: the reputation providers, VirusTotal pacing and the file analyzer.</summary>
internal static class V2CoreTests
{
    private const string Sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static readonly HashSet<string> NoStrings = new(StringComparer.OrdinalIgnoreCase);

    public static (string Name, Action Test)[] All =>
    [
        ("MetaDefender: detections mark the file detected", () => Run(async () =>
        {
            var json = """{"scan_results":{"total_detected_avs":3,"total_avs":20,"scan_all_result_a":"Infected","threat_name":"Trojan.X"}}""";
            using var md = new MetaDefenderProvider(Client(HttpStatusCode.OK, json), "key");
            var result = NewResult();
            await md.LookupAsync(result, new LookupRequest(result.Path), CancellationToken.None);
            Equal("detected", result.Status);
            Equal(3, result.Suspicious);
            Equal(ProviderState.Detected, Row(result, "MetaDefender").State);
            True(Row(result, "MetaDefender").Detail.Contains("Trojan.X"));
        })),
        ("MetaDefender: 404 means hash not found", () => Run(async () =>
        {
            using var md = new MetaDefenderProvider(Client(HttpStatusCode.NotFound, "{}"), "key");
            var result = NewResult();
            await md.LookupAsync(result, new LookupRequest(result.Path), CancellationToken.None);
            Equal(ProviderState.Unknown, Row(result, "MetaDefender").State);
        })),
        ("MetaDefender: without a key nothing is sent", () => Run(async () =>
        {
            var handler = new FakeHandler(HttpStatusCode.OK, "{}");
            using var md = new MetaDefenderProvider(new HttpClient(handler), "");
            var result = NewResult();
            await md.LookupAsync(result, new LookupRequest(result.Path), CancellationToken.None);
            Equal(0, handler.Calls);
            Equal(ProviderState.NotChecked, Row(result, "MetaDefender").State);
        })),
        ("VirusTotal: report with detections", () => Run(async () =>
        {
            var json = """{"data":{"attributes":{"last_analysis_stats":{"malicious":5,"suspicious":1,"harmless":0,"undetected":60}}}}""";
            using var vt = new VirusTotalProvider(VtClient(HttpStatusCode.OK, json), Unpaced());
            var result = NewResult();
            await vt.LookupAsync(result, new LookupRequest(result.Path), CancellationToken.None);
            Equal("detected", result.Status);
            Equal(5, result.Malicious);
            Equal(ProviderState.Detected, Row(result, "VirusTotal").State);
        })),
        ("VirusTotal: unknown hash offers upload only when the file exists", () => Run(async () =>
        {
            var file = Path.GetTempFileName();
            try
            {
                using var vt = new VirusTotalProvider(VtClient(HttpStatusCode.NotFound, """{"error":{"code":"NotFoundError"}}"""), Unpaced());
                var present = new ScanResult(file, "x.exe", "1") { Sha256 = Sha };
                await vt.LookupAsync(present, new LookupRequest(file), CancellationToken.None);
                Equal("unknown", present.Status);
                True(present.NeedsVirusTotalUpload);

                var gone = NewResult();
                await vt.LookupAsync(gone, new LookupRequest(gone.Path), CancellationToken.None);
                False(gone.NeedsVirusTotalUpload);
            }
            finally
            {
                File.Delete(file);
            }
        })),
        ("VirusTotal: a server error is recorded, not thrown", () => Run(async () =>
        {
            using var vt = new VirusTotalProvider(VtClient(HttpStatusCode.InternalServerError, "boom"), Unpaced());
            var result = NewResult();
            await vt.LookupAsync(result, new LookupRequest(result.Path), CancellationToken.None);
            Equal(ProviderState.Error, Row(result, "VirusTotal").State);
            True(result.Notes.Contains("VirusTotal lookup failed"));
        })),
        ("VirusTotal: a 401 tells the user to check the key", () => Run(async () =>
        {
            using var vt = new VirusTotalProvider(VtClient(HttpStatusCode.Unauthorized, "{}"), Unpaced());
            var result = NewResult();
            await vt.LookupAsync(result, new LookupRequest(result.Path), CancellationToken.None);
            True(Row(result, "VirusTotal").Detail.Contains("Verify the saved API key"));
        })),
        ("VirusTotal: free quota reached defers the lookup without a request", () => Run(async () =>
        {
            var handler = new FakeHandler(HttpStatusCode.OK, "{}");
            var http = new HttpClient(handler);
            http.DefaultRequestHeaders.Add("x-apikey", "k");
            var pacer = new VirusTotalPacer(true, TimeSpan.Zero, () => Task.FromResult(new QuotaReservation(false, "daily")), NoWait);
            using var vt = new VirusTotalProvider(http, pacer);
            var result = NewResult();
            await vt.LookupAsync(result, new LookupRequest(result.Path), CancellationToken.None);
            Equal(0, handler.Calls);
            True(result.VirusTotalDeferred);
            Equal(ProviderState.Deferred, Row(result, "VirusTotal").State);
        })),
        ("VirusTotal pacer: waits out a full minute window once", () => Run(async () =>
        {
            var waits = new List<TimeSpan>();
            var answers = new Queue<QuotaReservation>([new(false, "minute"), new(true, "")]);
            var pacer = new VirusTotalPacer(true, TimeSpan.Zero, () => Task.FromResult(answers.Dequeue()),
                (span, _) => { waits.Add(span); return Task.CompletedTask; });
            True(await pacer.TryReserveAsync(null, waitForMinuteSlot: true, CancellationToken.None));
            Equal(1, waits.Count);
            Equal(TimeSpan.FromSeconds(16), waits[0]);
        })),
        ("VirusTotal pacer: unpaced lookups never touch the quota", () => Run(async () =>
        {
            var reserved = 0;
            var pacer = new VirusTotalPacer(false, TimeSpan.Zero, () => { reserved++; return Task.FromResult(new QuotaReservation(true, "")); }, NoWait);
            using (await pacer.EnterAsync(CancellationToken.None))
            {
                await pacer.WaitForSpacingAsync(CancellationToken.None);
            }

            True(await pacer.TryReserveAsync(null, false, CancellationToken.None));
            Equal(0, reserved);
        })),
        ("VirusTotal pacer: lookups take turns", () => Run(async () =>
        {
            var pacer = new VirusTotalPacer(false, TimeSpan.FromSeconds(1), null, NoWait);
            var first = await pacer.EnterAsync(CancellationToken.None);
            var second = pacer.EnterAsync(CancellationToken.None);
            await Task.Delay(50);
            False(second.IsCompleted);
            first.Dispose();
            first.Dispose(); // a second dispose must not free an extra turn
            (await second).Dispose();
        })),
        ("Cymru: a registry match counts as malicious", () => Run(async () =>
        {
            var cymru = new CymruProvider((_, _) => Task.FromResult<CymruReputation?>(new(DateTimeOffset.Parse("2026-01-02T00:00:00Z"), 40)));
            var result = NewResult();
            await cymru.LookupAsync(result, new LookupRequest(result.Path), CancellationToken.None);
            Equal(1, result.Malicious);
            Equal("detected", result.Status);
            True(Row(result, "Cymru MHR").Detail.Contains("40%"));
        })),
        ("Cymru: no match is clean; cancellation still throws", () => Run(async () =>
        {
            var clean = new CymruProvider((_, _) => Task.FromResult<CymruReputation?>(null));
            var result = NewResult();
            await clean.LookupAsync(result, new LookupRequest(result.Path), CancellationToken.None);
            Equal(ProviderState.Clean, Row(result, "Cymru MHR").State);

            var cancelled = new CymruProvider((_, ct) => Task.FromCanceled<CymruReputation?>(new CancellationToken(true)));
            var threw = false;
            try
            {
                await cancelled.LookupAsync(NewResult(), new LookupRequest("x"), CancellationToken.None);
            }
            catch (OperationCanceledException)
            {
                threw = true;
            }

            True(threw);
        })),
        ("Analyzer: with no providers the file is unknown", () => Run(async () =>
        {
            var analyzer = Analyzer([], new AnalyzerSettings { HashCacheEnabled = false });
            var result = await analyzer.AnalyzeAsync(@"C:\nowhere\tool.exe", [new ProcessFile(42, "tool.exe", @"C:\nowhere\tool.exe")]);
            Equal("unknown", result.Status);
            Equal(Sha, result.Sha256);
            Equal("42", result.Pids);
            Equal(ProviderState.Unknown, Row(result, "Local").State);
            True(result.Notes.Contains("unsigned"));
        })),
        ("Analyzer: runs every provider and aggregates the verdict", () => Run(async () =>
        {
            var calls = new List<string>();
            var analyzer = Analyzer(
                [new StubProvider("A", ProviderState.Clean, calls), new StubProvider("B", ProviderState.Unknown, calls)],
                new AnalyzerSettings { HashCacheEnabled = false });
            var result = await analyzer.AnalyzeAsync(@"C:\nowhere\tool.exe", []);
            Equal("A,B", string.Join(",", calls));
            Equal("clean", result.Status);
        })),
        ("Analyzer: an ignored hash is marked ignored and keeps its verdict", () => Run(async () =>
        {
            var calls = new List<string>();
            var analyzer = Analyzer(
                [new StubProvider("A", ProviderState.Detected, calls, malicious: 2)],
                new AnalyzerSettings { HashCacheEnabled = false, IgnoredHashes = new HashSet<string>([Sha], StringComparer.OrdinalIgnoreCase) });
            var result = await analyzer.AnalyzeAsync(@"C:\nowhere\tool.exe", []);
            Equal("ignored", result.Status);
            Equal("detected", result.StatusBeforeIgnore);
            False(result.IsAlert);
        })),
        ("Analyzer: a hashing failure becomes an error result", () => Run(async () =>
        {
            var analyzer = new FileAnalyzer(new HashCache(), [], new AnalyzerSettings { HashCacheEnabled = false },
                _ => new SignatureInfo(SignatureReader.UnsignedSummary, ""),
                (_, _) => throw new IOException("locked"));
            var result = await analyzer.AnalyzeAsync(@"C:\nowhere\tool.exe", []);
            Equal("error", result.Status);
            True(result.Notes.StartsWith("locked"));
        })),
        ("Analyzer: auto-start entries are recorded as persistence", () => Run(async () =>
        {
            var analyzer = Analyzer([], new AnalyzerSettings { HashCacheEnabled = false });
            var result = await analyzer.AnalyzeAsync(@"C:\nowhere\tool.exe", [new ProcessFile(0, "Run key: Tool", @"C:\nowhere\tool.exe")]);
            Equal("Run key: Tool", string.Join("|", result.PersistenceSources));
            True(result.Notes.Contains("starts automatically"));
        })),
        ("Risk: malicious files score high; trusted publishers lower the score", () =>
        {
            var bad = new ScanResult(@"C:\Users\x\Downloads\bad.exe", "bad.exe", "1") { Malicious = 2, SignatureSummary = SignatureReader.UnsignedSummary };
            RiskScorer.Apply(bad, []);
            Equal("High", bad.RiskLevel);

            var signed = new ScanResult(@"D:\Tools\tool.exe", "tool.exe", "1") { SignatureSummary = "Signed by Contoso; chain valid", SignaturePublisher = "Contoso", FileAgeDays = 30 };
            RiskScorer.Apply(signed, ["Contoso"]);
            Equal(0, signed.RiskScore);
            True(signed.TrustSummary.Contains("trusted publisher: Contoso"));
        }),
    ];

    private static ScanResult NewResult() => new(@"C:\nowhere\x.exe", "x.exe", "1") { Sha256 = Sha };

    private static ProviderResult Row(ScanResult result, string provider) =>
        result.ProviderResults.Single(r => r.Provider == provider);

    private static FileAnalyzer Analyzer(IReadOnlyList<IReputationProvider> providers, AnalyzerSettings settings) =>
        new(new HashCache(), providers, settings, _ => new SignatureInfo(SignatureReader.UnsignedSummary, ""), (_, _) => Task.FromResult(Sha));

    private static VirusTotalPacer Unpaced() => new(false, TimeSpan.Zero, null, NoWait);

    private static Task NoWait(TimeSpan _, CancellationToken __) => Task.CompletedTask;

    private static HttpClient Client(HttpStatusCode code, string body) => new(new FakeHandler(code, body));

    private static HttpClient VtClient(HttpStatusCode code, string body)
    {
        var http = Client(code, body);
        http.DefaultRequestHeaders.Add("x-apikey", "k");
        return http;
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

    private sealed class FakeHandler(HttpStatusCode code, string body) : HttpMessageHandler
    {
        public int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(code) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }

    private sealed class StubProvider(string name, ProviderState state, List<string> calls, int malicious = 0) : IReputationProvider
    {
        public string Name => name;

        public Task LookupAsync(ScanResult result, LookupRequest request, CancellationToken cancellationToken)
        {
            calls.Add(name);
            result.Malicious = Math.Max(result.Malicious, malicious);
            result.SetProviderResult(name, state, "");
            return Task.CompletedTask;
        }
    }
}
