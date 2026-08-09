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
