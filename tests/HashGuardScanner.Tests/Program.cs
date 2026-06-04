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

return 0;

static void AssertEqual<T>(T expected, T actual)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
    {
        throw new InvalidOperationException($"expected '{expected}', got '{actual}'");
    }
}

static void AssertTrue(bool value)
{
    if (!value)
    {
        throw new InvalidOperationException("expected true");
    }
}

static void AssertFalse(bool value)
{
    if (value)
    {
        throw new InvalidOperationException("expected false");
    }
}
