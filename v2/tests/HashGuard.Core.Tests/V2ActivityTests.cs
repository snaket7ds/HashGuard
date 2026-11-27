using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HashGuard.Core;

/// <summary>Tests for v2's quarantine store, scan-history reader and Activity timeline.</summary>
internal static class V2ActivityTests
{
    private static readonly DateTimeOffset Clock = new(2026, 11, 27, 14, 30, 0, TimeSpan.Zero);

    public static (string Name, Action Test)[] All =>
    [
        ("Quarantine: moves the file, lists it and logs it in v1's format", () => WithTemp(dir =>
        {
            var file = Write(dir, "bad.exe", "payload");
            var store = Store(dir);
            var changed = 0;
            store.Changed += () => changed++;

            var entry = store.Quarantine(file, Sha("payload"), "Risk: high");
            False(File.Exists(file));
            True(File.Exists(entry.QuarantinePath));
            Equal("bad.exe.20261127143000.quarantine", Path.GetFileName(entry.QuarantinePath));
            Equal(1, store.RestorableCount);
            Equal(1, changed);

            var manifest = JsonSerializer.Deserialize<List<QuarantineEntry>>(File.ReadAllText(Path.Combine(dir, "manifest.json")))!;
            Equal(file, manifest.Single().OriginalPath);
            var log = File.ReadAllLines(Path.Combine(dir, "logs", "quarantine-log-20261127.csv"));
            Equal("timestamp_computer_time,action,source_path,target_path,details", log[0]);
            True(log[1].Contains("\"quarantine\""));
        })),
        ("Quarantine: a second file with the same name in the same second gets its own slot", () => WithTemp(dir =>
        {
            var store = Store(dir);
            var first = store.Quarantine(Write(Path.Combine(dir, "a"), "x.exe", "1"), "", "");
            var second = store.Quarantine(Write(Path.Combine(dir, "b"), "x.exe", "2"), "", "");
            True(first.QuarantinePath != second.QuarantinePath);
            Equal(2, store.Entries.Count);
        })),
        ("Quarantine: a missing file throws and changes nothing", () => WithTemp(dir =>
        {
            var store = Store(dir);
            Throws<FileNotFoundException>(() => store.Quarantine(Path.Combine(dir, "gone.exe"), "", ""));
            Equal(0, store.Entries.Count);
        })),
        ("Quarantine: v1's manifest is read and restored entries leave it", () => WithTemp(dir =>
        {
            var qdir = Path.Combine(dir, "q");
            Directory.CreateDirectory(qdir);
            var qfile = Path.Combine(qdir, "old.exe.20250101000000.quarantine");
            File.WriteAllText(qfile, "old");
            var original = Path.Combine(dir, "restored", "old.exe");
            File.WriteAllText(Path.Combine(dir, "manifest.json"), $$"""[{"OriginalPath":{{JsonSerializer.Serialize(original)}},"QuarantinePath":{{JsonSerializer.Serialize(qfile)}},"Sha256":"{{Sha("old")}}","Notes":"","QuarantinedAtUtc":"2025-01-01T00:00:00+00:00"}]""");

            var store = Store(dir);
            var entry = store.Entries.Single();
            Run(() => store.RestoreAsync(entry, original, replaceExisting: false));
            Equal("old", File.ReadAllText(original));
            Equal(0, store.Entries.Count);
            Equal(0, Store(dir).Entries.Count);
        })),
        ("Quarantine: restore refuses a changed file and an occupied target", () => WithTemp(dir =>
        {
            var store = Store(dir);
            var file = Write(dir, "app.exe", "v1");
            var entry = store.Quarantine(file, Sha("v1"), "");

            File.WriteAllText(file, "someone else's file");
            Throws<IOException>(() => Run(() => store.RestoreAsync(entry, file, replaceExisting: false)));

            File.WriteAllText(entry.QuarantinePath, "tampered");
            Throws<InvalidOperationException>(() => Run(() => store.RestoreAsync(entry, Path.Combine(dir, "other.exe"), replaceExisting: true)));
            Equal(1, store.Entries.Count);
        })),
        ("Quarantine: delete removes the file; repair drops entries whose file vanished", () => WithTemp(dir =>
        {
            var store = Store(dir);
            var kept = store.Quarantine(Write(dir, "a.exe", "a"), "", "");
            var vanished = store.Quarantine(Write(dir, "b.exe", "b"), "", "");
            File.Delete(vanished.QuarantinePath);
            Equal(1, store.RestorableCount);
            Equal(1, store.RemoveMissing());
            Equal(0, store.RemoveMissing());

            store.Delete(kept);
            False(File.Exists(kept.QuarantinePath));
            Equal(0, store.Entries.Count);
        })),
        ("Quarantine: Desktop restore picks a free name", () => WithTemp(dir =>
        {
            var entry = new QuarantineEntry { OriginalPath = @"C:\Tools\tool.exe" };
            Equal(Path.Combine(dir, "tool.exe"), QuarantineStore.DesktopRestorePath(entry, dir));
            File.WriteAllText(Path.Combine(dir, "tool.exe"), "");
            File.WriteAllText(Path.Combine(dir, "tool (1).exe"), "");
            Equal(Path.Combine(dir, "tool (2).exe"), QuarantineStore.DesktopRestorePath(entry, dir));
        })),
        ("Running processes: this test process is found by its executable", () =>
        {
            var exe = Environment.ProcessPath!;
            var pids = ProcessCollector.FindRunning(exe);
            // Paths on mapped drives come back as UNC, so a miss there is not a failure.
            True(pids.Contains(Environment.ProcessId) || exe.StartsWith(@"\\", StringComparison.Ordinal) || IsMappedDrive(exe));
            Equal(0, ProcessCollector.FindRunning(@"C:\definitely\not\running.exe").Count);
        }),
        ("Activity log: reads v1 and v2 rows newest first across files", () => WithTemp(dir =>
        {
            File.WriteAllLines(Path.Combine(dir, "scan-log-20261126.csv"),
            [
                ScanLog.Header,
                "\"2026-11-26 09:00:00\",\"clean\",\"0\",\"Low\",\"Signed\",\"\",\"0\",\"0\",\"60\",\"10\",\"a.exe\",\"1\",\"aa\",\"C:\\a.exe\",\"\",\"\"",
            ]);
            File.SetLastWriteTimeUtc(Path.Combine(dir, "scan-log-20261126.csv"), Clock.UtcDateTime.AddDays(-1));
            // An older v1 file whose header names the time column "timestamp".
            File.WriteAllLines(Path.Combine(dir, "scan-log-20261127.csv"),
            [
                "timestamp,status,malicious,suspicious,process_names,pids,sha256,path,notes",
                "2026-11-27 10:00:00,unknown,0,0,b.exe,2,bb,C:\\b.exe,first",
                "2026-11-27 11:00:00,clean,3,1,c.exe,3,cc,C:\\c.exe,\"has, comma\"",
            ]);

            var rows = new ActivityLogReader([dir]).Read();
            Equal(3, rows.Count);
            Equal("c.exe", rows[0].ProcessNames);
            Equal(3, rows[0].Malicious);
            Equal("has, comma", rows[0].Notes);
            Equal(new DateTime(2026, 11, 26, 9, 0, 0), rows[2].When);
            Equal("Low", rows[2].RiskLevel);
        })),
        ("Activity log: a large file is tail-read with its header kept", () => WithTemp(dir =>
        {
            var path = Path.Combine(dir, "big.csv");
            var lines = new List<string> { "status,path" };
            lines.AddRange(Enumerable.Range(0, 400).Select(i => $"clean,C:\\file{i:D4}.exe"));
            File.WriteAllLines(path, lines);

            var tail = ActivityLogReader.ReadLines(path, maxBytes: 200);
            Equal("status,path", tail[0]);
            Equal("clean,C:\\file0399.exe", tail.Last(line => line.Length > 0));
            True(tail.Skip(1).All(line => line.Length == 0 || line.StartsWith("clean,C:\\file", StringComparison.Ordinal)));
        })),
        ("Activity feed: a scan becomes one summary with clean rows folded", () =>
        {
            var start = new DateTime(2026, 11, 27, 9, 0, 0);
            var rows = new[]
            {
                Row(start, "clean", "a.exe"),
                Row(start.AddSeconds(20), "clean", "b.exe"),
                Row(start.AddSeconds(40), "unknown", "c.exe"),
                Row(start.AddHours(2), "clean", "later.exe"),
            };
            var feed = ActivityFeed.Build(rows, [], [], _ => false);

            Equal("later.exe is clean", feed[0].Title);
            var summary = feed[1];
            True(summary.Summary);
            Equal("3 files checked", summary.Title);
            Equal("2 clean · 1 unknown", summary.Detail);
            Equal(2, feed.Count(entry => entry.Folded));
            Equal(ActivityKind.Unknown, feed.Single(entry => entry.Title.StartsWith("c.exe", StringComparison.Ordinal)).Kind);
            False(feed.Single(entry => entry.Title.StartsWith("c.exe", StringComparison.Ordinal)).Folded);
        }),
        ("Activity feed: handled checks, quarantine and firewall rows", () =>
        {
            var when = new DateTime(2026, 11, 27, 9, 0, 0);
            var quarantined = new QuarantineEntry { OriginalPath = @"C:\q.exe", QuarantinePath = @"X:\q", QuarantinedAtUtc = new DateTimeOffset(when.AddMinutes(5)) };
            var feed = ActivityFeed.Build(
                [Row(when, "unknown", "q.exe", @"C:\q.exe")],
                [quarantined],
                ["2026-11-27 09:10:00\tBlocked outbound\tC:\\net.exe"],
                row => ActivityFeed.IsHandled(row, new HashSet<string>(), new HashSet<string>(), new HashSet<string>([quarantined.OriginalPath], StringComparer.OrdinalIgnoreCase)));

            Equal("Blocked net.exe in Windows Firewall", feed[0].Title);
            Equal("Quarantined q.exe", feed[1].Title);
            Equal(ActivityKind.Handled, feed[2].Kind);
        }),
        ("Activity feed: a check is handled when its hash is now ignored", () =>
        {
            var row = Row(DateTime.Now, "unknown", "x.exe") with { Sha256 = "ABC" };
            var hashes = new HashSet<string>(["abc"], StringComparer.OrdinalIgnoreCase);
            True(ActivityFeed.IsHandled(row, hashes, new HashSet<string>(), new HashSet<string>()));
            False(ActivityFeed.IsHandled(row, new HashSet<string>(), new HashSet<string>(), new HashSet<string>()));
        }),
        ("Activity view: batches fold until expanded; filters and search list rows on their own", () =>
        {
            var start = new DateTime(2026, 11, 27, 9, 0, 0);
            var feed = ActivityFeed.Build(
                [
                    Row(start, "clean", "a.exe"),
                    Row(start.AddSeconds(10), "clean", "b.exe"),
                    Row(start.AddSeconds(20), "unknown", "c.exe"),
                    Row(start.AddSeconds(30), "error", "d.exe"),
                    Row(start.AddSeconds(40), "unknown", "e.exe") with { Malicious = 2 },
                ],
                [new QuarantineEntry { OriginalPath = @"C:\q.exe", QuarantinePath = @"X:\q", QuarantinedAtUtc = new DateTimeOffset(start.AddHours(1)) }],
                [],
                _ => false);
            var none = new HashSet<int>();

            var all = ActivityFeed.Visible(feed, ActivityShow.All, null, none);
            Equal(5, all.Count); // quarantine, summary, c, d, e
            True(all.Any(entry => entry.Summary));
            Equal(7, ActivityFeed.Visible(feed, ActivityShow.All, "", new HashSet<int>([all.Single(e => e.Summary).BatchId])).Count);

            var action = ActivityFeed.Visible(feed, ActivityShow.NeedsAction, null, none);
            Equal(2, action.Count); // d (error) and e (malicious); c is only unknown
            Equal(1, ActivityFeed.Visible(feed, ActivityShow.Unknown, null, none).Count); // c; e has detections, so it's a threat
            Equal(1, ActivityFeed.Visible(feed, ActivityShow.Actions, null, none).Count);

            var search = ActivityFeed.Visible(feed, ActivityShow.All, "B.EXE", none);
            Equal("b.exe is clean", search.Single().Title);
        }),
    ];

    private static QuarantineStore Store(string dir) =>
        new(Path.Combine(dir, "q"), Path.Combine(dir, "manifest.json"), Path.Combine(dir, "logs")) { Now = () => Clock };

    private static ActivityLogRow Row(DateTime when, string status, string name, string? path = null) =>
        new(when, status, "", 0, "", "", 0, 0, name, "1", "", path ?? $@"C:\{name}", "", "");

    private static string Write(string dir, string name, string content)
    {
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, name);
        File.WriteAllText(path, content);
        return path;
    }

    private static string Sha(string content) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content)));

    private static bool IsMappedDrive(string path)
    {
        var root = Path.GetPathRoot(path);
        return root is not null && new DriveInfo(root).DriveType == DriveType.Network;
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

    private static void Throws<T>(Action action) where T : Exception
    {
        try
        {
            action();
        }
        catch (T)
        {
            return;
        }

        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }

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
}
