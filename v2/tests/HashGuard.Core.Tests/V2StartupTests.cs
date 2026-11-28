using HashGuard.Core;

/// <summary>Tests for v2's launch arguments and single-instance hand-over.</summary>
internal static class V2StartupTests
{
    public static (string Name, Action Test)[] All =>
    [
        ("Launch: arguments map to requests, as v1's task and Explorer pass them", () =>
        {
            Equal(new LaunchRequest(LaunchKind.Show), LaunchRequest.Parse([]));
            Equal(new LaunchRequest(LaunchKind.Minimized), LaunchRequest.Parse(["--minimized"]));
            Equal(new LaunchRequest(LaunchKind.ScheduledScan), LaunchRequest.Parse(["--scheduled-scan", "--minimized"]));
            Equal(new LaunchRequest(LaunchKind.ScanFile, @"C:\a b\x.exe"), LaunchRequest.Parse(["--scan-file", @"C:\a b\x.exe"]));
            Equal(new LaunchRequest(LaunchKind.Show), LaunchRequest.Parse(["--scan-file"]));
        }),
        ("App folder: the exe's folder, never the single-file unpack folder", () =>
        {
            // The release exe unpacks to %TEMP%\.net\HashGuard\<id>\ and AppContext.BaseDirectory
            // points there; config, keys and logs must still come from next to HashGuard.exe.
            Equal(@"C:\Program Files\HashGuard", AppPaths.ResolveAppFolder(@"C:\Program Files\HashGuard\HashGuard.exe", @"C:\Users\u\AppData\Local\Temp\.net\HashGuard\O9DwFBnLz8NK\"));
            Equal(@"D:\tools\bin\", AppPaths.ResolveAppFolder(@"C:\Program Files\dotnet\dotnet.exe", @"D:\tools\bin\"));
            Equal(@"D:\tools\bin\", AppPaths.ResolveAppFolder(null, @"D:\tools\bin\"));
            Equal(Path.GetDirectoryName(Environment.ProcessPath!), AppPaths.AppFolder);
            Equal(Path.Combine(AppPaths.AppFolder, "config"), AppPaths.GetConfigDirectory());
        }),
        ("Launch: messages round-trip; junk is refused", () =>
        {
            foreach (var request in new[] { new LaunchRequest(LaunchKind.Show), new LaunchRequest(LaunchKind.Minimized), new LaunchRequest(LaunchKind.ScheduledScan), new LaunchRequest(LaunchKind.ScanFile, @"C:\x.exe") })
            {
                Equal(request, LaunchRequest.FromMessage(request.ToMessage()));
            }

            Equal<LaunchRequest?>(null, LaunchRequest.FromMessage("format c:"));
            Equal<LaunchRequest?>(null, LaunchRequest.FromMessage("scan-file\t"));
            Equal<LaunchRequest?>(null, LaunchRequest.FromMessage(""));
            Equal<LaunchRequest?>(null, LaunchRequest.FromMessage(new string('a', 5000)));
        }),
        ("Single instance: a second claim fails and its request reaches the first", () =>
        {
            var name = $"HashGuard.test.{Guid.NewGuid():N}";
            using var first = SingleInstance.TryClaim(name)!;
            True(first is not null);
            Equal<SingleInstance?>(null, SingleInstance.TryClaim(name));

            using var received = new ManualResetEventSlim();
            LaunchRequest? got = null;
            first!.Listen(request =>
            {
                got = request;
                received.Set();
            });
            True(SingleInstance.TrySend(new LaunchRequest(LaunchKind.ScanFile, @"C:\x.exe"), name));
            True(received.Wait(TimeSpan.FromSeconds(5)));
            Equal(new LaunchRequest(LaunchKind.ScanFile, @"C:\x.exe"), got);
        }),
        ("Single instance: the claim ends when the first copy closes", () =>
        {
            var name = $"HashGuard.test.{Guid.NewGuid():N}";
            SingleInstance.TryClaim(name)!.Dispose();
            using var again = SingleInstance.TryClaim(name);
            True(again is not null);
            False(SingleInstance.TrySend(new LaunchRequest(LaunchKind.Show), $"HashGuard.test.{Guid.NewGuid():N}", TimeSpan.FromMilliseconds(200)));
        }),
        ("Legacy: 1.x builds count as v1; 2.x and versionless files don't", () =>
        {
            True(LegacyHashGuard.IsLegacy(1, "1.0.64+cd7cde4"));
            True(LegacyHashGuard.IsLegacy(0, "1.1.8"));
            False(LegacyHashGuard.IsLegacy(2, "2.0.0-alpha.1"));
            False(LegacyHashGuard.IsLegacy(0, null));
            False(LegacyHashGuard.IsLegacy(0, ""));
        }),
        ("Signatures: Windows catalog-signed files (notepad.exe) are signed by Microsoft", () =>
        {
            var notepad = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "notepad.exe");
            var signature = SignatureReader.ReadUncached(notepad);
            True(signature.Summary.StartsWith("Signed by Microsoft", StringComparison.Ordinal));
            True(HashGuardLogic.SignatureChainValid(signature.Summary));
        }),
        ("Signatures: embedded signatures verify; a changed copy doesn't; plain files are unsigned", () =>
        {
            var embedded = new[] { Environment.ProcessPath!, Path.Combine(AppContext.BaseDirectory, "HashGuard.Core.dll") }
                .Concat(Directory.GetFiles(Path.GetDirectoryName(typeof(object).Assembly.Location)!, "*.dll").Take(40))
                .FirstOrDefault(path => SignatureReader.ReadUncached(path) is { } s && HashGuardLogic.SignatureChainValid(s.Summary) && !s.Summary.Contains(SignatureReader.CatalogNote))
                ?? throw new InvalidOperationException("No file with a valid embedded signature found.");

            var dir = Directory.CreateTempSubdirectory("hg-sig").FullName;
            try
            {
                var copy = Path.Combine(dir, "changed" + Path.GetExtension(embedded));
                var bytes = File.ReadAllBytes(embedded);
                bytes[bytes.Length / 3] ^= 0xFF;
                File.WriteAllBytes(copy, bytes);
                Equal(SignatureReader.MismatchSummary, SignatureReader.ReadUncached(copy).Summary);

                var plain = Path.Combine(dir, "plain.txt");
                File.WriteAllText(plain, "hello");
                Equal(SignatureReader.UnsignedSummary, SignatureReader.ReadUncached(plain).Summary);
            }
            finally
            {
                Directory.Delete(dir, true);
            }
        }),
        ("Legacy: this test process is never reported", () =>
        {
            True(LegacyHashGuard.FindRunning().All(p => p.Pid != Environment.ProcessId));
        }),
    ];

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
