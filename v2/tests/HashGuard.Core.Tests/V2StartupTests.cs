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
