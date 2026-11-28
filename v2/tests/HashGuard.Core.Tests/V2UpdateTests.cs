using System.Net;
using System.Text;
using HashGuard.Core;

/// <summary>Tests for v2's updater, with a fake GitHub.</summary>
internal static class V2UpdateTests
{
    public static (string Name, Action Test)[] All =>
    [
        ("Updates: versions order numbers first, then releases above their previews", () =>
        {
            var ordered = new[] { "1.1.8", "2.0.0-alpha.1", "2.0.0-alpha.2", "2.0.0-beta.1", "2.0.0-beta.10", "v2.0.0", "2.0.1" }
                .Select(v => ReleaseVersion.TryParse(v)!)
                .ToList();
            for (var i = 1; i < ordered.Count; i++)
            {
                True(ordered[i].CompareTo(ordered[i - 1]) > 0);
            }

            Equal(0, ReleaseVersion.TryParse("2.0")!.CompareTo(ReleaseVersion.TryParse("v2.0.0+abc123")));
            Equal<ReleaseVersion?>(null, ReleaseVersion.TryParse("latest"));
            Equal("2.0.0-alpha.1", ReleaseVersion.TryParse("2.0.0-alpha.1+cd7cde4")!.ToString());
        }),
        ("Updates: a release build is offered releases only; a preview also previews", () =>
        {
            var json = Releases(("v1.1.8", false), ("v2.0.0-beta.1", false), ("v2.0.0-beta.2", true));
            Equal<UpdateOffer?>(null, Run(() => Service(json, "1.1.8").CheckAsync()));
            Equal("2.0.0-beta.1", Run(() => Service(json, "2.0.0-alpha.1").CheckAsync())!.Version.ToString());
            Equal<UpdateOffer?>(null, Run(() => Service(json, "2.0.0-beta.1").CheckAsync()));
        }),
        ("Updates: a beta build stays on beta, a release on stable, until Settings changes the channel", () =>
        {
            var beta = ReleaseVersion.TryParse("2.0.0-beta.1")!;
            var release = ReleaseVersion.TryParse("2.0.0")!;
            Equal(UpdateChannels.Beta, UpdateChannels.Effective("", beta));
            Equal(UpdateChannels.Stable, UpdateChannels.Effective(null, release));
            Equal(UpdateChannels.Stable, UpdateChannels.Effective("stable", beta));
            Equal(UpdateChannels.Beta, UpdateChannels.Effective(" Beta ", release));
            Equal(UpdateChannels.Beta, UpdateChannels.Effective("nightly", beta));

            var json = Releases(("v2.0.0", false), ("v2.0.1-beta.1", false), ("v2.0.0-beta.2", false));
            // A 2.0.0 release on stable isn't offered previews; switched to beta it is.
            Equal<UpdateOffer?>(null, Run(() => new UpdateService(Http(json), release, includePreviews: false).CheckAsync()));
            Equal("2.0.1-beta.1", Run(() => new UpdateService(Http(json), release, includePreviews: true).CheckAsync())!.Version.ToString());
            // A beta switched to stable is offered the full release only.
            Equal("2.0.0", Run(() => new UpdateService(Http(json), beta, includePreviews: false).CheckAsync())!.Version.ToString());
        }),
        ("Updates: a release without a signature or checksum is refused", () =>
        {
            const string unsigned = """[{"tag_name":"v9.0.0","draft":false,"body":"","assets":[{"name":"HashGuard.exe","browser_download_url":"https://x/exe","digest":"sha256:00"}]}]""";
            Throws<InvalidOperationException>(() => Run(() => Service(unsigned, "1.0.0").CheckAsync()));
            const string noSum = """[{"tag_name":"v9.0.0","draft":false,"body":"","assets":[{"name":"HashGuard.exe","browser_download_url":"https://x/exe"},{"name":"HashGuard.exe.sig","browser_download_url":"https://x/sig"}]}]""";
            Throws<InvalidOperationException>(() => Run(() => Service(noSum, "1.0.0").CheckAsync()));
        }),
        ("Updates: a download that doesn't match the checksum is deleted, not installed", () =>
        {
            var dir = Directory.CreateTempSubdirectory("hg-upd").FullName;
            try
            {
                var exe = Path.Combine(dir, "HashGuard.exe");
                File.WriteAllText(exe, "current");
                var offer = new UpdateOffer(ReleaseVersion.TryParse("9.0.0")!, "", "https://x/exe", new string('0', 64), null, "https://x/sig");
                var service = new UpdateService(new HttpClient(new Handler(_ => "new build")), ReleaseVersion.TryParse("1.0.0")!);
                Throws<InvalidOperationException>(() => Run(() => service.DownloadAsync(offer, exe)));
                False(File.Exists(Path.Combine(dir, "updates", "HashGuard.exe.new")));
            }
            finally
            {
                Directory.Delete(dir, true);
            }
        }),
        ("Updates: the swap script restores the old build if the copy fails", () =>
        {
            var script = UpdateService.BuildInstallScript(@"C:\HG\HashGuard.exe", @"C:\HG\updates\HashGuard.exe.new", @"C:\HG\HashGuard.exe.update-bak");
            True(script.Contains("copy /y \"C:\\HG\\HashGuard.exe.update-bak\" \"C:\\HG\\HashGuard.exe\""));
            True(script.Contains("start \"\" \"C:\\HG\\HashGuard.exe\""));
            True(script.IndexOf("exit /b 1", StringComparison.Ordinal) < script.IndexOf(":ok", StringComparison.Ordinal));
        }),
    ];

    private static UpdateService Service(string releasesJson, string current) =>
        new(new HttpClient(new Handler(_ => releasesJson)), ReleaseVersion.TryParse(current)!);

    private static HttpClient Http(string releasesJson) => new(new Handler(_ => releasesJson));

    private static string Releases(params (string Tag, bool Draft)[] releases) =>
        "[" + string.Join(",", releases.Select(r =>
            $$"""{"tag_name":"{{r.Tag}}","draft":{{(r.Draft ? "true" : "false")}},"body":"notes","assets":[{"name":"HashGuard.exe","browser_download_url":"https://x/{{r.Tag}}/exe","digest":"sha256:{{new string('a', 64)}}"},{"name":"HashGuard.exe.sig","browser_download_url":"https://x/{{r.Tag}}/sig"}]}""")) + "]";

    private sealed class Handler(Func<Uri, string> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(respond(request.RequestUri!), Encoding.UTF8) });
    }

    private static T Run<T>(Func<Task<T>> test) => test().GetAwaiter().GetResult();

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
