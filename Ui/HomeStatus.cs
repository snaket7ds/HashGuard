using System.Drawing;

namespace HashGuardScanner;

/// <summary>Where HashGuard's tray pop-up goes: bottom-right of the working area, inside it.</summary>
internal static class PopupPlacement
{
    public static Point BottomRight(Rectangle workingArea, Size size, int margin) =>
        new(
            Math.Max(workingArea.Left, workingArea.Right - size.Width - margin),
            Math.Max(workingArea.Top, workingArea.Bottom - size.Height - margin));
}

internal enum HomeTone
{
    Protected,
    Scanning,
    Attention,
    Danger,
    NotScanned,
}

internal sealed record HomeStatus(HomeTone Tone, string Title, string Subtitle, string SourcesChip, string LastScanChip);

/// <summary>
/// The Home hero's words, worked out from plain numbers so they are unit-tested: one headline,
/// one sentence, and the two chips ("Last scan …", "N reputation sources online").
/// </summary>
internal static class HomeStatusText
{
    public static HomeStatus Build(
        bool scanning,
        int threats,
        int needsDecision,
        int sourcesOn,
        int sourcesTotal,
        DateTime? lastScanLocal,
        DateTime nowLocal,
        bool firewallOn)
    {
        var sources = sourcesOn >= sourcesTotal
            ? $"{sourcesOn} reputation sources online"
            : $"{sourcesOn} of {sourcesTotal} reputation sources";
        var last = FormatLastScan(lastScanLocal, nowLocal);
        var protections = firewallOn ? "Antivirus and firewall are on." : "Antivirus is on. The firewall monitor is off.";

        if (scanning)
        {
            return new HomeStatus(HomeTone.Scanning, "Scanning", "Checking your running apps with your reputation sources.", sources, last);
        }

        if (threats > 0)
        {
            return new HomeStatus(
                HomeTone.Danger,
                threats == 1 ? "1 threat needs your attention" : $"{threats} threats need your attention",
                "Security vendors flag a file on this PC. Quarantine moves it somewhere it can't run, and you can restore it later.",
                sources,
                last);
        }

        if (needsDecision > 0)
        {
            return new HomeStatus(
                HomeTone.Attention,
                needsDecision == 1 ? "1 file needs your decision" : $"{needsDecision} files need your decision",
                "Nothing is flagged as malware, but HashGuard couldn't confirm these files are safe.",
                sources,
                last);
        }

        if (lastScanLocal is null)
        {
            return new HomeStatus(HomeTone.NotScanned, "Not scanned yet", $"{protections} Run a scan to check the apps on this PC.", sources, last);
        }

        return sourcesOn == 0
            ? new HomeStatus(HomeTone.Attention, "Turn on a reputation source", "No reputation source is enabled, so HashGuard can only use local checks. Turn one on in Settings → Reputation.", sources, last)
            : new HomeStatus(HomeTone.Protected, "You're protected", $"{protections} The last scan found nothing that needs you.", sources, last);
    }

    public static string FormatLastScan(DateTime? lastScanLocal, DateTime nowLocal)
    {
        if (lastScanLocal is not { } last)
        {
            return "No scan yet";
        }

        var time = last.ToString("HH:mm", System.Globalization.CultureInfo.CurrentCulture);
        if (last.Date == nowLocal.Date)
        {
            return $"Last scan today {time}";
        }

        if (last.Date == nowLocal.Date.AddDays(-1))
        {
            return $"Last scan yesterday {time}";
        }

        return $"Last scan {last.ToString("MMM d", System.Globalization.CultureInfo.CurrentCulture)}";
    }

    /// <summary>Sidebar badge text: empty for zero, "99+" above 99.</summary>
    public static string BadgeText(int count) => count <= 0 ? "" : count > 99 ? "99+" : count.ToString(System.Globalization.CultureInfo.InvariantCulture);
}
