using System.Drawing;
using System.Windows.Forms;

namespace HashGuardScanner;

/// <summary>
/// A borderless, always-on-top window just above the tray that holds one <see cref="AlertCard"/>.
/// It never takes focus away from what you are doing, closes itself after 20 seconds unless the
/// mouse is over it, and only one is open at a time.
/// </summary>
internal sealed class TrayPopup : Form
{
    public const int Margin16 = 16;
    private static TrayPopup? current;
    private readonly System.Windows.Forms.Timer lifetime = new() { Interval = 1000 };
    private int secondsLeft = 20;

    private TrayPopup(AlertCard card)
    {
        Card = card;
        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar = false;
        TopMost = true;
        StartPosition = FormStartPosition.Manual;
        BackColor = card.Surface;
        Text = "HashGuard";
        card.Location = Point.Empty;
        Controls.Add(card);
        card.SizeChanged += (_, _) => PlaceNearTray();
        card.Dismissed += (_, _) => Close();
        lifetime.Tick += (_, _) =>
        {
            if (Bounds.Contains(Cursor.Position))
            {
                secondsLeft = Math.Max(secondsLeft, 5);
                return;
            }

            if (--secondsLeft <= 0)
            {
                Close();
            }
        };
    }

    public AlertCard Card { get; }

    protected override bool ShowWithoutActivation => true;

    protected override CreateParams CreateParams
    {
        get
        {
            const int wsExToolWindow = 0x00000080;
            const int wsExTopmost = 0x00000008;
            var cp = base.CreateParams;
            cp.ExStyle |= wsExToolWindow | wsExTopmost;
            return cp;
        }
    }

    /// <summary>Bottom-right corner of the working area (just above a bottom taskbar).</summary>
    public static Point ComputeLocation(Rectangle workingArea, Size size, int margin) =>
        PopupPlacement.BottomRight(workingArea, size, margin);

    /// <summary>Shows the card above the tray, replacing any HashGuard pop-up already open.</summary>
    public static TrayPopup ShowCard(AlertCard card)
    {
        current?.Close();
        var popup = new TrayPopup(card);
        current = popup;
        popup.FormClosed += (_, _) =>
        {
            if (current == popup)
            {
                current = null;
            }
        };
        popup.PlaceNearTray();
        popup.Show();
        popup.lifetime.Start();
        return popup;
    }

    /// <summary>After the user acts on the card, keep the confirmation up for a few seconds.</summary>
    public void KeepForSeconds(int seconds) => secondsLeft = seconds;

    private void PlaceNearTray()
    {
        ClientSize = Card.Size;
        using (var path = RoundedPaint.RoundedRect(new RectangleF(0, 0, Card.Width, Card.Height), 16))
        {
            Region = new Region(path);
        }

        var screen = Screen.PrimaryScreen ?? Screen.FromPoint(Cursor.Position);
        Location = ComputeLocation(screen.WorkingArea, Size, Margin16);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            lifetime.Dispose();
        }

        base.Dispose(disposing);
    }
}
