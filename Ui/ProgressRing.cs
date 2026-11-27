using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace HashGuardScanner;

/// <summary>A round progress indicator with the percentage in the middle (Scan page).</summary>
internal sealed class ProgressRing : Control
{
    private int value;
    private int maximum = 100;

    public ProgressRing()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.UserPaint | ControlStyles.SupportsTransparentBackColor, true);
        BackColor = Color.Transparent;
        Size = new Size(116, 116);
        Font = new Font("Segoe UI Semibold", 18, FontStyle.Regular);
        AccessibleRole = AccessibleRole.ProgressBar;
    }

    public Color TrackColor { get; set; } = Color.FromArgb(238, 240, 243);
    public Color FillColor { get; set; } = Color.FromArgb(24, 134, 74);
    public Color TextColor { get; set; } = Color.FromArgb(17, 24, 39);
    /// <summary>Text shown when idle (no scan running), e.g. "Ready".</summary>
    public string IdleText { get; set; } = "";
    public bool Running { get; set; }

    public int Maximum
    {
        get => maximum;
        set { maximum = Math.Max(1, value); Invalidate(); }
    }

    public int Value
    {
        get => value;
        set { this.value = Math.Clamp(value, 0, maximum); AccessibleDescription = $"{Percent} percent"; Invalidate(); }
    }

    public int Percent => (int)Math.Round(100.0 * value / Math.Max(1, maximum));

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        const float stroke = 11f;
        var size = Math.Min(Width, Height) - stroke - 2;
        var rect = new RectangleF((Width - size) / 2f, (Height - size) / 2f, size, size);
        using var track = new Pen(TrackColor, stroke);
        g.DrawEllipse(track, rect);
        if (Running && value > 0)
        {
            using var fill = new Pen(FillColor, stroke) { StartCap = LineCap.Round, EndCap = LineCap.Round };
            g.DrawArc(fill, rect, -90, 360f * value / maximum);
        }

        var text = Running ? $"{Percent}%" : IdleText;
        TextRenderer.DrawText(g, text, Font, ClientRectangle, TextColor,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.NoPadding);
    }
}
