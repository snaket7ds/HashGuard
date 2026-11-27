using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace HashGuardScanner;

internal static class RoundedPaint
{
    public static GraphicsPath RoundedRect(RectangleF rect, float radius)
    {
        var path = new GraphicsPath();
        var d = Math.Max(0, Math.Min(radius * 2, Math.Min(rect.Width, rect.Height)));
        if (d <= 0)
        {
            path.AddRectangle(rect);
            return path;
        }

        path.AddArc(rect.X, rect.Y, d, d, 180, 90);
        path.AddArc(rect.Right - d, rect.Y, d, d, 270, 90);
        path.AddArc(rect.Right - d, rect.Bottom - d, d, d, 0, 90);
        path.AddArc(rect.X, rect.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        return path;
    }

    public static void FillRounded(Graphics graphics, RectangleF rect, float radius, Color color)
    {
        graphics.SmoothingMode = SmoothingMode.AntiAlias;
        using var path = RoundedRect(rect, radius);
        using var brush = new SolidBrush(color);
        graphics.FillPath(brush, path);
    }
}

/// <summary>
/// Rounded surface card. Paints its own surface over the app background (BackColor), so
/// child controls with a transparent background show the card through them. Clickable
/// cards highlight on hover and on press, before the click fires.
/// </summary>
internal sealed class CardPanel : Panel
{
    private bool hover;
    private bool pressed;

    public CardPanel()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.UserPaint, true);
        Tag = "soft-card";
    }

    public int Radius { get; set; } = 12;
    public Color SurfaceColor { get; set; } = Color.White;
    public Color HoverColor { get; set; } = Color.FromArgb(247, 248, 250);
    public Color PressedColor { get; set; } = Color.FromArgb(238, 240, 243);
    public Color EdgeColor { get; set; } = Color.FromArgb(232, 235, 238);
    public Color ShadowColor { get; set; } = Color.FromArgb(16, 16, 24, 40);
    /// <summary>Edge thickness; 2 with the accent colour marks the selected card (Scan page scan types).</summary>
    public float EdgeWidth { get; set; } = 1;
    public bool Interactive { get; private set; }

    public void MakeInteractive()
    {
        Interactive = true;
        WireHover(this);
    }

    private void WireHover(Control control)
    {
        control.MouseEnter += (_, _) => SetHover(true);
        control.MouseLeave += (_, _) => SetHover(RectangleToScreen(ClientRectangle).Contains(Cursor.Position));
        control.MouseDown += (_, e) =>
        {
            if (e.Button == MouseButtons.Left)
            {
                pressed = true;
                Invalidate();
            }
        };
        control.MouseUp += (_, _) =>
        {
            pressed = false;
            Invalidate();
        };
        foreach (Control child in control.Controls)
        {
            WireHover(child);
        }
    }

    private void SetHover(bool value)
    {
        if (hover == value)
        {
            return;
        }

        hover = value;
        if (!hover)
        {
            pressed = false;
        }

        Invalidate(true);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        var inset = EdgeWidth / 2f;
        var rect = new RectangleF(inset, inset, Width - 1f - EdgeWidth, Height - 2.5f - EdgeWidth);
        if (rect.Width <= 0 || rect.Height <= 0)
        {
            return;
        }

        // Two-step soft drop shadow, then a hairline edge, then the surface.
        if (ShadowColor.A > 0)
        {
            using var far = RoundedPaint.RoundedRect(new RectangleF(rect.X, rect.Y + 2, rect.Width, rect.Height), Radius);
            using var farBrush = new SolidBrush(Color.FromArgb(ShadowColor.A / 2, ShadowColor));
            g.FillPath(farBrush, far);
            using var near = RoundedPaint.RoundedRect(new RectangleF(rect.X, rect.Y + 1, rect.Width, rect.Height), Radius);
            using var nearBrush = new SolidBrush(ShadowColor);
            g.FillPath(nearBrush, near);
        }

        var fill = Interactive && pressed ? PressedColor : Interactive && hover ? HoverColor : SurfaceColor;
        using var path = RoundedPaint.RoundedRect(rect, Radius);
        using var brush = new SolidBrush(fill);
        g.FillPath(brush, path);
        using var edge = new Pen(EdgeColor, EdgeWidth);
        g.DrawPath(edge, path);
    }
}

/// <summary>A rounded tinted square holding one Segoe MDL2 Assets glyph.</summary>
internal sealed class IconBadge : Control
{
    public IconBadge(string glyph, string tone)
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.UserPaint | ControlStyles.SupportsTransparentBackColor, true);
        Text = glyph;
        Tag = tone;
        BackColor = Color.Transparent;
        Size = new Size(34, 34);
        Font = UiFonts.Create("Segoe MDL2 Assets", 12, FontStyle.Regular);
    }

    public Color TintColor { get; set; } = Color.FromArgb(237, 247, 227);
    public Color GlyphColor { get; set; } = Color.FromArgb(46, 122, 16);
    public int Radius { get; set; } = 9;

    protected override void OnPaint(PaintEventArgs e)
    {
        RoundedPaint.FillRounded(e.Graphics, new RectangleF(0, 0, Width - 1, Height - 1), Radius, TintColor);
        if (LineIcons.IsIcon(Text))
        {
            var size = Math.Min(Width, Height) * 0.52f;
            LineIcons.Draw(e.Graphics, Text, new RectangleF((Width - size) / 2f, (Height - size) / 2f, size, size), GlyphColor);
            return;
        }

        TextRenderer.DrawText(e.Graphics, Text, Font, ClientRectangle, GlyphColor,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding | TextFormatFlags.SingleLine);
    }
}

/// <summary>A label drawn as a rounded pill (count badges, stat chips).</summary>
internal sealed class PillLabel : Label
{
    public PillLabel()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.UserPaint | ControlStyles.SupportsTransparentBackColor, true);
        BackColor = Color.Transparent;
    }

    public Color PillColor { get; set; } = Color.FromArgb(247, 248, 250);
    public int Radius { get; set; } = 10;
    /// <summary>A small status dot before the text (provider chips); Empty = none. Use Padding.Left ≥ 24.</summary>
    public Color DotColor { get; set; } = Color.Empty;
    /// <summary>A 14px line icon (LineIcons name, e.g. "activity" = clock) before the text; null = none. Use Padding.Left ≥ 30.</summary>
    public string? Icon { get; set; }

    protected override void OnPaint(PaintEventArgs e)
    {
        RoundedPaint.FillRounded(e.Graphics, new RectangleF(0, 0, Width - 1, Height - 1), Math.Min(Radius, Height / 2f), PillColor);
        if (!DotColor.IsEmpty)
        {
            e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            using var dot = new SolidBrush(DotColor);
            e.Graphics.FillEllipse(dot, 11, (Height - 7) / 2f, 7, 7);
        }
        else if (Icon is { } icon)
        {
            LineIcons.Draw(e.Graphics, LineIcons.Prefix + icon, new RectangleF(10, (Height - 14) / 2f, 14, 14), ForeColor);
        }

        var flags = TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis;
        flags |= TextAlign is ContentAlignment.MiddleCenter or ContentAlignment.TopCenter or ContentAlignment.BottomCenter
            ? TextFormatFlags.HorizontalCenter
            : TextFormatFlags.Left;
        var bounds = new Rectangle(Padding.Left, 0, Math.Max(0, Width - Padding.Horizontal), Height);
        TextRenderer.DrawText(e.Graphics, Text, Font, bounds, ForeColor, flags);
    }
}

/// <summary>A rounded tinted square with an app's first letter (Firewall detail card, as designed).</summary>
internal sealed class LetterTile : Control
{
    public LetterTile()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.UserPaint | ControlStyles.SupportsTransparentBackColor, true);
        BackColor = Color.Transparent;
        Size = new Size(48, 48);
        Font = UiFonts.Create("Segoe UI Bold", 14, FontStyle.Bold);
    }

    public Color TintColor { get; set; } = Color.FromArgb(232, 239, 253);
    public Color InkColor { get; set; } = Color.FromArgb(36, 87, 197);
    public int Radius { get; set; } = 13;

    protected override void OnPaint(PaintEventArgs e)
    {
        RoundedPaint.FillRounded(e.Graphics, new RectangleF(0, 0, Width - 1, Height - 1), Radius, TintColor);
        TextRenderer.DrawText(e.Graphics, Text, Font, ClientRectangle, InkColor,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);
    }
}

internal static class TextWrap
{
    /// <summary>
    /// Wraps text at any character to fit <paramref name="width"/> (paths have no spaces to break at),
    /// as the design's "word-break: break-all". At most <paramref name="maxLines"/>; the last one ends in "…".
    /// </summary>
    public static string Anywhere(string text, Font font, int width, int maxLines = 3)
    {
        if (string.IsNullOrEmpty(text) || width <= 20)
        {
            return text;
        }

        var lines = new List<string>();
        var start = 0;
        while (start < text.Length && lines.Count < maxLines)
        {
            var length = 1;
            while (start + length < text.Length
                && TextRenderer.MeasureText(text.Substring(start, length + 1), font, Size.Empty, TextFormatFlags.NoPadding | TextFormatFlags.NoPrefix).Width <= width)
            {
                length++;
            }

            lines.Add(text.Substring(start, length));
            start += length;
        }

        if (start < text.Length && lines.Count > 0)
        {
            var last = lines[^1];
            lines[^1] = (last.Length > 1 ? last[..^1] : last) + "…";
        }

        return string.Join(Environment.NewLine, lines);
    }
}

/// <summary>A small rounded grey tile (Scan page counts).</summary>
internal sealed class StatTile : Panel
{
    public StatTile()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.UserPaint, true);
        Tag = "stat-tile";
    }

    public Color TileColor { get; set; } = Color.FromArgb(247, 248, 250);

    protected override void OnPaintBackground(PaintEventArgs e)
    {
        e.Graphics.Clear(ToggleSwitch.SurfaceBehind(this));
        e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        RoundedPaint.FillRounded(e.Graphics, new RectangleF(0, 0, Width - 1, Height - 1), 12, TileColor);
    }
}
