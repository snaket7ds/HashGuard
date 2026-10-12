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
        var rect = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 3f);
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
        using var edge = new Pen(EdgeColor, 1);
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
        Font = new Font("Segoe MDL2 Assets", 12, FontStyle.Regular);
    }

    public Color TintColor { get; set; } = Color.FromArgb(237, 247, 227);
    public Color GlyphColor { get; set; } = Color.FromArgb(46, 122, 16);
    public int Radius { get; set; } = 9;

    protected override void OnPaint(PaintEventArgs e)
    {
        RoundedPaint.FillRounded(e.Graphics, new RectangleF(0, 0, Width - 1, Height - 1), Radius, TintColor);
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

    protected override void OnPaint(PaintEventArgs e)
    {
        RoundedPaint.FillRounded(e.Graphics, new RectangleF(0, 0, Width - 1, Height - 1), Math.Min(Radius, Height / 2f), PillColor);
        var flags = TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis;
        flags |= TextAlign is ContentAlignment.MiddleCenter or ContentAlignment.TopCenter or ContentAlignment.BottomCenter
            ? TextFormatFlags.HorizontalCenter
            : TextFormatFlags.Left;
        var bounds = new Rectangle(Padding.Left, 0, Math.Max(0, Width - Padding.Horizontal), Height);
        TextRenderer.DrawText(e.Graphics, Text, Font, bounds, ForeColor, flags);
    }
}
