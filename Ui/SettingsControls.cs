using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace HashGuardScanner;

/// <summary>
/// An on/off switch. It is a CheckBox underneath (Checked, CheckedChanged, keyboard Space,
/// accessibility), so the Settings code that reads and writes .Checked is unchanged; only the
/// look differs. The label is drawn by the settings row, not by the switch.
/// </summary>
internal sealed class ToggleSwitch : CheckBox
{
    public ToggleSwitch()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        base.AutoSize = false;
        Size = new Size(48, 28);
        Cursor = Cursors.Hand;
        Tag = "toggle";
        CheckedChanged += (_, _) => Invalidate();
    }

    public Color OnColor { get; set; } = Color.FromArgb(24, 134, 74);
    public Color OffColor { get; set; } = Color.FromArgb(201, 205, 212);

    /// <summary>Always fixed size; the old initializers set AutoSize = true, which is ignored.</summary>
    public override bool AutoSize
    {
        get => false;
        set { }
    }

    /// <summary>The colour actually behind a control: the first opaque ancestor (a card's surface).</summary>
    internal static Color SurfaceBehind(Control control)
    {
        for (var parent = control.Parent; parent is not null; parent = parent.Parent)
        {
            if (parent is CardPanel card)
            {
                return card.SurfaceColor;
            }

            if (parent.BackColor.A == 255)
            {
                return parent.BackColor;
            }
        }

        return SystemColors.Window;
    }

    protected override void OnTextChanged(EventArgs e)
    {
        base.OnTextChanged(e);
        AccessibleName = Text;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(SurfaceBehind(this));
        var track = new RectangleF(1, (Height - 26) / 2f, 46, 26);
        var color = Enabled ? (Checked ? OnColor : OffColor) : Color.FromArgb(225, 227, 231);
        RoundedPaint.FillRounded(g, track, 13, color);
        var knob = Checked ? new RectangleF(track.Right - 23, track.Y + 3, 20, 20) : new RectangleF(track.X + 3, track.Y + 3, 20, 20);
        using var white = new SolidBrush(Color.White);
        g.FillEllipse(white, knob);
        if (Focused && ShowFocusCues)
        {
            using var focus = new Pen(OnColor, 1.5f) { DashStyle = DashStyle.Dot };
            using var path = RoundedPaint.RoundedRect(new RectangleF(track.X - 1, track.Y - 1, track.Width + 1, track.Height + 1), 14);
            g.DrawPath(focus, path);
        }
    }
}

/// <summary>Segmented tabs (Behavior · Reputation · …) above one content area.</summary>
internal sealed class SegmentTabs : Panel
{
    private static readonly Color AppBack = Color.FromArgb(245, 246, 248);
    private readonly FlowLayoutPanel strip = new() { Dock = DockStyle.Top, Height = 46, WrapContents = false, Padding = new Padding(0, 0, 0, 8), BackColor = AppBack };
    private readonly Panel host = new() { Dock = DockStyle.Fill, BackColor = AppBack };
    private readonly List<(ChipButton Button, Control Content)> tabs = [];

    public SegmentTabs()
    {
        BackColor = AppBack;
        Controls.Add(host);
        Controls.Add(strip);
    }

    public void AddTab(string title, Control content)
    {
        var button = new ChipButton(title) { Margin = new Padding(0, 0, 6, 0), AccessibleRole = AccessibleRole.PageTab };
        content.Dock = DockStyle.Fill;
        content.Visible = tabs.Count == 0;
        host.Controls.Add(content);
        tabs.Add((button, content));
        button.Click += (_, _) => Show(tabs.FindIndex(tab => tab.Button == button));
        strip.Controls.Add(button);
        Show(tabs.FindIndex(tab => tab.Content.Visible));
    }

    private void Show(int index)
    {
        for (var i = 0; i < tabs.Count; i++)
        {
            tabs[i].Content.Visible = i == index;
            tabs[i].Button.SetState("", i == index);
        }
    }
}

/// <summary>
/// The Firewall mode control as designed: a grey track holding "Monitor" (selected, white with a
/// soft shadow) and "Ask first" with a small "Soon" tag. Ask first isn't available yet, so the
/// control is display-only.
/// </summary>
internal sealed class ModeSwitch : Control
{
    public ModeSwitch()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        Size = new Size(222, 40);
        AccessibleRole = AccessibleRole.Grouping;
        AccessibleName = "Firewall mode: Monitor. Ask first is coming soon.";
        TabStop = false;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(ToggleSwitch.SurfaceBehind(this));
        RoundedPaint.FillRounded(g, new RectangleF(0, 0, Width - 1, Height - 1), 11, Color.FromArgb(233, 235, 239));
        using var bold = new Font("Segoe UI Semibold", 9.75f, FontStyle.Regular);
        using var regular = new Font("Segoe UI", 9.75f, FontStyle.Regular);
        using var tagFont = new Font("Segoe UI Semibold", 7.5f, FontStyle.Regular);
        var monitorWidth = TextRenderer.MeasureText("Monitor", bold).Width + 24;
        var selected = new RectangleF(3, 3, monitorWidth, Height - 7);
        RoundedPaint.FillRounded(g, new RectangleF(selected.X, selected.Y + 1, selected.Width, selected.Height), 8, Color.FromArgb(30, 16, 24, 40));
        RoundedPaint.FillRounded(g, selected, 8, Color.White);
        TextRenderer.DrawText(g, "Monitor", bold, Rectangle.Round(selected), Color.FromArgb(17, 24, 39),
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);
        var askX = (int)selected.Right + 12;
        var askWidth = TextRenderer.MeasureText("Ask first", regular, Size.Empty, TextFormatFlags.NoPadding).Width;
        TextRenderer.DrawText(g, "Ask first", regular, new Rectangle(askX, 0, askWidth + 2, Height), Color.FromArgb(75, 83, 97),
            TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding | TextFormatFlags.NoPrefix);
        var soonWidth = TextRenderer.MeasureText("Soon", tagFont, Size.Empty, TextFormatFlags.NoPadding).Width + 12;
        var soon = new RectangleF(askX + askWidth + 7, (Height - 18) / 2f, soonWidth, 18);
        RoundedPaint.FillRounded(g, soon, 6, Color.FromArgb(218, 221, 227));
        TextRenderer.DrawText(g, "Soon", tagFont, Rectangle.Round(soon), Color.FromArgb(75, 83, 97),
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding | TextFormatFlags.NoPrefix);
        var wanted = (int)soon.Right + 12;
        if (Width != wanted)
        {
            Width = wanted;
        }
    }
}

/// <summary>A search box as designed: rounded border, magnifier icon, borderless text box inside.</summary>
internal sealed class SearchField : Panel
{
    private readonly TextBox box;

    public SearchField(TextBox box)
    {
        this.box = box;
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        BackColor = Color.White;
        box.BorderStyle = BorderStyle.None;
        box.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        Controls.Add(box);
        Resize += (_, _) => Place();
        box.GotFocus += (_, _) => Invalidate();
        box.LostFocus += (_, _) => Invalidate();
        Click += (_, _) => box.Focus();
        Place();
    }

    private void Place()
    {
        box.Location = new Point(36, (Height - box.Height) / 2);
        box.Width = Math.Max(20, Width - 36 - 10);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(ToggleSwitch.SurfaceBehind(this));
        var rect = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
        RoundedPaint.FillRounded(g, rect, 10, box.BackColor);
        using var path = RoundedPaint.RoundedRect(rect, 10);
        using var pen = new Pen(box.Focused ? Color.FromArgb(24, 134, 74) : Color.FromArgb(218, 221, 227), box.Focused ? 1.5f : 1f);
        g.DrawPath(pen, path);
        LineIcons.Draw(g, "icon:scan", new RectangleF(12, (Height - 16) / 2f, 16, 16), Color.FromArgb(91, 100, 114));
    }
}

/// <summary>
/// Rounded corners for ordinary buttons (the design's 10 px radius). WinForms' flat buttons are
/// square, so this paints over them with the same colours the theme set (back, border, hover, pressed).
/// </summary>
internal static class RoundedButtons
{
    /// <summary>Per button: whether focus arrived by keyboard (only then is the focus ring drawn).</summary>
    private sealed class State
    {
        public bool KeyboardFocus;
    }

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<Button, State> Attached = new();

    public static void Attach(Button button)
    {
        if (Attached.TryGetValue(button, out _))
        {
            return;
        }

        var state = new State();
        Attached.Add(button, state);
        button.KeyUp += (_, _) => { state.KeyboardFocus = true; button.Invalidate(); };
        button.LostFocus += (_, _) => { state.KeyboardFocus = false; button.Invalidate(); };
        button.Paint += Paint;
        button.MouseEnter += (_, _) => button.Invalidate();
        button.MouseLeave += (_, _) => button.Invalidate();
        button.MouseDown += (_, _) => { state.KeyboardFocus = false; button.Invalidate(); };
        button.MouseUp += (_, _) => button.Invalidate();
        button.EnabledChanged += (_, _) => button.Invalidate();
    }

    private static void Paint(object? sender, PaintEventArgs e)
    {
        if (sender is not Button button)
        {
            return;
        }

        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(ToggleSwitch.SurfaceBehind(button));
        var over = button.Enabled && button.ClientRectangle.Contains(button.PointToClient(Cursor.Position));
        var down = over && (Control.MouseButtons & MouseButtons.Left) != 0;
        var fill = down && !button.FlatAppearance.MouseDownBackColor.IsEmpty ? button.FlatAppearance.MouseDownBackColor
            : over && !button.FlatAppearance.MouseOverBackColor.IsEmpty ? button.FlatAppearance.MouseOverBackColor
            : button.BackColor;
        var ink = button.ForeColor;
        if (!button.Enabled)
        {
            fill = Blend(fill, ToggleSwitch.SurfaceBehind(button), 0.5f);
            ink = Blend(ink, fill, 0.55f);
        }

        var rect = new RectangleF(0.5f, 0.5f, button.Width - 1.5f, button.Height - 1.5f);
        var radius = Math.Min(10f, button.Height / 2f);
        RoundedPaint.FillRounded(g, rect, radius, fill);
        if (button.FlatAppearance.BorderSize > 0)
        {
            using var path = RoundedPaint.RoundedRect(rect, radius);
            using var pen = new Pen(button.FlatAppearance.BorderColor.IsEmpty ? Color.FromArgb(213, 217, 223) : button.FlatAppearance.BorderColor);
            g.DrawPath(pen, path);
        }

        TextRenderer.DrawText(g, button.Text, button.Font, Rectangle.Round(rect), ink,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis);
        if (button.Focused && Attached.TryGetValue(button, out var focusState) && focusState.KeyboardFocus)
        {
            using var focus = RoundedPaint.RoundedRect(new RectangleF(2.5f, 2.5f, button.Width - 5.5f, button.Height - 5.5f), Math.Max(2, radius - 2));
            using var pen = new Pen(Color.FromArgb(24, 134, 74), 1.5f) { DashStyle = DashStyle.Dot };
            g.DrawPath(pen, focus);
        }
    }

    private static Color Blend(Color a, Color b, float t) =>
        Color.FromArgb((int)(a.R + (b.R - a.R) * t), (int)(a.G + (b.G - a.G) * t), (int)(a.B + (b.B - a.B) * t));
}
