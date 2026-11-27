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
