using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace HashGuardScanner;

internal enum AppPage
{
    Home,
    Scan,
    Quarantine,
    Firewall,
    Activity,
    Settings,
}

/// <summary>
/// The left navigation of the v1.1.0 window: app mark, one button per page and Settings at the
/// bottom. Items are real buttons, so Tab/Enter/Space and screen readers work; Up/Down move
/// between them.
/// </summary>
internal sealed class SidebarNav : Panel
{
    private readonly List<NavButton> buttons = [];
    private readonly FlowLayoutPanel list;
    private readonly Panel bottom;
    private AppPage active = AppPage.Home;

    public SidebarNav()
    {
        Dock = DockStyle.Fill;
        Padding = new Padding(14, 22, 14, 16);
        Tag = "sidebar";
        DoubleBuffered = true;
        ResizeRedraw = true;

        var brand = new Label
        {
            Dock = DockStyle.Top,
            Height = 52,
            Text = "HashGuard",
            Font = UiFonts.Create("Segoe UI Semibold", 13, FontStyle.Regular),
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(42, 0, 0, 8),
            Tag = "sidebar-brand",
            UseMnemonic = false,
        };
        brand.Paint += (_, e) => PaintBrandMark(e.Graphics, new Rectangle(8, (brand.Height - 8 - 28) / 2, 28, 28), BrandColor);

        list = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Margin = new Padding(0),
            Padding = new Padding(0),
            Tag = "sidebar",
        };
        bottom = new Panel { Dock = DockStyle.Bottom, Height = 48, Tag = "sidebar" };

        AddItem(AppPage.Home, "Home", "icon:home");
        AddItem(AppPage.Scan, "Scan", "icon:scan");
        AddItem(AppPage.Quarantine, "Quarantine", "icon:quarantine");
        AddItem(AppPage.Firewall, "Firewall", "icon:firewall");
        AddItem(AppPage.Activity, "Activity", "icon:activity");
        var settings = CreateButton(AppPage.Settings, "Settings", "");
        settings.Dock = DockStyle.Fill;
        bottom.Controls.Add(settings);

        Controls.Add(list);
        Controls.Add(bottom);
        Controls.Add(brand);
        Resize += (_, _) => SizeButtons();
        SetActive(AppPage.Home);
    }

    public event Action<AppPage>? NavigateRequested;

    public Color BrandColor { get; set; } = Color.FromArgb(24, 134, 74);
    public Color ActiveBack { get; set; } = Color.FromArgb(230, 244, 234);
    public Color ActiveText { get; set; } = Color.FromArgb(17, 98, 54);
    public Color ItemText { get; set; } = Color.FromArgb(55, 65, 81);
    public Color HoverBack { get; set; } = Color.FromArgb(240, 241, 244);
    public Color BadgeBack { get; set; } = Color.FromArgb(180, 35, 24);
    public Color BadgeText { get; set; } = Color.White;
    public Color NeutralBadgeBack { get; set; } = Color.FromArgb(232, 234, 238);
    public Color NeutralBadgeText { get; set; } = Color.FromArgb(75, 83, 97);
    /// <summary>The 1px line between the sidebar and the page (design: #E6E8EC).</summary>
    public Color DividerColor { get; set; } = Color.FromArgb(230, 232, 236);

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        using var pen = new Pen(DividerColor);
        e.Graphics.DrawLine(pen, Width - 1, 0, Width - 1, Height);
    }

    public void SetActive(AppPage page)
    {
        active = page;
        foreach (var button in buttons)
        {
            button.IsActive = button.Page == page;
            button.AccessibleDescription = button.IsActive ? "Current page" : null;
            button.Invalidate();
        }
    }

    /// <summary>Count shown on an item (empty hides it). Alert badges are red, others neutral.</summary>
    public void SetBadge(AppPage page, string text, bool alert)
    {
        var button = buttons.FirstOrDefault(item => item.Page == page);
        if (button is null || (button.Badge == text && button.BadgeAlert == alert))
        {
            return;
        }

        button.Badge = text;
        button.BadgeAlert = alert;
        button.AccessibleName = string.IsNullOrEmpty(text) ? button.Label : $"{button.Label}, {text}";
        button.Invalidate();
    }

    public void ApplyColors()
    {
        foreach (var button in buttons)
        {
            button.Invalidate();
        }

        Invalidate(true);
    }

    protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
    {
        if (keyData is Keys.Down or Keys.Up)
        {
            var focused = buttons.FindIndex(button => button.Focused);
            if (focused >= 0)
            {
                var next = (focused + (keyData == Keys.Down ? 1 : buttons.Count - 1)) % buttons.Count;
                buttons[next].Focus();
                return true;
            }
        }

        return base.ProcessCmdKey(ref msg, keyData);
    }

    private void AddItem(AppPage page, string label, string glyph)
    {
        list.Controls.Add(CreateButton(page, label, glyph));
    }

    private NavButton CreateButton(AppPage page, string label, string glyph)
    {
        var button = new NavButton(this, page, label, glyph)
        {
            Height = 44,
            Margin = new Padding(0, 0, 0, 2),
            AccessibleName = label,
            AccessibleRole = AccessibleRole.PushButton,
        };
        button.Click += (_, _) => NavigateRequested?.Invoke(page);
        buttons.Add(button);
        return button;
    }

    private void SizeButtons()
    {
        var width = Math.Max(80, list.ClientSize.Width);
        foreach (Control control in list.Controls)
        {
            control.Width = width;
        }
    }

    /// <summary>A white outlined shield with a white check, dot or "!" (the Home status badge).</summary>
    internal static void PaintShieldOutline(Graphics graphics, RectangleF bounds, ShieldSymbol symbol)
    {
        graphics.SmoothingMode = SmoothingMode.AntiAlias;
        float x = bounds.X, y = bounds.Y, w = bounds.Width, h = bounds.Height;
        using var path = new GraphicsPath();
        path.AddLine(x + w * 0.5f, y, x + w, y + h * 0.14f);
        path.AddBezier(x + w, y + h * 0.14f, x + w, y + h * 0.62f, x + w * 0.78f, y + h * 0.86f, x + w * 0.5f, y + h);
        path.AddBezier(x + w * 0.5f, y + h, x + w * 0.22f, y + h * 0.86f, x, y + h * 0.62f, x, y + h * 0.14f);
        path.CloseFigure();
        var stroke = Math.Max(1.8f, w / 12f);
        using var outline = new Pen(Color.White, stroke) { LineJoin = LineJoin.Round };
        graphics.DrawPath(outline, path);
        using var pen = new Pen(Color.White, stroke * 1.1f) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round };
        using var white = new SolidBrush(Color.White);
        switch (symbol)
        {
            case ShieldSymbol.Check:
                graphics.DrawLines(pen, new[] { new PointF(x + w * 0.3f, y + h * 0.5f), new PointF(x + w * 0.45f, y + h * 0.64f), new PointF(x + w * 0.72f, y + h * 0.36f) });
                break;
            case ShieldSymbol.Exclamation:
                graphics.DrawLine(pen, x + w * 0.5f, y + h * 0.28f, x + w * 0.5f, y + h * 0.54f);
                graphics.FillEllipse(white, x + w * 0.5f - stroke * 0.7f, y + h * 0.66f - stroke * 0.7f, stroke * 1.4f, stroke * 1.4f);
                break;
            default:
                graphics.FillEllipse(white, x + w * 0.36f, y + h * 0.35f, w * 0.28f, w * 0.28f);
                break;
        }
    }

    internal static void PaintBrandMark(Graphics graphics, Rectangle bounds, Color color) =>
        PaintShield(graphics, bounds, color, ShieldSymbol.Check, Color.Empty);

    internal enum ShieldSymbol
    {
        Check,
        Dot,
        Exclamation,
    }

    /// <summary>
    /// The HashGuard shield (app mark, sidebar, alerts and the tray icon): a filled shield with a
    /// white check, dot or exclamation mark, and an optional outline so it stands out on any taskbar.
    /// </summary>
    internal static void PaintShield(Graphics graphics, RectangleF bounds, Color color, ShieldSymbol symbol, Color outline)
    {
        graphics.SmoothingMode = SmoothingMode.AntiAlias;
        float x = bounds.X, y = bounds.Y, w = bounds.Width, h = bounds.Height;
        using var path = new GraphicsPath();
        path.AddLine(x + w * 0.5f, y, x + w, y + h * 0.14f);
        path.AddBezier(x + w, y + h * 0.14f, x + w, y + h * 0.62f, x + w * 0.78f, y + h * 0.86f, x + w * 0.5f, y + h);
        path.AddBezier(x + w * 0.5f, y + h, x + w * 0.22f, y + h * 0.86f, x, y + h * 0.62f, x, y + h * 0.14f);
        path.CloseFigure();
        using var brush = new SolidBrush(color);
        graphics.FillPath(brush, path);
        if (outline != Color.Empty)
        {
            using var outlinePen = new Pen(outline, Math.Max(1.5f, w / 22f)) { LineJoin = LineJoin.Round };
            graphics.DrawPath(outlinePen, path);
        }

        var stroke = Math.Max(2f, w / 11f);
        using var pen = new Pen(Color.White, stroke) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round };
        using var white = new SolidBrush(Color.White);
        switch (symbol)
        {
            case ShieldSymbol.Check:
                graphics.DrawLines(pen, new[]
                {
                    new PointF(x + w * 0.3f, y + h * 0.5f),
                    new PointF(x + w * 0.45f, y + h * 0.64f),
                    new PointF(x + w * 0.72f, y + h * 0.36f),
                });
                break;
            case ShieldSymbol.Exclamation:
                graphics.DrawLine(pen, x + w * 0.5f, y + h * 0.26f, x + w * 0.5f, y + h * 0.55f);
                var dot = stroke * 1.15f;
                graphics.FillEllipse(white, x + w * 0.5f - dot / 2, y + h * 0.68f - dot / 2, dot, dot);
                break;
            default:
                var size = w * 0.3f;
                graphics.FillEllipse(white, x + (w - size) / 2, y + h * 0.47f - size / 2, size, size);
                break;
        }
    }

    private sealed class NavButton : Button
    {
        private readonly SidebarNav owner;
        private readonly string glyph;
        private bool hover;

        public NavButton(SidebarNav owner, AppPage page, string label, string glyph)
        {
            this.owner = owner;
            this.glyph = glyph;
            Page = page;
            Label = label;
            Text = label;
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            Cursor = Cursors.Hand;
            TabStop = true;
            UseMnemonic = false;
            Tag = "nav-item";
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            MouseEnter += (_, _) => { hover = true; Invalidate(); };
            MouseLeave += (_, _) => { hover = false; Invalidate(); };
        }

        public AppPage Page { get; }
        public string Label { get; }
        public bool IsActive { get; set; }
        public string Badge { get; set; } = "";
        public bool BadgeAlert { get; set; }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Parent?.BackColor ?? owner.BackColor);
            var rect = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
            if (IsActive || hover)
            {
                RoundedPaint.FillRounded(g, rect, 10, IsActive ? owner.ActiveBack : owner.HoverBack);
            }

            var color = IsActive ? owner.ActiveText : owner.ItemText;
            if (LineIcons.IsIcon(glyph))
            {
                LineIcons.Draw(g, glyph, new RectangleF(14, (Height - 20) / 2f, 20, 20), color);
            }
            else
            {
                using var glyphFont = UiFonts.Create("Segoe MDL2 Assets", 11.5f, FontStyle.Regular);
                TextRenderer.DrawText(g, glyph, glyphFont, new Rectangle(12, 0, 24, Height), color,
                    TextFormatFlags.VerticalCenter | TextFormatFlags.HorizontalCenter | TextFormatFlags.NoPadding);
            }
            using var textFont = UiFonts.Create(IsActive ? "Segoe UI Semibold" : "Segoe UI", 10.5f, FontStyle.Regular);
            var badgeWidth = 0;
            if (!string.IsNullOrEmpty(Badge))
            {
                var size = TextRenderer.MeasureText(Badge, Font, Size.Empty, TextFormatFlags.NoPadding);
                badgeWidth = Math.Max(22, size.Width + 14);
                var badgeRect = new RectangleF(Width - badgeWidth - 10, (Height - 20) / 2f, badgeWidth, 20);
                RoundedPaint.FillRounded(g, badgeRect, 10, BadgeAlert ? owner.BadgeBack : owner.NeutralBadgeBack);
                using var badgeFont = UiFonts.Create("Segoe UI Semibold", 8.5f, FontStyle.Regular);
                TextRenderer.DrawText(g, Badge, badgeFont, Rectangle.Round(badgeRect), BadgeAlert ? owner.BadgeText : owner.NeutralBadgeText,
                    TextFormatFlags.VerticalCenter | TextFormatFlags.HorizontalCenter | TextFormatFlags.NoPadding);
            }

            TextRenderer.DrawText(g, Label, textFont, new Rectangle(46, 0, Math.Max(0, Width - 56 - badgeWidth), Height), color,
                TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
            if (Focused && ShowFocusCues)
            {
                using var focusPen = new Pen(owner.ActiveText, 1.5f) { DashStyle = DashStyle.Dot };
                using var path = RoundedPaint.RoundedRect(new RectangleF(1.5f, 1.5f, Width - 3.5f, Height - 3.5f), 9);
                g.DrawPath(focusPen, path);
            }
        }
    }
}
