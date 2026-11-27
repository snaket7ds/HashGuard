using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace HashGuardScanner;

internal enum AlertTone
{
    Info,
    Warning,
    Danger,
}

internal enum AlertButtonKind
{
    Normal,
    Primary,
    Danger,
}

/// <summary>One button on an alert. The handler gets the card so it can confirm, update or close it.</summary>
internal sealed record AlertButton(string Text, AlertButtonKind Kind, Action<AlertCard> OnClick);

/// <summary>
/// HashGuard's own alert: "HashGuard · now" header with a close button, an icon, a title, a short
/// message and up to three buttons that never wrap. After an action it can shrink to a one-line
/// confirmation with Undo. Shown in a <see cref="TrayPopup"/> when the window is hidden, or as an
/// overlay in the window when it is open.
/// </summary>
internal sealed class AlertCard : UserControl
{
    public const int CardWidth = 384;
    private readonly Label title = new() { AutoSize = false, Font = UiFonts.Create("Segoe UI Semibold", 10.5f, FontStyle.Regular), UseMnemonic = false };
    private readonly Label body = new() { AutoSize = false, Font = UiFonts.Create("Segoe UI", 9.5f, FontStyle.Regular), UseMnemonic = false };
    private readonly Label header = new() { AutoSize = false, Font = UiFonts.Create("Segoe UI Semibold", 8.5f, FontStyle.Regular), Text = "HashGuard · now", UseMnemonic = false };
    private readonly Button close = new() { Text = "", Font = UiFonts.Create("Segoe MDL2 Assets", 8, FontStyle.Regular), FlatStyle = FlatStyle.Flat, AccessibleName = "Dismiss", TabIndex = 9 };
    private readonly TableLayoutPanel buttonRow = new() { ColumnCount = 1, RowCount = 1, Margin = new Padding(0), Padding = new Padding(0) };
    private readonly Label confirmation = new() { AutoSize = false, Font = UiFonts.Create("Segoe UI Semibold", 9.5f, FontStyle.Regular), Visible = false, UseMnemonic = false };
    private readonly Button undo = new() { Text = "Undo", FlatStyle = FlatStyle.Flat, Visible = false };
    private AlertTone tone;
    private Action? undoAction;
    private bool confirmed;

    public AlertCard()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.UserPaint, true);
        Width = CardWidth;
        close.FlatAppearance.BorderSize = 0;
        close.Size = new Size(30, 30);
        close.Click += (_, _) => Dismiss();
        undo.Click += (_, _) => undoAction?.Invoke();
        Controls.AddRange([header, close, title, body, buttonRow, confirmation, undo]);
        Tag = "alert-card";
    }

    public event EventHandler? Dismissed;

    public Color Surface { get; set; } = Color.White;
    public Color Edge { get; set; } = Color.FromArgb(227, 230, 234);
    public Color TextColor { get; set; } = Color.FromArgb(17, 24, 39);
    public Color MutedColor { get; set; } = Color.FromArgb(75, 83, 97);
    public Color ButtonBack { get; set; } = Color.White;
    public Color ButtonBorder { get; set; } = Color.FromArgb(213, 217, 223);

    public void Show(AlertTone alertTone, string titleText, string bodyText, IReadOnlyList<AlertButton> actions)
    {
        tone = alertTone;
        confirmed = false;
        title.Text = titleText;
        body.Text = bodyText;
        AccessibleName = $"HashGuard alert: {titleText}";
        AccessibleDescription = bodyText;
        buttonRow.SuspendLayout();
        buttonRow.Controls.Clear();
        buttonRow.ColumnStyles.Clear();
        buttonRow.ColumnCount = Math.Max(1, Math.Min(3, actions.Count));
        for (var index = 0; index < buttonRow.ColumnCount; index++)
        {
            buttonRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / buttonRow.ColumnCount));
            var action = actions[index];
            var button = new Button
            {
                Text = action.Text,
                Dock = DockStyle.Fill,
                Height = 36,
                Margin = new Padding(index == 0 ? 0 : 4, 0, index == buttonRow.ColumnCount - 1 ? 0 : 4, 0),
                FlatStyle = FlatStyle.Flat,
                AutoEllipsis = false,
                UseMnemonic = false,
                Font = UiFonts.Create(action.Kind == AlertButtonKind.Normal ? "Segoe UI" : "Segoe UI Semibold", 9.5f, FontStyle.Regular),
                TabIndex = index,
                Tag = action.Kind,
            };
            button.Click += (_, _) => action.OnClick(this);
            buttonRow.Controls.Add(button, index, 0);
        }

        buttonRow.ResumeLayout();
        SetConfirmMode(false);
        ApplyColors();
        LayoutCard();
    }

    /// <summary>Shrinks the card to "✓ text  [Undo]".</summary>
    public void ShowConfirmation(string text, Action? onUndo)
    {
        confirmed = true;
        confirmation.Text = text;
        undoAction = onUndo;
        undo.Visible = onUndo is not null;
        SetConfirmMode(true);
        LayoutCard();
        Invalidate();
    }

    public void Dismiss() => Dismissed?.Invoke(this, EventArgs.Empty);

    public void ApplyColors()
    {
        BackColor = Surface;
        foreach (var label in new[] { title, confirmation })
        {
            label.ForeColor = TextColor;
            label.BackColor = Surface;
        }

        body.ForeColor = MutedColor;
        body.BackColor = Surface;
        header.ForeColor = MutedColor;
        header.BackColor = Surface;
        close.BackColor = Surface;
        close.ForeColor = MutedColor;
        close.FlatAppearance.MouseOverBackColor = ButtonBack == Color.White ? Color.FromArgb(240, 241, 244) : ControlPaint.Light(ButtonBack);
        foreach (Control control in buttonRow.Controls.Cast<Control>().Append(undo))
        {
            if (control is not Button button)
            {
                continue;
            }

            var kind = button.Tag is AlertButtonKind k ? k : AlertButtonKind.Normal;
            button.FlatAppearance.BorderSize = kind == AlertButtonKind.Normal ? 1 : 0;
            button.FlatAppearance.BorderColor = ButtonBorder;
            button.BackColor = kind switch
            {
                AlertButtonKind.Danger => Color.FromArgb(180, 35, 24),
                AlertButtonKind.Primary => Color.FromArgb(24, 134, 74),
                _ => ButtonBack,
            };
            button.ForeColor = kind == AlertButtonKind.Normal ? TextColor : Color.White;
        }

        buttonRow.BackColor = Surface;
        Invalidate(true);
    }

    private void SetConfirmMode(bool on)
    {
        title.Visible = !on;
        body.Visible = !on;
        buttonRow.Visible = !on;
        confirmation.Visible = on;
    }

    private void LayoutCard()
    {
        const int pad = 16;
        var inner = CardWidth - pad * 2;
        header.SetBounds(pad + 24, pad - 2, inner - 24 - 34, 22);
        close.Location = new Point(CardWidth - pad - close.Width + 6, pad - 6);
        if (confirmed)
        {
            undo.Size = new Size(72, 34);
            confirmation.SetBounds(pad + 40, pad + 28, inner - 40 - (undo.Visible ? undo.Width + 8 : 0), 34);
            undo.Location = new Point(CardWidth - pad - undo.Width, pad + 28);
            confirmation.TextAlign = ContentAlignment.MiddleLeft;
            Height = pad + 28 + 34 + pad;
            return;
        }

        var textLeft = pad + 52;
        var textWidth = CardWidth - textLeft - pad;
        title.SetBounds(textLeft, pad + 28, textWidth, 22);
        var bodyHeight = TextRenderer.MeasureText(body.Text, body.Font, new Size(textWidth, 0), TextFormatFlags.WordBreak | TextFormatFlags.NoPrefix).Height;
        body.SetBounds(textLeft, pad + 52, textWidth, Math.Max(20, bodyHeight + 2));
        var buttonsTop = Math.Max(pad + 28 + 44, body.Bottom) + 12;
        buttonRow.SetBounds(pad, buttonsTop, inner, 36);
        Height = buttonsTop + 36 + pad;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Parent?.BackColor ?? Surface);
        using (var path = RoundedPaint.RoundedRect(new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f), 16))
        {
            using var fill = new SolidBrush(Surface);
            g.FillPath(fill, path);
            using var edge = new Pen(Edge);
            g.DrawPath(edge, path);
        }

        SidebarNav.PaintBrandMark(g, new Rectangle(16, 15, 18, 18), Color.FromArgb(24, 134, 74));
        var (tint, glyphColor, glyph) = confirmed
            ? (Color.FromArgb(230, 244, 234), Color.FromArgb(17, 98, 54), "")
            : tone switch
            {
                AlertTone.Danger => (Color.FromArgb(254, 228, 226), Color.FromArgb(180, 35, 24), ""),
                AlertTone.Warning => (Color.FromArgb(255, 241, 214), Color.FromArgb(122, 79, 0), ""),
                _ => (Color.FromArgb(232, 239, 253), Color.FromArgb(36, 87, 197), ""),
            };
        var iconRect = confirmed ? new RectangleF(16, 44, 32, 32) : new RectangleF(16, 44, 40, 40);
        RoundedPaint.FillRounded(g, iconRect, 11, tint);
        var glyphFont = UiFonts.Get("Segoe MDL2 Assets", confirmed ? 10 : 12, FontStyle.Regular);
        TextRenderer.DrawText(g, glyph, glyphFont, Rectangle.Round(iconRect), glyphColor,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
    }
}
