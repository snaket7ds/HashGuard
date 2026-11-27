using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace HashGuardScanner;

internal enum CardTone
{
    Good,
    Warn,
    Bad,
    Neutral,
    Blue,
}

/// <summary>One row of a <see cref="CardList"/>, or a section header when <see cref="IsHeader"/>.</summary>
internal sealed class CardListItem
{
    public bool IsHeader { get; init; }
    public string Header { get; init; } = "";
    public string Glyph { get; init; } = "";
    public CardTone Tone { get; init; } = CardTone.Neutral;
    public string Title { get; init; } = "";
    public string Detail { get; init; } = "";
    public string Pill { get; init; } = "";
    /// <summary>Colour of the pill when it differs from the row (e.g. "Clean" stays green on an unverified app).</summary>
    public CardTone? PillTone { get; init; }
    public string Trailing { get; init; } = "";
    public object? Tag { get; init; }
    /// <summary>Buttons drawn in the row, left to right (e.g. Details, Ignore, Quarantine).</summary>
    public IReadOnlyList<string> Actions { get; init; } = [];
    /// <summary>Index of the action drawn as a solid red button, or -1.</summary>
    public int DangerAction { get; init; } = -1;
    /// <summary>Index of the action drawn as a solid dark button, or -1.</summary>
    public int PrimaryAction { get; init; } = -1;
    /// <summary>An on/off switch at the right end of the row (null = none).</summary>
    public bool? Toggle { get; init; }
    public string ToggleLabel { get; init; } = "";
    /// <summary>A rounded letter avatar instead of the glyph (Firewall app rows).</summary>
    public bool LetterAvatar { get; init; }
    /// <summary>Text for the list's <see cref="CardColumnKind.Text"/> columns, in order (column mode only).</summary>
    public IReadOnlyList<string> Cells { get; init; } = [];
}

internal enum CardColumnKind
{
    /// <summary>Icon tile, bold title and muted detail line (always the first column).</summary>
    Main,
    /// <summary>The row's pill, left-aligned in its column.</summary>
    Pill,
    /// <summary>One entry of <see cref="CardListItem.Cells"/>.</summary>
    Text,
}

/// <summary>A column of a <see cref="CardList"/> in column mode: a fixed width, or a share of what is left.</summary>
internal sealed record CardColumn(string Header, CardColumnKind Kind, int Width = 0, float Weight = 0);

/// <summary>
/// The redesign's list: rounded icon tile, bold title, muted detail line, coloured pill and a
/// time on the right, with day/section headers. Owner-drawn and virtual (only visible rows are
/// painted), so thousands of rows stay smooth. Up/Down/Home/End/PageUp/PageDown move, Enter or
/// double-click activates, right-click or the menu key asks for a context menu.
/// </summary>
internal sealed class CardList : Control
{
    public const int RowHeight = 64;
    public const int HeaderHeight = 36;
    // Created once: OnPaint runs on every scroll, hover and refresh.
    private static readonly Font TitleFont = UiFonts.Create("Segoe UI Semibold", 10.5f, FontStyle.Regular);
    private static readonly Font DetailFont = UiFonts.Create("Segoe UI", 9f, FontStyle.Regular);
    private static readonly Font PillFont = UiFonts.Create("Segoe UI Semibold", 8.5f, FontStyle.Regular);
    private static readonly Font GlyphFont = UiFonts.Create("Segoe MDL2 Assets", 11f, FontStyle.Regular);
    private static readonly Font ActionFont = UiFonts.Create("Segoe UI Semibold", 9f, FontStyle.Regular);
    private readonly VScrollBar scroll = new() { Dock = DockStyle.Right, Visible = false };
    private IReadOnlyList<CardListItem> items = [];
    private int[] tops = [];
    private int totalHeight;
    private int selected = -1;
    private int hover = -1;

    public CardList()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.UserPaint | ControlStyles.Selectable, true);
        TabStop = true;
        AccessibleRole = AccessibleRole.List;
        Controls.Add(scroll);
        scroll.ValueChanged += (_, _) => Invalidate();
        Font = UiFonts.Create("Segoe UI", 9.5f, FontStyle.Regular);
    }

    public event EventHandler? SelectionChanged;
    public event EventHandler? ItemActivated;
    public event Action<Point>? MenuRequested;
    /// <summary>A row button was clicked: (item, action index).</summary>
    public event Action<CardListItem, int>? ActionClicked;
    /// <summary>A row's switch was clicked (or Space pressed on a row with a switch).</summary>
    public event Action<CardListItem>? ToggleClicked;

    public string EmptyText { get; set; } = "Nothing here yet.";
    public Color Surface { get; set; } = Color.White;
    public Color TextColor { get; set; } = Color.FromArgb(17, 24, 39);
    public Color Muted { get; set; } = Color.FromArgb(91, 100, 114);
    public Color Hairline { get; set; } = Color.FromArgb(241, 242, 244);
    public Color HeaderBack { get; set; } = Color.FromArgb(250, 250, 251);
    public Color SelectedBack { get; set; } = Color.FromArgb(243, 248, 244);
    public Color HoverBack { get; set; } = Color.FromArgb(248, 249, 250);
    public Color ButtonBorder { get; set; } = Color.FromArgb(213, 217, 223);
    public Color PrimaryButton { get; set; } = Color.FromArgb(17, 24, 39);
    public Color ToggleOn { get; set; } = Color.FromArgb(24, 134, 74);
    public Color ToggleOff { get; set; } = Color.FromArgb(201, 205, 212);
    public Dictionary<CardTone, (Color Tint, Color Ink)> Tones { get; } = new()
    {
        [CardTone.Good] = (Color.FromArgb(230, 244, 234), Color.FromArgb(17, 98, 54)),
        [CardTone.Warn] = (Color.FromArgb(255, 241, 214), Color.FromArgb(122, 79, 0)),
        [CardTone.Bad] = (Color.FromArgb(254, 228, 226), Color.FromArgb(180, 35, 24)),
        [CardTone.Neutral] = (Color.FromArgb(240, 241, 244), Color.FromArgb(75, 83, 97)),
        [CardTone.Blue] = (Color.FromArgb(232, 239, 253), Color.FromArgb(36, 87, 197)),
    };

    /// <summary>
    /// Column mode (as the design's Quarantine table and Firewall rows): the row is laid out in these
    /// columns instead of title-then-pill. Null = the default card row.
    /// </summary>
    public IReadOnlyList<CardColumn>? Columns { get; set; }
    /// <summary>In column mode, a fixed header row (FILE · WHY · …) that stays put while rows scroll.</summary>
    public bool ShowColumnHeaders { get; set; }
    public const int ColumnHeaderHeight = 40;
    private int HeaderOffset => Columns is not null && ShowColumnHeaders ? ColumnHeaderHeight : 0;
    private int ViewHeight => Math.Max(0, ClientSize.Height - HeaderOffset);

    public IReadOnlyList<CardListItem> Items => items;
    public CardListItem? SelectedItem => selected >= 0 && selected < items.Count ? items[selected] : null;

    public void SetItems(IReadOnlyList<CardListItem> newItems, bool keepScroll = false)
    {
        var previous = SelectedItem?.Tag;
        items = newItems;
        tops = new int[items.Count];
        var y = 0;
        for (var index = 0; index < items.Count; index++)
        {
            tops[index] = y;
            y += items[index].IsHeader ? HeaderHeight : RowHeight;
        }

        totalHeight = y;
        selected = previous is null ? -1 : FindIndex(item => Equals(item.Tag, previous));
        hover = -1;
        UpdateScroll(keepScroll);
        Invalidate();
        SelectionChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Selects (and scrolls to) the row whose Tag equals <paramref name="tag"/>.</summary>
    public bool SelectTag(object tag)
    {
        var index = FindIndex(item => Equals(item.Tag, tag) || (item.Tag is string text && tag is string wanted && string.Equals(text, wanted, StringComparison.OrdinalIgnoreCase)));
        if (index < 0)
        {
            return false;
        }

        Select(index);
        return true;
    }

    public void ApplyPalette(ThemePalette palette)
    {
        Surface = palette.Surface;
        BackColor = palette.Surface;
        TextColor = palette.Text;
        Muted = palette.MutedText;
        Hairline = palette.Hairline;
        HeaderBack = palette.SurfaceHover;
        SelectedBack = palette.AccentTint;
        HoverBack = palette.SurfaceHover;
        ButtonBorder = palette.Border;
        Tones[CardTone.Good] = (palette.AccentTint, palette.AccentText);
        Tones[CardTone.Warn] = (palette.AttentionTint, palette.AttentionText);
        Tones[CardTone.Bad] = (palette.DangerTint, palette.DangerText);
        Tones[CardTone.Neutral] = (palette.NeutralTint, palette.MutedText);
        Invalidate();
    }

    private int FindIndex(Func<CardListItem, bool> predicate)
    {
        for (var index = 0; index < items.Count; index++)
        {
            if (!items[index].IsHeader && predicate(items[index]))
            {
                return index;
            }
        }

        return -1;
    }

    private void UpdateScroll(bool keep)
    {
        var overflow = totalHeight > ViewHeight;
        scroll.Visible = overflow;
        if (!overflow)
        {
            scroll.Value = 0;
            return;
        }

        scroll.Minimum = 0;
        scroll.LargeChange = Math.Max(1, ViewHeight);
        scroll.SmallChange = RowHeight;
        scroll.Maximum = totalHeight;
        var max = Math.Max(0, totalHeight - ViewHeight);
        scroll.Value = keep ? Math.Min(scroll.Value, max) : 0;
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        UpdateScroll(keep: true);
    }

    private int Offset => scroll.Visible ? scroll.Value : 0;

    private sealed record RowLayout(Rectangle Toggle, Rectangle[] Actions, int Right);

    /// <summary>Right-hand controls of a row: switch, then trailing text, then buttons (right to left).</summary>
    private RowLayout LayoutRow(CardListItem item, int top, int width, Font actionFont, Font smallFont)
    {
        var right = width - 22;
        var toggle = Rectangle.Empty;
        if (item.Toggle is not null)
        {
            toggle = new Rectangle(right - 46, top + (RowHeight - 26) / 2, 46, 26);
            right -= 46 + 14;
        }

        if (!string.IsNullOrEmpty(item.Trailing))
        {
            right -= TextRenderer.MeasureText(item.Trailing, smallFont).Width + 16;
        }

        var rects = new Rectangle[item.Actions.Count];
        for (var index = item.Actions.Count - 1; index >= 0; index--)
        {
            var buttonWidth = TextRenderer.MeasureText(item.Actions[index], actionFont).Width + 26;
            rects[index] = new Rectangle(right - buttonWidth, top + (RowHeight - 34) / 2, buttonWidth, 34);
            right -= buttonWidth + 8;
        }

        if (item.Actions.Count > 0)
        {
            right -= 8;
        }

        return new RowLayout(toggle, rects, right);
    }

    private (int Action, bool Toggle) HitTest(int index, Point point)
    {
        if (index < 0 || index >= items.Count || items[index].IsHeader)
        {
            return (-1, false);
        }

        var layout = LayoutRow(items[index], tops[index] - Offset + HeaderOffset, ContentWidth, ActionFont, DetailFont);
        if (layout.Toggle.Contains(point))
        {
            return (-1, true);
        }

        for (var action = 0; action < layout.Actions.Length; action++)
        {
            if (layout.Actions[action].Contains(point))
            {
                return (action, false);
            }
        }

        return (-1, false);
    }
    private int ContentWidth => ClientSize.Width - (scroll.Visible ? scroll.Width : 0);

    private int IndexAt(int y)
    {
        var absolute = y - HeaderOffset + Offset;
        if (y < HeaderOffset || absolute < 0 || absolute >= totalHeight || tops.Length == 0)
        {
            return -1;
        }

        var index = Array.BinarySearch(tops, absolute);
        return index >= 0 ? index : ~index - 1;
    }

    private void Select(int index, bool ensureVisible = true)
    {
        if (index < 0 || index >= items.Count || items[index].IsHeader)
        {
            return;
        }

        if (selected != index)
        {
            selected = index;
            AccessibleDescription = $"{items[index].Title}. {items[index].Detail}";
            SelectionChanged?.Invoke(this, EventArgs.Empty);
        }

        if (ensureVisible && scroll.Visible)
        {
            var top = tops[index];
            var bottom = top + RowHeight;
            if (top < scroll.Value)
            {
                scroll.Value = Math.Max(0, top - (index > 0 && items[index - 1].IsHeader ? HeaderHeight : 0));
            }
            else if (bottom > scroll.Value + ViewHeight)
            {
                scroll.Value = Math.Min(Math.Max(0, totalHeight - ViewHeight), bottom - ViewHeight);
            }
        }

        Invalidate();
    }

    private void MoveSelection(int direction, int steps = 1)
    {
        if (items.Count == 0)
        {
            return;
        }

        var index = selected < 0 ? (direction > 0 ? -1 : items.Count) : selected;
        var remaining = steps;
        var last = selected;
        while (remaining > 0)
        {
            index += direction;
            if (index < 0 || index >= items.Count)
            {
                break;
            }

            if (!items[index].IsHeader)
            {
                last = index;
                remaining--;
            }
        }

        Select(last);
    }

    protected override bool IsInputKey(Keys keyData) =>
        keyData is Keys.Up or Keys.Down or Keys.Home or Keys.End or Keys.PageUp or Keys.PageDown or Keys.Enter or Keys.Space || base.IsInputKey(keyData);

    protected override void OnKeyDown(KeyEventArgs e)
    {
        var page = Math.Max(1, ClientSize.Height / RowHeight - 1);
        switch (e.KeyCode)
        {
            case Keys.Down: MoveSelection(1); break;
            case Keys.Up: MoveSelection(-1); break;
            case Keys.PageDown: MoveSelection(1, page); break;
            case Keys.PageUp: MoveSelection(-1, page); break;
            case Keys.Home: selected = -1; MoveSelection(1); break;
            case Keys.End: selected = -1; MoveSelection(-1); break;
            case Keys.Enter when SelectedItem is not null: ItemActivated?.Invoke(this, EventArgs.Empty); break;
            case Keys.Space when SelectedItem is { Toggle: not null } toggled: ToggleClicked?.Invoke(toggled); break;
            case Keys.Apps when SelectedItem is not null:
                MenuRequested?.Invoke(new Point(40, tops[selected] - Offset + HeaderOffset + RowHeight / 2));
                break;
            default: base.OnKeyDown(e); return;
        }

        e.Handled = true;
    }

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        if (scroll.Visible)
        {
            var max = Math.Max(0, totalHeight - ViewHeight);
            scroll.Value = Math.Clamp(scroll.Value - Math.Sign(e.Delta) * RowHeight * 2, 0, max);
        }

        base.OnMouseWheel(e);
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        Focus();
        var index = IndexAt(e.Y);
        Select(index, ensureVisible: false);
        if (e.Button == MouseButtons.Left && SelectedItem is { } clicked && index == selected)
        {
            var (action, toggle) = HitTest(index, e.Location);
            if (toggle)
            {
                ToggleClicked?.Invoke(clicked);
                base.OnMouseDown(e);
                return;
            }

            if (action >= 0)
            {
                ActionClicked?.Invoke(clicked, action);
                base.OnMouseDown(e);
                return;
            }
        }

        if (e.Button == MouseButtons.Right && SelectedItem is not null)
        {
            MenuRequested?.Invoke(e.Location);
        }

        base.OnMouseDown(e);
    }

    protected override void OnMouseDoubleClick(MouseEventArgs e)
    {
        var hit = HitTest(IndexAt(e.Y), e.Location);
        if (SelectedItem is not null && IndexAt(e.Y) == selected && hit.Action < 0 && !hit.Toggle)
        {
            ItemActivated?.Invoke(this, EventArgs.Empty);
        }

        base.OnMouseDoubleClick(e);
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        var index = IndexAt(e.Y);
        if (index != hover)
        {
            hover = index;
            Invalidate();
        }

        base.OnMouseMove(e);
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        hover = -1;
        Invalidate();
        base.OnMouseLeave(e);
    }

    protected override void OnGotFocus(EventArgs e)
    {
        base.OnGotFocus(e);
        if (selected < 0)
        {
            MoveSelection(1);
        }

        Invalidate();
    }

    protected override void OnLostFocus(EventArgs e)
    {
        base.OnLostFocus(e);
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(Surface);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        var width = ContentWidth;
        if (items.Count == 0)
        {
            TextRenderer.DrawText(g, EmptyText, Font, new Rectangle(0, HeaderOffset, width, Math.Min(ViewHeight, 160)), Muted,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.WordBreak);
            PaintColumnHeaders(g, width, width - 22);
            return;
        }

        var first = Math.Max(0, IndexAt(0));
        var bold = TitleFont;
        var small = DetailFont;
        var pillFont = PillFont;
        var headerFont = PillFont;
        var glyphFont = GlyphFont;
        var actionFont = ActionFont;
        using var hairline = new Pen(Hairline);
        for (var index = first; index < items.Count; index++)
        {
            var top = tops[index] - Offset + HeaderOffset;
            if (top > ClientSize.Height)
            {
                break;
            }

            var item = items[index];
            if (item.IsHeader)
            {
                var headerRect = new Rectangle(0, top, width, HeaderHeight);
                using (var back = new SolidBrush(HeaderBack))
                {
                    g.FillRectangle(back, headerRect);
                }

                TextRenderer.DrawText(g, item.Header.ToUpperInvariant(), headerFont, new Rectangle(22, top, width - 44, HeaderHeight), Muted,
                    TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.NoPrefix);
                g.DrawLine(hairline, 0, top + HeaderHeight - 1, width, top + HeaderHeight - 1);
                continue;
            }

            var rowRect = new Rectangle(0, top, width, RowHeight);
            if (index == selected || index == hover)
            {
                using var back = new SolidBrush(index == selected ? SelectedBack : HoverBack);
                g.FillRectangle(back, rowRect);
            }

            var (tint, ink) = Tones.TryGetValue(item.Tone, out var tone) ? tone : Tones[CardTone.Neutral];
            var iconRect = new RectangleF(22, top + (RowHeight - 38) / 2f, 38, 38);
            RoundedPaint.FillRounded(g, iconRect, 10, tint);
            var glyphText = item.LetterAvatar ? (item.Title.Length > 0 ? item.Title[..1].ToUpperInvariant() : "?") : item.Glyph;
            var glyphIsSymbol = !item.LetterAvatar && glyphText.Length == 1 && glyphText[0] >= '\uE000';
            TextRenderer.DrawText(g, glyphText, glyphIsSymbol ? glyphFont : bold, Rectangle.Round(iconRect), ink,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding | TextFormatFlags.NoPrefix);

            var layout = LayoutRow(item, top, width, actionFont, small);
            if (item.Toggle is { } on)
            {
                var track = new RectangleF(layout.Toggle.X, layout.Toggle.Y, layout.Toggle.Width, layout.Toggle.Height);
                RoundedPaint.FillRounded(g, track, track.Height / 2, on ? ToggleOn : ToggleOff);
                var knob = on ? new RectangleF(track.Right - track.Height + 3, track.Y + 3, track.Height - 6, track.Height - 6) : new RectangleF(track.X + 3, track.Y + 3, track.Height - 6, track.Height - 6);
                using var knobBrush = new SolidBrush(Color.White);
                g.FillEllipse(knobBrush, knob);
            }

            if (!string.IsNullOrEmpty(item.Trailing))
            {
                var trailingWidth = TextRenderer.MeasureText(item.Trailing, small).Width;
                var trailingRight = item.Toggle is null ? width - 22 : layout.Toggle.X - 14;
                TextRenderer.DrawText(g, item.Trailing, small, new Rectangle(trailingRight - trailingWidth, top, trailingWidth, RowHeight), Muted,
                    TextFormatFlags.VerticalCenter | TextFormatFlags.Right | TextFormatFlags.NoPrefix);
            }

            for (var action = 0; action < layout.Actions.Length; action++)
            {
                var rect = layout.Actions[action];
                var danger = action == item.DangerAction;
                var primary = action == item.PrimaryAction;
                var fill = danger ? Color.FromArgb(180, 35, 24) : primary ? PrimaryButton : Surface;
                RoundedPaint.FillRounded(g, rect, 9, fill);
                if (!danger && !primary)
                {
                    using var border = RoundedPaint.RoundedRect(new RectangleF(rect.X + 0.5f, rect.Y + 0.5f, rect.Width - 1, rect.Height - 1), 9);
                    using var borderPen = new Pen(ButtonBorder);
                    g.DrawPath(borderPen, border);
                }

                TextRenderer.DrawText(g, item.Actions[action], actionFont, rect, danger || primary ? Color.White : TextColor,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
            }

            var right = layout.Right;
            if (Columns is { } columns)
            {
                PaintColumnRow(g, item, top, columns, layout.Right, tint, ink, bold, small, pillFont);
                g.DrawLine(hairline, 0, top + RowHeight - 1, width, top + RowHeight - 1);
                if (index == selected && Focused && ShowFocusCues)
                {
                    using var columnFocus = new Pen(ink, 1.5f) { DashStyle = DashStyle.Dot };
                    g.DrawRectangle(columnFocus, 1, top + 1, width - 3, RowHeight - 3);
                }

                continue;
            }

            if (!string.IsNullOrEmpty(item.Pill))
            {
                var pillWidth = TextRenderer.MeasureText(item.Pill, pillFont, Size.Empty, TextFormatFlags.NoPadding).Width + 20;
                var pillRect = new RectangleF(right - pillWidth, top + (RowHeight - 24) / 2f, pillWidth, 24);
                var (pillTint, pillInk) = item.PillTone is { } pillTone && Tones.TryGetValue(pillTone, out var pt) ? pt : (tint, ink);
                RoundedPaint.FillRounded(g, pillRect, 12, pillTint);
                TextRenderer.DrawText(g, item.Pill, pillFont, Rectangle.Round(pillRect), pillInk,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding | TextFormatFlags.NoPrefix);
                right -= pillWidth + 16;
            }

            var textLeft = 76;
            var textWidth = Math.Max(40, right - textLeft);
            TextRenderer.DrawText(g, item.Title, bold, new Rectangle(textLeft, top + 12, textWidth, 22), TextColor,
                TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
            TextRenderer.DrawText(g, item.Detail, small, new Rectangle(textLeft, top + 34, textWidth, 20), Muted,
                TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
            g.DrawLine(hairline, 0, top + RowHeight - 1, width, top + RowHeight - 1);
            if (index == selected && Focused && ShowFocusCues)
            {
                using var focus = new Pen(ink, 1.5f) { DashStyle = DashStyle.Dot };
                g.DrawRectangle(focus, 1, top + 1, width - 3, RowHeight - 3);
            }
        }

        // Drawn last so rows scrolling up pass under it.
        var headerRight = items.Count > 0 && items.FirstOrDefault(row => !row.IsHeader) is { } sample
            ? LayoutRow(sample, 0, width, actionFont, small).Right
            : width - 22;
        PaintColumnHeaders(g, width, headerRight);
    }

    /// <summary>Left edge and width of each column between the row's start (22) and <paramref name="right"/>.</summary>
    private static (int X, int Width)[] PlaceColumns(IReadOnlyList<CardColumn> columns, int right)
    {
        const int left = 22, gap = 16;
        var fixedTotal = columns.Sum(column => column.Width) + gap * Math.Max(0, columns.Count - 1);
        var weightTotal = columns.Sum(column => column.Weight);
        var spare = Math.Max(0, right - left - fixedTotal);
        var placed = new (int X, int Width)[columns.Count];
        var x = left;
        for (var index = 0; index < columns.Count; index++)
        {
            var column = columns[index];
            var w = column.Width + (weightTotal > 0 ? (int)(spare * column.Weight / weightTotal) : 0);
            placed[index] = (x, w);
            x += w + gap;
        }

        return placed;
    }

    private void PaintColumnRow(Graphics g, CardListItem item, int top, IReadOnlyList<CardColumn> columns, int right, Color tint, Color ink, Font bold, Font small, Font pillFont)
    {
        var placed = PlaceColumns(columns, right);
        var cell = 0;
        for (var index = 0; index < columns.Count; index++)
        {
            var (x, w) = placed[index];
            switch (columns[index].Kind)
            {
                case CardColumnKind.Main:
                    // The icon tile is already drawn at 22; the text starts after it.
                    var textLeft = 76;
                    var textWidth = Math.Max(20, x + w - textLeft);
                    var hasDetail = !string.IsNullOrEmpty(item.Detail);
                    TextRenderer.DrawText(g, item.Title, bold, new Rectangle(textLeft, hasDetail ? top + 12 : top, textWidth, hasDetail ? 22 : RowHeight), TextColor,
                        TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine | (hasDetail ? 0 : TextFormatFlags.VerticalCenter));
                    if (hasDetail)
                    {
                        TextRenderer.DrawText(g, item.Detail, small, new Rectangle(textLeft, top + 34, textWidth, 20), Muted,
                            TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
                    }

                    break;
                case CardColumnKind.Pill when !string.IsNullOrEmpty(item.Pill):
                    var pillWidth = Math.Min(w, TextRenderer.MeasureText(item.Pill, pillFont, Size.Empty, TextFormatFlags.NoPadding).Width + 20);
                    var pillRect = new RectangleF(x, top + (RowHeight - 24) / 2f, pillWidth, 24);
                    var (pillTint, pillInk) = item.PillTone is { } pillTone && Tones.TryGetValue(pillTone, out var pt) ? pt : (tint, ink);
                    RoundedPaint.FillRounded(g, pillRect, 12, pillTint);
                    TextRenderer.DrawText(g, item.Pill, pillFont, Rectangle.Round(pillRect), pillInk,
                        TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding | TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis);
                    break;
                case CardColumnKind.Text:
                    var text = cell < item.Cells.Count ? item.Cells[cell] : "";
                    cell++;
                    TextRenderer.DrawText(g, text, small, new Rectangle(x, top, w, RowHeight), Muted,
                        TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
                    break;
            }
        }
    }

    private void PaintColumnHeaders(Graphics g, int width, int right)
    {
        if (Columns is not { } columns || HeaderOffset == 0)
        {
            return;
        }

        using (var back = new SolidBrush(Surface))
        {
            g.FillRectangle(back, 0, 0, ClientSize.Width, HeaderOffset);
        }

        var placed = PlaceColumns(columns, right);
        for (var index = 0; index < columns.Count; index++)
        {
            var (x, w) = placed[index];
            TextRenderer.DrawText(g, columns[index].Header.ToUpperInvariant(), PillFont, new Rectangle(x, 0, Math.Max(w, 40), HeaderOffset), Muted,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
        }

        using var line = new Pen(Hairline);
        g.DrawLine(line, 0, HeaderOffset - 1, width, HeaderOffset - 1);
    }
}

/// <summary>A rounded filter chip with an optional count ("Action needed 3"); dark when selected.</summary>
internal sealed class ChipButton : Button
{
    public ChipButton(string label)
    {
        Label = label;
        Text = label;
        FlatStyle = FlatStyle.Flat;
        FlatAppearance.BorderSize = 0;
        Height = 36;
        Cursor = Cursors.Hand;
        UseMnemonic = false;
        Tag = "chip";
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
    }

    public string Label { get; }
    public string Count { get; private set; } = "";
    public bool Selected { get; private set; }
    public Color Back { get; set; } = Color.White;
    public Color Border { get; set; } = Color.FromArgb(218, 221, 227);
    public Color Ink { get; set; } = Color.FromArgb(55, 65, 81);
    public Color SelectedBack { get; set; } = Color.FromArgb(17, 24, 39);
    public Color SelectedInk { get; set; } = Color.White;

    public void SetState(string count, bool selected)
    {
        Count = count;
        Selected = selected;
        AccessibleName = string.IsNullOrEmpty(count) ? Label : $"{Label}, {count}";
        AccessibleDescription = selected ? "Selected filter" : null;
        var bold = UiFonts.Get("Segoe UI Semibold", 9.5f, FontStyle.Regular);
        var small = UiFonts.Get("Segoe UI Semibold", 8.5f, FontStyle.Regular);
        Width = TextRenderer.MeasureText(Label, bold).Width + (string.IsNullOrEmpty(count) ? 24 : TextRenderer.MeasureText(count, small).Width + 40);
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(ToggleSwitch.SurfaceBehind(this));
        var rect = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
        RoundedPaint.FillRounded(g, rect, 10, Selected ? SelectedBack : Back);
        if (!Selected)
        {
            using var path = RoundedPaint.RoundedRect(rect, 10);
            using var pen = new Pen(Border);
            g.DrawPath(pen, path);
        }

        var ink = Selected ? SelectedInk : Ink;
        var bold = UiFonts.Get(Selected ? "Segoe UI Semibold" : "Segoe UI", 9.5f, FontStyle.Regular);
        var small = UiFonts.Get("Segoe UI Semibold", 8.5f, FontStyle.Regular);
        var labelWidth = TextRenderer.MeasureText(Label, bold).Width;
        TextRenderer.DrawText(g, Label, bold, new Rectangle(12, 0, labelWidth, Height), ink, TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.NoPrefix);
        if (!string.IsNullOrEmpty(Count))
        {
            var countWidth = TextRenderer.MeasureText(Count, small).Width + 12;
            var countRect = new RectangleF(12 + labelWidth + 4, (Height - 20) / 2f, countWidth, 20);
            RoundedPaint.FillRounded(g, countRect, 10, Selected ? Color.FromArgb(46, 255, 255, 255) : Color.FromArgb(240, 241, 244));
            TextRenderer.DrawText(g, Count, small, Rectangle.Round(countRect), ink, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
        }

        if (Focused && ShowFocusCues)
        {
            using var focus = new Pen(ink, 1.5f) { DashStyle = DashStyle.Dot };
            g.DrawRectangle(focus, 3, 3, Width - 7, Height - 7);
        }
    }
}
