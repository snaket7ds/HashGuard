using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.Windows.Forms;

namespace HashGuardScanner;

/// <summary>
/// The Quarantine page as designed: search, a card list of isolated files (why, where from, when)
/// and a card for the selected file with Copy hash · Restore to Desktop · Restore · Delete
/// permanently. Restore/delete/repair are the existing code, fed through a one-row proxy list.
/// </summary>
public sealed partial class MainForm : Form
{
    /// <summary>Search (and the folder links) at the right of the Quarantine title, as designed.</summary>
    private Control? quarantineHeaderTools;

    /// <summary>Reloads the Quarantine list in place when the page is shown again.</summary>
    private Action? refreshQuarantinePage;

    private Control BuildQuarantinePage()
    {
        var page = new Panel { Dock = DockStyle.Fill, BackColor = SoftAppBack };
        var search = new TextBox { PlaceholderText = "Search name, path or hash", AccessibleName = "Search quarantine", Font = UiFonts.Create("Segoe UI", 10, FontStyle.Regular) };
        var searchBox = new SearchField(search) { Size = new Size(300, 40), Margin = new Padding(0) };
        // Outlined buttons beside the search, matching the design's button style.
        var openFolder = new Button { Text = "Open folder", AutoSize = true, Height = 40, Margin = new Padding(0, 0, 10, 0) };
        var repair = new Button { Text = "Remove missing entries", AutoSize = true, Height = 40, Margin = new Padding(0, 0, 10, 0), Visible = false };
        var bar = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(16, 2, 0, 0), BackColor = SoftAppBack };
        bar.Controls.AddRange([repair, openFolder, searchBox]);
        quarantineHeaderTools = bar;

        // A table as designed: FILE · WHY · CAME FROM · QUARANTINED, with a header row that stays put.
        var list = new CardList
        {
            Dock = DockStyle.Fill,
            AccessibleName = "Quarantined files",
            EmptyText = "Nothing in quarantine. When HashGuard isolates a file, it shows up here.",
            Columns =
            [
                new CardColumn("File", CardColumnKind.Main, Weight: 1.3f),
                new CardColumn("Why", CardColumnKind.Pill, Width: 150),
                new CardColumn("Came from", CardColumnKind.Text, Weight: 1.6f),
                new CardColumn("Quarantined", CardColumnKind.Text, Width: 130),
            ],
            ShowColumnHeaders = true,
        };
        var listCard = new CardPanel { Dock = DockStyle.Fill, Radius = 18, Padding = new Padding(2, 4, 2, 10) };
        listCard.Controls.Add(list);

        var selName = new Label { AutoSize = false, Dock = DockStyle.Top, Height = 24, Font = UiFonts.Create("Segoe UI Semibold", 11, FontStyle.Regular), AutoEllipsis = true, UseMnemonic = false };
        var selPath = new Label { AutoSize = false, Dock = DockStyle.Top, Height = 20, Tag = "muted", AutoEllipsis = true, UseMnemonic = false };
        var selHash = new Label { AutoSize = false, Dock = DockStyle.Top, Height = 20, Tag = "muted", AutoEllipsis = true, Font = UiFonts.Create("Consolas", 9, FontStyle.Regular), UseMnemonic = false };
        var selText = new Panel { Dock = DockStyle.Fill, BackColor = Color.Transparent };
        selText.Controls.Add(selHash);
        selText.Controls.Add(selPath);
        selText.Controls.Add(selName);
        var copyHash = new Button { Text = "Copy hash", AutoSize = true, Height = 40, Margin = new Padding(8, 0, 0, 0) };
        var restoreDesktop = new Button { Text = "Restore to Desktop", AutoSize = true, Height = 40, Margin = new Padding(8, 0, 0, 0) };
        var restore = new Button { Text = "Restore", AutoSize = true, Height = 40, Margin = new Padding(8, 0, 0, 0), Font = UiFonts.Create("Segoe UI Semibold", 9.5f, FontStyle.Regular) };
        var delete = new Button { Text = "Delete permanently", AutoSize = true, Height = 40, Margin = new Padding(8, 0, 0, 0), Tag = "danger-solid" };
        var selButtons = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Anchor = AnchorStyles.Right, BackColor = Color.Transparent, Margin = new Padding(0) };
        selButtons.Controls.AddRange([copyHash, restoreDesktop, restore, delete]);
        var selLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Color.Transparent };
        selLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        selLayout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        selLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        selLayout.Controls.Add(selText, 0, 0);
        selLayout.Controls.Add(selButtons, 1, 0);
        var selCard = new CardPanel { Dock = DockStyle.Bottom, Height = 104, Radius = 18, Padding = new Padding(22, 16, 22, 14) };
        selCard.Controls.Add(selLayout);

        page.Controls.Add(listCard);
        page.Controls.Add(new Panel { Dock = DockStyle.Bottom, Height = 14, BackColor = SoftAppBack });
        page.Controls.Add(selCard);

        var proxy = new ListView { View = View.Details, Size = new Size(1, 1), Location = new Point(-10, -10), TabStop = false };
        proxy.Columns.Add("File");
        page.Controls.Add(proxy);

        QuarantineEntry? Selected() => list.SelectedItem?.Tag as QuarantineEntry;

        bool Proxy(QuarantineEntry entry)
        {
            proxy.Items.Clear();
            var item = new ListViewItem(HashGuardLogic.QuarantineDisplayName(entry)) { Tag = entry };
            proxy.Items.Add(item);
            item.Selected = true;
            return true;
        }

        void UpdateSelection()
        {
            var entry = Selected();
            selName.Text = entry is null ? "No file selected" : HashGuardLogic.QuarantineDisplayName(entry);
            selPath.Text = entry is null ? "Select a file to restore it or delete it for good." : $"From {entry.OriginalPath}";
            selHash.Text = entry is null ? "" : $"SHA-256 {entry.Sha256}";
            foreach (var button in new[] { copyHash, restoreDesktop, restore, delete })
            {
                button.Enabled = entry is not null;
            }
        }

        void Reload()
        {
            if (page.IsDisposed)
            {
                return;
            }

            var all = LoadQuarantineManifest();
            quarantineCountCache = null;
            var stale = all.Count(entry => !HashGuardLogic.QuarantineEntryIsRestorable(entry));
            repair.Visible = stale > 0;
            repair.Text = stale == 1 ? "Remove 1 missing entry" : $"Remove {stale} missing entries";
            var items = all
                .Where(entry => HashGuardLogic.QuarantineEntryIsRestorable(entry))
                .Where(entry => HashGuardLogic.QuarantineEntryMatchesFilter(entry, search.Text))
                .OrderByDescending(entry => entry.QuarantinedAtUtc)
                .Select(entry =>
                {
                    var malicious = entry.Notes.Contains("malicious", StringComparison.OrdinalIgnoreCase) || entry.Notes.Contains("detection", StringComparison.OrdinalIgnoreCase);
                    var directory = System.IO.Path.GetDirectoryName(entry.OriginalPath) ?? entry.OriginalPath;
                    return new CardListItem
                    {
                        Glyph = "",
                        Tone = malicious ? CardTone.Bad : CardTone.Warn,
                        Title = HashGuardLogic.QuarantineDisplayName(entry),
                        Pill = malicious ? "Malicious" : "Isolated",
                        Cells =
                        [
                            directory,
                            entry.QuarantinedAtUtc == default ? "" : entry.QuarantinedAtUtc.LocalDateTime.ToString(entry.QuarantinedAtUtc.LocalDateTime.Date == DateTime.Today ? "'Today' HH:mm" : "MMM d", CultureInfo.CurrentCulture),
                        ],
                        Tag = entry,
                    };
                })
                .ToList();
            list.SetItems(items, keepScroll: true);
            UpdateSelection();
            UpdateHomePage();
        }

        list.SelectionChanged += (_, _) => UpdateSelection();
        search.TextChanged += (_, _) => Reload();
        restore.Click += async (_, _) =>
        {
            if (Selected() is { } entry && Proxy(entry))
            {
                try { await RestoreSelectedQuarantineEntriesAsync(proxy, restoreToDesktop: false); } finally { Reload(); }
            }
        };
        restoreDesktop.Click += async (_, _) =>
        {
            if (Selected() is { } entry && Proxy(entry))
            {
                try { await RestoreSelectedQuarantineEntriesAsync(proxy, restoreToDesktop: true); } finally { Reload(); }
            }
        };
        delete.Click += (_, _) =>
        {
            if (Selected() is { } entry && Proxy(entry))
            {
                DeleteSelectedQuarantineEntries(proxy);
                Reload();
            }
        };
        copyHash.Click += (_, _) =>
        {
            if (Selected() is { Sha256: { Length: > 0 } hash })
            {
                try
                {
                    Clipboard.SetText(hash);
                    statusLabel.Text = "Copied the SHA-256.";
                }
                catch
                {
                    // Another app may hold the clipboard.
                }
            }
        };
        repair.Click += (_, _) =>
        {
            RepairMissingQuarantineEntries();
            Reload();
        };
        openFolder.Click += (_, _) =>
        {
            Directory.CreateDirectory(GetQuarantineDirectory());
            Process.Start(new ProcessStartInfo(GetQuarantineDirectory()) { UseShellExecute = true });
        };
        list.ItemActivated += (_, _) => restore.PerformClick();
        Reload();
        refreshQuarantinePage = Reload;
        return page;
    }
}
