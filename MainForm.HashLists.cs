using System.Drawing;
using System.Globalization;
using System.Windows.Forms;

namespace HashGuardScanner;

/// <summary>
/// "Stored &amp; ignored hashes": one window, two tabs.
/// Stored lists the hash cache (every file HashGuard has checked and remembers, with its verdict);
/// Forget / Clear all make the next scan check those files again.
/// Ignored lists the hashes and paths you told HashGuard to ignore; Un-ignore takes them back.
/// Opened from Settings → Antivirus → Hashes and from the Scan page title row.
/// </summary>
public sealed partial class MainForm : Form
{
    private void ShowHashLists(bool ignoredTab)
    {
        using var dialog = new Form
        {
            Text = "Stored & ignored hashes",
            StartPosition = FormStartPosition.CenterParent,
            Size = new Size(980, 680),
            MinimumSize = new Size(760, 480),
            ShowInTaskbar = false,
            MinimizeBox = false,
            Icon = Icon,
            BackColor = SoftAppBack,
            Padding = new Padding(24, 18, 24, 20),
            Font = UiFonts.Get("Segoe UI", 9.75f),
        };

        var tabs = new SegmentTabs { Dock = DockStyle.Fill };
        var stored = BuildStoredHashesTab(dialog);
        var ignored = BuildIgnoredHashesTab(dialog);
        tabs.AddTab("Stored", stored);
        tabs.AddTab("Ignored", ignored);
        dialog.Controls.Add(tabs);
        // Escape closes it, like the app's other windows.
        dialog.KeyPreview = true;
        dialog.KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Escape)
            {
                dialog.Close();
            }
        };
        ApplyAppTheme(dialog);
        if (ignoredTab)
        {
            dialog.Shown += (_, _) => tabs.ShowTab(1);
        }

        dialog.ShowDialog(this);
    }

    private Control BuildStoredHashesTab(Form owner)
    {
        var page = new Panel { Dock = DockStyle.Fill, BackColor = SoftAppBack };
        var search = new TextBox { PlaceholderText = "Search name, path or hash", AccessibleName = "Search stored hashes", Font = UiFonts.Get("Segoe UI", 10) };
        var searchBox = new SearchField(search) { Size = new Size(300, 38), Margin = new Padding(0, 0, 12, 0) };
        var summary = new Label { AutoSize = true, Margin = new Padding(0, 11, 12, 0), Tag = "muted", UseMnemonic = false };
        var clearAll = new Button { Text = "Clear all…", Size = new Size(110, 38), Margin = new Padding(0), Tag = "danger-button" };
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 52, WrapContents = false, BackColor = SoftAppBack };
        bar.Controls.AddRange([searchBox, summary, clearAll]);

        var list = new CardList
        {
            Dock = DockStyle.Fill,
            AccessibleName = "Stored hashes",
            EmptyText = "No stored hashes. Files HashGuard checks are remembered here, so unchanged files aren't looked up again.",
        };
        var card = new CardPanel { Dock = DockStyle.Fill, Radius = 18, Padding = new Padding(6, 10, 6, 10) };
        card.Controls.Add(list);
        page.Controls.Add(card);
        page.Controls.Add(bar);

        void Reload()
        {
            var query = search.Text.Trim();
            var all = hashCache.Snapshot();
            var shown = all
                .Where(item => query.Length == 0
                    || item.Sha256.Contains(query, StringComparison.OrdinalIgnoreCase)
                    || item.Path.Contains(query, StringComparison.OrdinalIgnoreCase)
                    || item.Entry.Status.Contains(query, StringComparison.OrdinalIgnoreCase))
                .Select(item =>
                {
                    var (tone, label) = DescribeStoredStatus(item.Entry);
                    var name = item.Path.Length > 0 ? Path.GetFileName(item.Path) : $"Hash {ShortHash(item.Sha256)}";
                    var where = item.Path.Length > 0 ? item.Path : "File location not known";
                    return new CardListItem
                    {
                        Glyph = tone switch { CardTone.Good => "", CardTone.Bad => "!", _ => "?" },
                        Tone = tone,
                        Title = name,
                        Detail = $"{where}  ·  {ShortHash(item.Sha256)}",
                        Pill = label,
                        Trailing = item.Entry.CheckedAtUtc == default ? "" : item.Entry.CheckedAtUtc.LocalDateTime.ToString("MMM d", CultureInfo.CurrentCulture),
                        Actions = ["Copy hash", "Forget"],
                        Tag = item.Sha256,
                    };
                })
                .ToList();
            list.SetItems(shown, keepScroll: true);
            summary.Text = all.Count == shown.Count
                ? $"{all.Count:N0} stored"
                : $"{shown.Count:N0} of {all.Count:N0} stored";
            clearAll.Enabled = all.Count > 0;
        }

        list.ActionClicked += async (item, action) =>
        {
            if (item.Tag is not string sha)
            {
                return;
            }

            if (item.Actions[action] == "Copy hash")
            {
                TryCopyText(sha);
                return;
            }

            if (!CanChangeHashLists(owner))
            {
                return;
            }

            hashCache.Remove(sha);
            await hashCache.FlushIfDueAsync(force: true);
            Reload();
        };
        clearAll.Click += async (_, _) =>
        {
            if (!CanChangeHashLists(owner))
            {
                return;
            }

            var answer = MessageBox.Show(owner,
                $"Forget all {hashCache.Count:N0} stored hashes?\n\nNothing is deleted from your PC. The next scan checks every file again, which takes longer and uses more reputation lookups.",
                "Clear stored hashes", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (answer != DialogResult.Yes)
            {
                return;
            }

            hashCache.Clear();
            await hashCache.FlushIfDueAsync(force: true);
            Reload();
        };
        search.TextChanged += (_, _) => Reload();
        page.HandleCreated += async (_, _) =>
        {
            await hashCache.EnsureLoadedAsync();
            if (!page.IsDisposed)
            {
                Reload();
            }
        };
        return page;
    }

    private Control BuildIgnoredHashesTab(Form owner)
    {
        var page = new Panel { Dock = DockStyle.Fill, BackColor = SoftAppBack };
        var search = new TextBox { PlaceholderText = "Search name, path or hash", AccessibleName = "Search ignored files", Font = UiFonts.Get("Segoe UI", 10) };
        var searchBox = new SearchField(search) { Size = new Size(300, 38), Margin = new Padding(0, 0, 12, 0) };
        var summary = new Label { AutoSize = true, Margin = new Padding(0, 11, 0, 0), Tag = "muted", UseMnemonic = false };
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 52, WrapContents = false, BackColor = SoftAppBack };
        bar.Controls.AddRange([searchBox, summary]);

        var list = new CardList
        {
            Dock = DockStyle.Fill,
            AccessibleName = "Ignored files",
            EmptyText = "Nothing ignored. When you choose Ignore on a file, it shows up here and HashGuard stops asking about it.",
        };
        var card = new CardPanel { Dock = DockStyle.Fill, Radius = 18, Padding = new Padding(6, 10, 6, 10) };
        card.Controls.Add(list);
        page.Controls.Add(card);
        page.Controls.Add(bar);

        void Reload()
        {
            // Names for ignored hashes come from the hash cache and this session's results.
            var pathByHash = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in hashCache.Snapshot().Where(item => item.Path.Length > 0))
            {
                pathByHash.TryAdd(item.Sha256, item.Path);
            }

            foreach (var result in results.Where(result => !string.IsNullOrEmpty(result.Sha256) && !string.IsNullOrEmpty(result.Path)))
            {
                pathByHash[result.Sha256] = result.Path;
            }

            var query = search.Text.Trim();
            var rows = ignoredHashes
                .Select(hash => (Kind: "hash", Value: hash, Path: pathByHash.TryGetValue(hash, out var path) ? path : ""))
                .Concat(ignoredPaths.Select(path => (Kind: "path", Value: path, Path: path)))
                .Where(row => query.Length == 0
                    || row.Value.Contains(query, StringComparison.OrdinalIgnoreCase)
                    || row.Path.Contains(query, StringComparison.OrdinalIgnoreCase))
                .OrderBy(row => row.Path.Length == 0 ? row.Value : Path.GetFileName(row.Path), StringComparer.OrdinalIgnoreCase)
                .Select(row => new CardListItem
                {
                    Glyph = "",
                    Tone = CardTone.Neutral,
                    Title = row.Path.Length > 0 ? Path.GetFileName(row.Path) : $"Hash {ShortHash(row.Value)}",
                    Detail = row.Kind == "hash"
                        ? $"This exact file, wherever it is  ·  {ShortHash(row.Value)}{(row.Path.Length > 0 ? $"  ·  {row.Path}" : "")}"
                        : $"Anything at this location  ·  {row.Path}",
                    Pill = row.Kind == "hash" ? "By hash" : "By path",
                    Actions = [row.Kind == "hash" ? "Copy hash" : "Copy path", "Un-ignore"],
                    Tag = row,
                })
                .ToList();
            list.SetItems(rows, keepScroll: true);
            var total = ignoredHashes.Count + ignoredPaths.Count;
            summary.Text = total == rows.Count ? $"{total:N0} ignored" : $"{rows.Count:N0} of {total:N0} ignored";
        }

        list.ActionClicked += (item, action) =>
        {
            if (item.Tag is not ValueTuple<string, string, string> row)
            {
                return;
            }

            var (kind, value, _) = row;
            if (item.Actions[action] != "Un-ignore")
            {
                TryCopyText(value);
                return;
            }

            if (kind == "hash")
            {
                ignoredHashes.Remove(value);
                SaveIgnoredHashes();
            }
            else
            {
                ignoredPaths.Remove(value);
                SaveIgnoredPaths();
            }

            statusLabel.Text = "Un-ignored. HashGuard checks that file again on the next scan.";
            Reload();
        };
        search.TextChanged += (_, _) => Reload();
        page.HandleCreated += async (_, _) =>
        {
            await hashCache.EnsureLoadedAsync();
            if (!page.IsDisposed)
            {
                Reload();
            }
        };
        return page;
    }

    /// <summary>The stored-hash list must not change under a running scan.</summary>
    private bool CanChangeHashLists(IWin32Window owner)
    {
        if (scanCancellation is null && !scanGate.IsBusy)
        {
            return true;
        }

        MessageBox.Show(owner, "A scan is running. Try again when it has finished.", "Scan running", MessageBoxButtons.OK, MessageBoxIcon.Information);
        return false;
    }

    private static (CardTone Tone, string Label) DescribeStoredStatus(CacheEntry entry)
    {
        if (entry.Malicious > 0 || string.Equals(entry.Status, "malicious", StringComparison.OrdinalIgnoreCase))
        {
            return (CardTone.Bad, entry.Malicious > 0 ? $"Malicious ({entry.Malicious})" : "Malicious");
        }

        if (entry.Suspicious > 0 || string.Equals(entry.Status, "suspicious", StringComparison.OrdinalIgnoreCase))
        {
            return (CardTone.Warn, "Suspicious");
        }

        if (HashCache.IsCleanEntry(entry))
        {
            return (CardTone.Good, "Clean");
        }

        if (string.Equals(entry.Status, "ignored", StringComparison.OrdinalIgnoreCase))
        {
            return (CardTone.Neutral, "Ignored");
        }

        return (CardTone.Warn, "Unknown");
    }

    private static string ShortHash(string sha256) =>
        sha256.Length > 12 ? $"{sha256[..6]}…{sha256[^4..]}" : sha256;

    private void TryCopyText(string text)
    {
        try
        {
            Clipboard.SetText(text);
            statusLabel.Text = "Copied.";
        }
        catch
        {
            // Another app may hold the clipboard.
        }
    }
}
