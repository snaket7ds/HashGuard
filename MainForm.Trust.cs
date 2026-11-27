using System.Drawing;
using System.Windows.Forms;

namespace HashGuardScanner;

/// <summary>
/// Settings → Trust: pick trusted publishers from the signers HashGuard has seen on this PC, or
/// from a signed file, instead of typing names (matching is exact since v1.1.0, so a typo would
/// silently trust nothing). Both lists are the same height and scroll; the "seen" list is a
/// virtual ListView so thousands of publishers stay fast.
/// </summary>
public sealed partial class MainForm : Form
{
    private sealed record PublisherStat(string Name, int Files, string Apps);

    /// <summary>Validly signed publishers from this session's scan results and the Firewall page.</summary>
    private List<PublisherStat> CollectSeenPublishers()
    {
        var files = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        void Add(string publisher, string summary, string path)
        {
            var name = HashGuardLogic.NormalizePublisher(publisher);
            if (name.Length == 0 || !HashGuardLogic.SignatureChainValid(summary) || string.IsNullOrWhiteSpace(path))
            {
                return;
            }

            if (!files.TryGetValue(name, out var set))
            {
                set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                files[name] = set;
            }

            set.Add(path);
        }

        foreach (var result in results)
        {
            Add(result.SignaturePublisher, result.SignatureSummary, result.Path);
        }

        foreach (var app in networkTracker?.Apps ?? [])
        {
            if (File.Exists(app.Path))
            {
                var signature = GetSignatureInfo(app.Path);
                Add(signature.Publisher, signature.Summary, app.Path);
            }
        }

        return files
            .Select(pair => new PublisherStat(
                pair.Key,
                pair.Value.Count,
                string.Join(", ", pair.Value.Select(Path.GetFileName).Distinct(StringComparer.OrdinalIgnoreCase).Take(3))))
            .ToList();
    }

    private Control BuildTrustEditor(List<string> pendingTrusted)
    {
        var seen = CollectSeenPublishers();
        var counts = seen.ToDictionary(stat => stat.Name, stat => stat.Files, StringComparer.OrdinalIgnoreCase);
        var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Padding = new Padding(0, 4, 0, 4), BackColor = SoftAppBack };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        // Left card: trusted publishers. Both cards fill the same height and scroll inside.
        var trustedTitle = new Label { AutoSize = false, Dock = DockStyle.Top, Height = 30, Font = new Font("Segoe UI Semibold", 11, FontStyle.Regular), UseMnemonic = false };
        var trustedHelp = new Label
        {
            Text = "Only files with a valid signature and this exact publisher name count. They get a lower risk score and no new-app alerts, and are still checked for malware.",
            AutoSize = false,
            Dock = DockStyle.Top,
            Height = 40,
            Tag = "muted",
            UseMnemonic = false,
        };
        var trustedList = new CardList { Dock = DockStyle.Fill, AccessibleName = "Trusted publishers", EmptyText = "No trusted publishers. Pick some from the list on the right." };
        var leftHead = new Panel { Dock = DockStyle.Top, Height = 84, Padding = new Padding(20, 12, 20, 6), BackColor = Color.White, Tag = "surface" };
        leftHead.Controls.Add(trustedHelp);
        leftHead.Controls.Add(trustedTitle);
        var leftCard = new CardPanel { Dock = DockStyle.Fill, Radius = 18, Padding = new Padding(6, 10, 6, 10), Margin = new Padding(0, 0, 8, 0) };
        leftCard.Controls.Add(trustedList);
        leftCard.Controls.Add(leftHead);

        // Right card: publishers seen on this PC, searchable and sortable.
        var seenTitle = new Label { AutoSize = false, Dock = DockStyle.Top, Height = 30, Font = new Font("Segoe UI Semibold", 11, FontStyle.Regular), UseMnemonic = false };
        var search = new TextBox { Width = 150, PlaceholderText = "Search publishers", AccessibleName = "Search publishers", Margin = new Padding(0, 0, 8, 0) };
        var sortFiles = new ChipButton("Most files");
        var sortName = new ChipButton("A–Z");
        var fromFile = new LinkLabel { Text = "Choose a file…", AutoSize = true, Margin = new Padding(8, 8, 0, 0), Tag = "accent-link" };
        var controls = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 42, WrapContents = false, BackColor = Color.White, Tag = "surface" };
        sortFiles.Margin = new Padding(0, 0, 4, 0);
        controls.Controls.AddRange([search, sortFiles, sortName, fromFile]);
        var seenList = new CardList { Dock = DockStyle.Fill, AccessibleName = "Publishers on this PC", EmptyText = "No other signed publishers seen yet. Run a scan to find more." };
        var rightHead = new Panel { Dock = DockStyle.Top, Height = 84, Padding = new Padding(20, 12, 20, 6), BackColor = Color.White, Tag = "surface" };
        rightHead.Controls.Add(controls);
        rightHead.Controls.Add(seenTitle);
        var rightCard = new CardPanel { Dock = DockStyle.Fill, Radius = 18, Padding = new Padding(6, 10, 6, 10), Margin = new Padding(8, 0, 0, 0) };
        rightCard.Controls.Add(seenList);
        rightCard.Controls.Add(rightHead);
        grid.Controls.Add(leftCard, 0, 0);
        grid.Controls.Add(rightCard, 1, 0);

        var byName = false;
        void Refresh()
        {
            trustedList.SetItems(pendingTrusted
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                .Select(name => new CardListItem
                {
                    LetterAvatar = true,
                    Tone = CardTone.Blue,
                    Title = name,
                    Detail = counts.TryGetValue(name, out var files) ? $"Signs {files} file{(files == 1 ? "" : "s")} on this PC" : "Not seen on this PC yet",
                    Actions = ["Remove"],
                    Tag = name,
                })
                .ToList(), keepScroll: true);
            trustedTitle.Text = $"Trusted publishers  ({pendingTrusted.Count})";
            var query = search.Text.Trim();
            var filtered = seen
                .Where(stat => !pendingTrusted.Any(name => HashGuardLogic.PublisherEquals(name, stat.Name)))
                .Where(stat => query.Length == 0
                    || stat.Name.Contains(query, StringComparison.OrdinalIgnoreCase)
                    || stat.Apps.Contains(query, StringComparison.OrdinalIgnoreCase))
                .OrderBy(stat => byName ? 0 : -stat.Files)
                .ThenBy(stat => stat.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
            seenList.SetItems(filtered.Select(stat => new CardListItem
            {
                LetterAvatar = true,
                Tone = CardTone.Blue,
                Title = stat.Name,
                Detail = $"{stat.Files} file{(stat.Files == 1 ? "" : "s")} · {stat.Apps}",
                Actions = ["Trust"],
                PrimaryAction = 0,
                Tag = stat.Name,
            }).ToList(), keepScroll: true);
            seenTitle.Text = $"Publishers on this PC  ({filtered.Count})";
            sortFiles.SetState("", !byName);
            sortName.SetState("", byName);
        }

        trustedList.ActionClicked += (item, _) =>
        {
            pendingTrusted.RemoveAll(name => string.Equals(name, item.Tag as string, StringComparison.OrdinalIgnoreCase));
            Refresh();
            statusLabel.Text = "Click Save to apply your trust changes.";
        };
        seenList.ActionClicked += (item, _) =>
        {
            if (item.Tag is string name)
            {
                pendingTrusted.Add(name);
                Refresh();
                statusLabel.Text = $"\"{name}\" will be trusted when you save.";
            }
        };
        seenList.ItemActivated += (_, _) =>
        {
            if (seenList.SelectedItem is { } item)
            {
                pendingTrusted.Add((string)item.Tag!);
                Refresh();
            }
        };
        search.TextChanged += (_, _) => Refresh();
        sortFiles.Click += (_, _) => { byName = false; Refresh(); };
        sortName.Click += (_, _) => { byName = true; Refresh(); };
        fromFile.LinkClicked += (_, _) =>
        {
            using var picker = new OpenFileDialog { Title = "Choose a signed file to trust its publisher", Filter = "Programs and libraries|*.exe;*.dll;*.msi;*.sys|All files|*.*", CheckFileExists = true };
            if (picker.ShowDialog(this) != DialogResult.OK)
            {
                return;
            }

            var signature = GetSignatureInfo(picker.FileName);
            var name = HashGuardLogic.NormalizePublisher(signature.Publisher);
            if (name.Length == 0 || !HashGuardLogic.SignatureChainValid(signature.Summary))
            {
                MessageBox.Show(this, $"{Path.GetFileName(picker.FileName)} doesn't have a valid signature, so there's no publisher HashGuard can trust.\n\n{signature.Summary}", "No valid signature", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            if (!pendingTrusted.Any(existing => HashGuardLogic.PublisherEquals(existing, name)))
            {
                pendingTrusted.Add(name);
            }

            Refresh();
            statusLabel.Text = $"\"{name}\" will be trusted when you save.";
        };

        Refresh();
        return grid;
    }
}
