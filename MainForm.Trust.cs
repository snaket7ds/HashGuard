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
        var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Padding = new Padding(4), BackColor = Color.White };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        // Left: trusted publishers.
        var trustedTitle = new Label { AutoSize = false, Dock = DockStyle.Top, Height = 28, Font = new Font("Segoe UI Semibold", 11, FontStyle.Regular), UseMnemonic = false };
        var trustedHelp = new Label
        {
            Text = "Only files with a valid signature and this exact publisher name count. They get a lower risk score and no new-app alerts, and are still checked for malware.",
            AutoSize = false,
            Dock = DockStyle.Top,
            Height = 40,
            ForeColor = Color.DimGray,
        };
        var trustedView = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, HideSelection = false, HeaderStyle = ColumnHeaderStyle.Nonclickable, BorderStyle = BorderStyle.FixedSingle };
        trustedView.Columns.Add("Publisher", 260);
        trustedView.Columns.Add("On this PC", 140);
        var remove = new Button { Text = "Remove", AutoSize = true, Enabled = false };
        var leftButtons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 46, Padding = new Padding(0, 8, 0, 0), WrapContents = false };
        leftButtons.Controls.Add(remove);
        var left = new Panel { Dock = DockStyle.Fill, Padding = new Padding(8, 4, 12, 4) };
        left.Controls.Add(trustedView);
        left.Controls.Add(leftButtons);
        left.Controls.Add(trustedHelp);
        left.Controls.Add(trustedTitle);

        // Right: publishers seen on this PC, searchable and sortable.
        var seenTitle = new Label { AutoSize = false, Dock = DockStyle.Top, Height = 28, Font = new Font("Segoe UI Semibold", 11, FontStyle.Regular), UseMnemonic = false };
        var controls = new TableLayoutPanel { Dock = DockStyle.Top, Height = 40, ColumnCount = 2, RowCount = 1, Margin = new Padding(0) };
        controls.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        controls.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 130));
        var search = new TextBox { Dock = DockStyle.Fill, PlaceholderText = "Search publishers or apps", Margin = new Padding(0, 4, 8, 4), AccessibleName = "Search publishers" };
        var sort = new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList, Margin = new Padding(0, 4, 0, 4), AccessibleName = "Sort publishers" };
        sort.Items.AddRange(["Most files", "A–Z"]);
        sort.SelectedIndex = 0;
        controls.Controls.Add(search, 0, 0);
        controls.Controls.Add(sort, 1, 0);
        var seenView = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, HideSelection = false, VirtualMode = true, HeaderStyle = ColumnHeaderStyle.Nonclickable, BorderStyle = BorderStyle.FixedSingle };
        seenView.Columns.Add("Publisher", 220);
        seenView.Columns.Add("Files", 60);
        seenView.Columns.Add("Apps", 220);
        var trust = new Button { Text = "Trust", AutoSize = true, Enabled = false, Tag = "primary-button" };
        var fromFile = new Button { Text = "Choose a file…", AutoSize = true };
        var rightButtons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 46, Padding = new Padding(0, 8, 0, 0), WrapContents = false };
        rightButtons.Controls.Add(trust);
        rightButtons.Controls.Add(fromFile);
        var right = new Panel { Dock = DockStyle.Fill, Padding = new Padding(12, 4, 8, 4) };
        right.Controls.Add(seenView);
        right.Controls.Add(rightButtons);
        right.Controls.Add(controls);
        right.Controls.Add(seenTitle);
        grid.Controls.Add(left, 0, 0);
        grid.Controls.Add(right, 1, 0);

        var filtered = new List<PublisherStat>();
        void Refresh()
        {
            trustedView.BeginUpdate();
            trustedView.Items.Clear();
            foreach (var name in pendingTrusted.OrderBy(name => name, StringComparer.OrdinalIgnoreCase))
            {
                var item = new ListViewItem(name) { Tag = name };
                item.SubItems.Add(counts.TryGetValue(name, out var files) ? $"{files} file{(files == 1 ? "" : "s")}" : "Not seen yet");
                trustedView.Items.Add(item);
            }

            trustedView.EndUpdate();
            trustedTitle.Text = $"Trusted publishers  ({pendingTrusted.Count})";
            var query = search.Text.Trim();
            filtered = seen
                .Where(stat => !pendingTrusted.Any(name => HashGuardLogic.PublisherEquals(name, stat.Name)))
                .Where(stat => query.Length == 0
                    || stat.Name.Contains(query, StringComparison.OrdinalIgnoreCase)
                    || stat.Apps.Contains(query, StringComparison.OrdinalIgnoreCase))
                .OrderBy(stat => sort.SelectedIndex == 1 ? 0 : -stat.Files)
                .ThenBy(stat => stat.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
            seenView.SelectedIndices.Clear();
            seenView.VirtualListSize = filtered.Count;
            seenView.Invalidate();
            seenTitle.Text = $"Publishers on this PC  ({filtered.Count})";
            remove.Enabled = trustedView.SelectedItems.Count > 0;
            trust.Enabled = false;
        }

        seenView.RetrieveVirtualItem += (_, e) =>
        {
            var stat = e.ItemIndex >= 0 && e.ItemIndex < filtered.Count ? filtered[e.ItemIndex] : new PublisherStat("", 0, "");
            var item = new ListViewItem(stat.Name);
            item.SubItems.Add(stat.Files.ToString(System.Globalization.CultureInfo.CurrentCulture));
            item.SubItems.Add(stat.Apps);
            e.Item = item;
        };
        seenView.SelectedIndexChanged += (_, _) => trust.Enabled = seenView.SelectedIndices.Count > 0;
        trustedView.SelectedIndexChanged += (_, _) => remove.Enabled = trustedView.SelectedItems.Count > 0;
        search.TextChanged += (_, _) => Refresh();
        sort.SelectedIndexChanged += (_, _) => Refresh();
        trust.Click += (_, _) =>
        {
            foreach (int index in seenView.SelectedIndices)
            {
                if (index >= 0 && index < filtered.Count)
                {
                    pendingTrusted.Add(filtered[index].Name);
                }
            }

            Refresh();
        };
        seenView.DoubleClick += (_, _) => trust.PerformClick();
        remove.Click += (_, _) =>
        {
            foreach (ListViewItem item in trustedView.SelectedItems)
            {
                pendingTrusted.RemoveAll(name => string.Equals(name, item.Tag as string, StringComparison.OrdinalIgnoreCase));
            }

            Refresh();
        };
        fromFile.Click += (_, _) =>
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
