using System.Diagnostics;
using System.Drawing;
using System.IO.Pipes;
using System.Net;
using System.Net.Http.Headers;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows.Forms;
using System.Xml.Linq;
using Microsoft.Win32;

namespace HashGuardScanner;

public sealed partial class MainForm : Form
{
    private void QuarantineSelectedFiles(ListView sourceView)
    {
        var paths = sourceView.SelectedItems
            .Cast<ListViewItem>()
            .Select(item => GetSubItemText(item, ColPath))
            .Where(path => !string.IsNullOrWhiteSpace(path) && File.Exists(path))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (paths.Count == 0)
        {
            MessageBox.Show(this, "Select one or more rows with existing files.", "No file selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var accepted = MessageBox.Show(
            this,
            $"Move {paths.Count} selected file(s) to HashGuard quarantine? Running files may need their process killed first.{Environment.NewLine}{Environment.NewLine}{BuildSelectedActionSummary(sourceView)}",
            "Quarantine selected files",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);
        if (accepted != DialogResult.Yes)
        {
            return;
        }

        var quarantineDir = GetQuarantineDirectory();
        Directory.CreateDirectory(quarantineDir);
        var manifest = LoadQuarantineManifest();
        var moved = 0;
        var failures = new List<string>();

        foreach (var path in paths)
        {
            try
            {
                var sha256 = sourceView.Items
                    .Cast<ListViewItem>()
                    .Where(item => string.Equals(GetSubItemText(item, ColPath), path, StringComparison.OrdinalIgnoreCase))
                    .Select(item => GetSubItemText(item, ColSha256))
                    .FirstOrDefault(hash => !string.IsNullOrWhiteSpace(hash)) ?? "";
                var notes = sourceView.Items
                    .Cast<ListViewItem>()
                    .Where(item => string.Equals(GetSubItemText(item, ColPath), path, StringComparison.OrdinalIgnoreCase))
                    .Select(item => GetSubItemText(item, ColNotes))
                    .FirstOrDefault() ?? "";
                var target = Path.Combine(
                    quarantineDir,
                    $"{Path.GetFileName(path)}.{DateTime.Now:yyyyMMddHHmmss}.quarantine");
                File.Move(path, target);
                manifest.Add(new QuarantineEntry
                {
                    OriginalPath = path,
                    QuarantinePath = target,
                    Sha256 = sha256,
                    Notes = notes,
                    QuarantinedAtUtc = DateTimeOffset.UtcNow,
                });
                moved++;
                AppendQuarantineLog("quarantine", path, target, "moved to quarantine");
                MarkRowsQuarantined(sourceView, path, target);
                MarkRowsQuarantined(resultsView, path, target);
                MarkResultsQuarantined(path, target);
            }
            catch (Exception ex)
            {
                AppendQuarantineLog("quarantine-failed", path, "", ex.Message);
                failures.Add($"{path}: {ex.Message}");
            }
        }

        SaveQuarantineManifest(manifest);
        statusLabel.Text = $"Quarantined {moved} file(s).";
        UpdateQuarantineTile();
        ReconcileReviewQueue(updateSummary: false);
        UpdateSummary();
        if (failures.Count > 0)
        {
            MessageBox.Show(this, string.Join(Environment.NewLine, failures.Take(8)), "Some files could not be quarantined", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void MarkResultsQuarantined(string originalPath, string quarantinePath)
    {
        foreach (var result in results.Where(result => string.Equals(result.Path, originalPath, StringComparison.OrdinalIgnoreCase)))
        {
            result.Notes = result.Notes.Contains("Quarantined to ", StringComparison.OrdinalIgnoreCase)
                ? result.Notes
                : string.IsNullOrWhiteSpace(result.Notes)
                    ? $"Quarantined to {quarantinePath}"
                    : $"{result.Notes}; Quarantined to {quarantinePath}";
        }
    }

    private static string BuildSelectedActionSummary(ListView sourceView)
    {
        var lines = sourceView.SelectedItems
            .Cast<ListViewItem>()
            .Take(5)
            .Select(item =>
            {
                var risk = GetSubItemText(item, ColRisk);
                var pids = GetSubItemText(item, ColPids);
                var path = GetSubItemText(item, ColPath);
                var process = GetSubItemText(item, ColProcess);
                var reason = BuildReasonSummary(item)
                    .Split(Environment.NewLine)
                    .FirstOrDefault(line => line.StartsWith("Reason:", StringComparison.OrdinalIgnoreCase)) ?? "Reason: not available";
                return $"{process} | PID {pids} | {risk}{Environment.NewLine}{path}{Environment.NewLine}{reason}";
            })
            .ToList();
        var remaining = sourceView.SelectedItems.Count - lines.Count;
        if (remaining > 0)
        {
            lines.Add($"+{remaining} more");
        }

        return string.Join(Environment.NewLine, lines);
    }

    private void ShowQuarantineDialog()
    {
        using var dialog = new Form
        {
            Text = "Quarantine Manager",
            StartPosition = FormStartPosition.CenterParent,
            Size = new Size(1040, 580),
            MinimumSize = new Size(800, 460),
            BackColor = Color.FromArgb(246, 247, 249),
        };

        var heading = new Label
        {
            Dock = DockStyle.Fill,
            Height = 28,
            Font = new Font("Segoe UI Semibold", 11, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft,
            ForeColor = Color.FromArgb(35, 35, 35),
        };
        var searchBox = new TextBox
        {
            PlaceholderText = "Search file name, path, or hash",
            Dock = DockStyle.Fill,
            Margin = new Padding(0, 0, 0, 8),
        };
        var view = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = false,
            HideSelection = false,
            BorderStyle = BorderStyle.FixedSingle,
        };
        view.Columns.Add("File", 180);
        view.Columns.Add("Quarantined", 140);
        view.Columns.Add("Original path", 420);
        view.Columns.Add("SHA-256", 240);
        var emptyLabel = new Label
        {
            Text = "No files in quarantine. Select a detection in Review Queue and click Quarantine, then come back here to restore it.",
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleCenter,
            ForeColor = Color.DimGray,
            Font = new Font("Segoe UI", 10, FontStyle.Regular),
        };
        var detail = new Label
        {
            Text = "Select a file to restore it to the original path or to your Desktop.",
            Dock = DockStyle.Fill,
            Height = 72,
            AutoEllipsis = true,
            Padding = new Padding(10, 8, 10, 8),
            BackColor = Color.White,
            ForeColor = Color.FromArgb(35, 35, 35),
            BorderStyle = BorderStyle.FixedSingle,
            Tag = "callout",
        };

        var restore = new Button { Text = "Restore", AutoSize = true };
        var restoreDesktop = new Button { Text = "Restore to Desktop", AutoSize = true };
        var delete = new Button { Text = "Delete permanently", AutoSize = true };
        var copyHash = new Button { Text = "Copy Hash", AutoSize = true };
        var repairMissing = new Button { Text = "Repair Missing", AutoSize = true };
        var openFolder = new Button { Text = "Open Folder", AutoSize = true };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.OK };

        void ReloadRows()
        {
            var all = LoadQuarantineManifest();
            var restorable = all
                .Where(entry => HashGuardLogic.QuarantineEntryIsRestorable(entry))
                .OrderByDescending(entry => entry.QuarantinedAtUtc)
                .Where(entry => HashGuardLogic.QuarantineEntryMatchesFilter(entry, searchBox.Text))
                .ToList();
            var staleCount = all.Count(entry => !HashGuardLogic.QuarantineEntryIsRestorable(entry));
            view.BeginUpdate();
            view.Items.Clear();
            foreach (var entry in restorable)
            {
                var item = new ListViewItem(HashGuardLogic.QuarantineDisplayName(entry));
                item.SubItems.Add(entry.QuarantinedAtUtc.LocalDateTime.ToString("g"));
                item.SubItems.Add(entry.OriginalPath);
                item.SubItems.Add(entry.Sha256);
                item.Tag = entry;
                view.Items.Add(item);
            }
            view.EndUpdate();
            emptyLabel.Visible = view.Items.Count == 0;
            heading.Text = BuildQuarantineHeading(restorable.Count, staleCount);
            var hasSelection = view.SelectedItems.Count > 0;
            restore.Enabled = hasSelection;
            restoreDesktop.Enabled = hasSelection;
            delete.Enabled = hasSelection;
            copyHash.Enabled = hasSelection;
            repairMissing.Enabled = staleCount > 0;
            if (!hasSelection)
            {
                detail.Text = view.Items.Count == 0
                    ? "Nothing to restore. Quarantined files will appear here."
                    : "Select a file to restore it to the original path or to your Desktop.";
            }
        }

        void UpdateDetail()
        {
            var entries = GetSelectedQuarantineEntries(view);
            if (entries.Count == 0)
            {
                return;
            }

            var first = entries[0];
            var extra = entries.Count > 1 ? $"{Environment.NewLine}+{entries.Count - 1} more selected" : "";
            detail.Text =
                $"{HashGuardLogic.QuarantineDisplayName(first)}{Environment.NewLine}" +
                $"Original: {first.OriginalPath}{Environment.NewLine}" +
                $"SHA-256: {first.Sha256}{extra}";
            restore.Enabled = true;
            restoreDesktop.Enabled = true;
            delete.Enabled = true;
            copyHash.Enabled = true;
        }

        searchBox.TextChanged += (_, _) => ReloadRows();
        view.SelectedIndexChanged += (_, _) => UpdateDetail();

        restore.Click += async (_, _) =>
        {
            try
            {
                await RestoreSelectedQuarantineEntriesAsync(view, restoreToDesktop: false);
            }
            finally
            {
                ReloadRows();
                UpdateQuarantineTile();
            }
        };
        restoreDesktop.Click += async (_, _) =>
        {
            try
            {
                await RestoreSelectedQuarantineEntriesAsync(view, restoreToDesktop: true);
            }
            finally
            {
                ReloadRows();
                UpdateQuarantineTile();
            }
        };
        delete.Click += (_, _) =>
        {
            DeleteSelectedQuarantineEntries(view);
            ReloadRows();
            UpdateQuarantineTile();
        };
        copyHash.Click += (_, _) =>
        {
            var entries = GetSelectedQuarantineEntries(view);
            var hash = entries.FirstOrDefault()?.Sha256;
            if (string.IsNullOrWhiteSpace(hash))
            {
                return;
            }

            try
            {
                Clipboard.SetText(hash);
                statusLabel.Text = "Copied quarantine SHA-256.";
            }
            catch
            {
                // Clipboard can fail if another app holds it.
            }
        };
        repairMissing.Click += (_, _) =>
        {
            RepairMissingQuarantineEntries();
            ReloadRows();
            UpdateQuarantineTile();
        };
        openFolder.Click += (_, _) =>
        {
            Directory.CreateDirectory(GetQuarantineDirectory());
            Process.Start(new ProcessStartInfo(GetQuarantineDirectory()) { UseShellExecute = true });
        };

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            AutoSize = true,
            FlowDirection = FlowDirection.RightToLeft,
            WrapContents = true,
            Padding = new Padding(0, 8, 0, 0),
        };
        buttons.Controls.Add(close);
        buttons.Controls.Add(openFolder);
        buttons.Controls.Add(repairMissing);
        buttons.Controls.Add(copyHash);
        buttons.Controls.Add(delete);
        buttons.Controls.Add(restoreDesktop);
        buttons.Controls.Add(restore);

        var listHost = new Panel { Dock = DockStyle.Fill };
        listHost.Controls.Add(emptyLabel);
        listHost.Controls.Add(view);
        emptyLabel.BringToFront();

        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 5, Padding = new Padding(12) };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.Controls.Add(heading, 0, 0);
        layout.Controls.Add(searchBox, 0, 1);
        layout.Controls.Add(listHost, 0, 2);
        layout.Controls.Add(detail, 0, 3);
        layout.Controls.Add(buttons, 0, 4);
        dialog.Controls.Add(layout);
        dialog.AcceptButton = close;
        ApplyAppTheme(dialog);
        ReloadRows();
        dialog.ShowDialog(this);
        UpdateQuarantineTile();
    }

    private static string BuildQuarantineHeading(int restorableCount, int staleCount)
    {
        if (restorableCount == 0)
        {
            return staleCount == 0
                ? "No quarantined files"
                : $"No restorable files. {staleCount} stale manifest {PluralizeEntry(staleCount)} can be repaired.";
        }

        var staleText = staleCount == 0
            ? ""
            : $" {staleCount} stale manifest {PluralizeEntry(staleCount)} found.";
        return $"{restorableCount} quarantined file(s). Select entries to restore or delete.{staleText}";
    }

    private static string PluralizeEntry(int count)
    {
        return count == 1 ? "entry" : "entries";
    }

    private static void SetQuarantineButtonsEnabled(
        bool hasRestorableRows,
        bool hasStaleRows,
        Button restore,
        Button restoreDesktop,
        Button delete,
        Button repairMissing)
    {
        restore.Enabled = hasRestorableRows;
        restoreDesktop.Enabled = hasRestorableRows;
        delete.Enabled = hasRestorableRows;
        repairMissing.Enabled = hasStaleRows;
    }

    private async Task RestoreSelectedQuarantineEntriesAsync(ListView view, bool restoreToDesktop)
    {
        var entries = GetSelectedQuarantineEntries(view);
        if (entries.Count == 0)
        {
            MessageBox.Show(this, "Select one or more quarantined files first.", "No quarantine selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var restoreTargetText = restoreToDesktop ? "to your Desktop" : "to their original paths";
        var accepted = MessageBox.Show(this, $"Restore {entries.Count} quarantined file(s) {restoreTargetText}?", "Restore quarantine", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
        if (accepted != DialogResult.Yes)
        {
            return;
        }

        var manifest = LoadQuarantineManifest();
        var restored = 0;
        var restoredEntries = new List<QuarantineEntry>();
        var failures = new List<string>();
        foreach (var entry in entries)
        {
            try
            {
                if (!File.Exists(entry.QuarantinePath))
                {
                    throw new FileNotFoundException("Quarantined file no longer exists.", entry.QuarantinePath);
                }

                var restorePath = restoreToDesktop
                    ? GetDesktopRestorePath(entry)
                    : entry.OriginalPath;
                if (!restoreToDesktop && File.Exists(restorePath))
                {
                    var replaceExisting = MessageBox.Show(
                        this,
                        $"A file already exists at the original path. Replace it with the quarantined copy?{Environment.NewLine}{restorePath}",
                        "Restore quarantine",
                        MessageBoxButtons.YesNoCancel,
                        MessageBoxIcon.Warning);
                    if (replaceExisting == DialogResult.Cancel)
                    {
                        continue;
                    }

                    if (replaceExisting == DialogResult.No)
                    {
                        using var saveDialog = new SaveFileDialog
                        {
                            Title = "Restore quarantined file as",
                            FileName = Path.GetFileName(restorePath),
                            InitialDirectory = Directory.Exists(Path.GetDirectoryName(restorePath)) ? Path.GetDirectoryName(restorePath) : Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                        };
                        if (saveDialog.ShowDialog(this) != DialogResult.OK)
                        {
                            continue;
                        }

                        restorePath = saveDialog.FileName;
                    }
                }

                if (!string.IsNullOrWhiteSpace(entry.Sha256))
                {
                    statusLabel.Text = $"Verifying quarantined file: {Path.GetFileName(entry.QuarantinePath)}";
                    var quarantinedHash = await FileHash.Sha256FileAsync(entry.QuarantinePath);
                    if (!string.Equals(quarantinedHash, entry.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException("Quarantined file hash no longer matches the manifest.");
                    }
                }

                if (IsWindowsOrProgramFilesPath(restorePath))
                {
                    var sensitiveAccepted = MessageBox.Show(
                        this,
                        $"Restore into a protected system or Program Files location?{Environment.NewLine}{restorePath}",
                        "Confirm protected restore",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Warning);
                    if (sensitiveAccepted != DialogResult.Yes)
                    {
                        continue;
                    }
                }

                var restoreDirectory = Path.GetDirectoryName(restorePath);
                if (!string.IsNullOrWhiteSpace(restoreDirectory))
                {
                    Directory.CreateDirectory(restoreDirectory);
                }

                if (File.Exists(restorePath))
                {
                    File.Delete(restorePath);
                }

                File.Move(entry.QuarantinePath, restorePath);
                manifest.RemoveAll(item => string.Equals(item.QuarantinePath, entry.QuarantinePath, StringComparison.OrdinalIgnoreCase));
                restored++;
                restoredEntries.Add(entry);
                AppendQuarantineLog(restoreToDesktop ? "restore-desktop" : "restore", entry.QuarantinePath, restorePath, "restored from quarantine");
            }
            catch (Exception ex)
            {
                AppendQuarantineLog("restore-failed", entry.QuarantinePath, entry.OriginalPath, ex.Message);
                failures.Add($"{entry.OriginalPath}: {ex.Message}");
            }
        }

        SaveQuarantineManifest(manifest);
        statusLabel.Text = $"Restored {restored} quarantined file(s).";
        if (failures.Count > 0)
        {
            MessageBox.Show(this, string.Join(Environment.NewLine, failures.Take(8)), "Some files could not be restored", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        RemoveQuarantineRows(view, restoredEntries);
    }

    private static string GetDesktopRestorePath(QuarantineEntry entry)
    {
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        if (string.IsNullOrWhiteSpace(desktop))
        {
            desktop = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        }

        var originalName = Path.GetFileName(entry.OriginalPath);
        if (string.IsNullOrWhiteSpace(originalName))
        {
            originalName = Path.GetFileNameWithoutExtension(entry.QuarantinePath);
        }

        foreach (var invalidChar in Path.GetInvalidFileNameChars())
        {
            originalName = originalName.Replace(invalidChar, '_');
        }

        if (string.IsNullOrWhiteSpace(originalName))
        {
            originalName = "HashGuard-Restored-File";
        }

        var candidate = Path.Combine(desktop, originalName);
        if (!File.Exists(candidate))
        {
            return candidate;
        }

        var name = Path.GetFileNameWithoutExtension(originalName);
        var extension = Path.GetExtension(originalName);
        for (var index = 1; index < 1000; index++)
        {
            candidate = Path.Combine(desktop, $"{name} ({index}){extension}");
            if (!File.Exists(candidate))
            {
                return candidate;
            }
        }

        return Path.Combine(desktop, $"{name}-{DateTime.Now:yyyyMMddHHmmss}{extension}");
    }

    private void RepairMissingQuarantineEntries()
    {
        var manifest = LoadQuarantineManifest();
        var staleEntries = manifest
            .Where(entry => !File.Exists(entry.QuarantinePath))
            .ToList();
        if (staleEntries.Count == 0)
        {
            MessageBox.Show(this, "No missing quarantine entries were found.", "Repair quarantine", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var accepted = MessageBox.Show(
            this,
            $"Remove {staleEntries.Count} stale manifest entr{(staleEntries.Count == 1 ? "y" : "ies")} for quarantined files that no longer exist?",
            "Repair quarantine",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);
        if (accepted != DialogResult.Yes)
        {
            return;
        }

        manifest.RemoveAll(entry => !File.Exists(entry.QuarantinePath));
        SaveQuarantineManifest(manifest);
        foreach (var entry in staleEntries)
        {
            AppendQuarantineLog("repair-missing", entry.QuarantinePath, entry.OriginalPath, "removed stale manifest entry");
        }

        statusLabel.Text = $"Removed {staleEntries.Count} stale quarantine entr{(staleEntries.Count == 1 ? "y" : "ies")}.";
    }

    private void DeleteSelectedQuarantineEntries(ListView view)
    {
        var entries = GetSelectedQuarantineEntries(view);
        if (entries.Count == 0)
        {
            MessageBox.Show(this, "Select one or more quarantined files first.", "No quarantine selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var accepted = MessageBox.Show(this, $"Permanently delete {entries.Count} quarantined file(s)?", "Delete quarantine", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
        if (accepted != DialogResult.Yes)
        {
            return;
        }

        var manifest = LoadQuarantineManifest();
        var deletedEntries = new List<QuarantineEntry>();
        foreach (var entry in entries)
        {
            try
            {
                if (File.Exists(entry.QuarantinePath))
                {
                    File.Delete(entry.QuarantinePath);
                }

                manifest.RemoveAll(item => string.Equals(item.QuarantinePath, entry.QuarantinePath, StringComparison.OrdinalIgnoreCase));
                deletedEntries.Add(entry);
                AppendQuarantineLog("delete", entry.QuarantinePath, entry.OriginalPath, "deleted from quarantine");
            }
            catch (Exception ex)
            {
                AppendQuarantineLog("delete-failed", entry.QuarantinePath, entry.OriginalPath, ex.Message);
                MessageBox.Show(this, ex.Message, "Delete quarantine failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        SaveQuarantineManifest(manifest);
        statusLabel.Text = "Selected quarantine entries deleted.";
        RemoveQuarantineRows(view, deletedEntries);
    }

    private static void RemoveQuarantineRows(ListView view, List<QuarantineEntry> entries)
    {
        var quarantinedPaths = entries
            .Select(entry => entry.QuarantinePath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var item in view.Items.Cast<ListViewItem>().ToList())
        {
            if (item.Tag is QuarantineEntry entry && quarantinedPaths.Contains(entry.QuarantinePath))
            {
                view.Items.Remove(item);
            }
        }
    }

    private static List<QuarantineEntry> GetSelectedQuarantineEntries(ListView view)
    {
        return view.SelectedItems
            .Cast<ListViewItem>()
            .Select(item => item.Tag as QuarantineEntry)
            .Where(entry => entry is not null)
            .Cast<QuarantineEntry>()
            .ToList();
    }

    private static List<QuarantineEntry> LoadQuarantineManifest()
    {
        try
        {
            var path = GetQuarantineManifestPath();
            return File.Exists(path)
                ? JsonSerializer.Deserialize<List<QuarantineEntry>>(File.ReadAllText(path, Encoding.UTF8)) ?? []
                : [];
        }
        catch
        {
            return [];
        }
    }

    private static void SaveQuarantineManifest(List<QuarantineEntry> manifest)
    {
        Directory.CreateDirectory(AppPaths.GetConfigDirectory());
        File.WriteAllText(
            GetQuarantineManifestPath(),
            JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }),
            Encoding.UTF8);
    }

    private static void AppendQuarantineLog(string action, string sourcePath, string targetPath, string details)
    {
        try
        {
            var logDir = AppPaths.GetLogDirectory();
            Directory.CreateDirectory(logDir);
            var logPath = Path.Combine(logDir, $"quarantine-log-{DateTime.Now:yyyyMMdd}.csv");
            var writeHeader = !File.Exists(logPath);
            using var writer = new StreamWriter(logPath, append: true, Encoding.UTF8);
            if (writeHeader)
            {
                writer.WriteLine("timestamp_computer_time,action,source_path,target_path,details");
            }

            writer.WriteLine(string.Join(",", new[]
            {
                Csv(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")),
                Csv(action),
                Csv(sourcePath),
                Csv(targetPath),
                Csv(details),
            }));
        }
        catch
        {
            // Quarantine logging must never block the quarantine action itself.
        }
    }

    private static void MarkRowsQuarantined(ListView view, string originalPath, string quarantinePath)
    {
        foreach (var item in view.Items.Cast<ListViewItem>().ToList())
        {
            if (!string.Equals(GetSubItemText(item, ColPath), originalPath, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (view.Name == MainResultsViewName)
            {
                view.Items.Remove(item);
                continue;
            }

            var notes = GetSubItemText(item, ColNotes);
            item.SubItems[ColNotes].Text = string.IsNullOrWhiteSpace(notes)
                ? $"Quarantined to {quarantinePath}"
                : $"{notes}; Quarantined to {quarantinePath}";
            ApplyResultRowColor(item);
        }
    }
}
