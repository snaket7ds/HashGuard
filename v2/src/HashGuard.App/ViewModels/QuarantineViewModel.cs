using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using HashGuard.App.Services;
using HashGuard.Core;

namespace HashGuard.App.ViewModels;

/// <summary>One quarantined file.</summary>
public sealed partial class QuarantineItemViewModel(QuarantineEntry entry, bool isMissing) : ObservableObject
{
    public QuarantineEntry Entry { get; } = entry;

    public QuarantineItemViewModel Self => this;

    public bool IsMissing { get; } = isMissing;

    public bool CanRestore => !IsMissing && !IsBusy;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanRestore))]
    public partial bool IsBusy { get; set; }

    public string Name => HashGuardLogic.QuarantineDisplayName(Entry);

    public string FromText => $"From {ActivityText.FriendlyPath(Entry.OriginalPath)}";

    public string InfoText
    {
        get
        {
            var parts = new List<string>();
            if (Entry.QuarantinedAtUtc != default)
            {
                parts.Add($"Quarantined {Entry.QuarantinedAtUtc.LocalDateTime.ToString("d MMM yyyy, HH:mm", CultureInfo.CurrentCulture)}");
            }

            if (Entry.Sha256.Length >= 12)
            {
                parts.Add($"SHA-256 {Entry.Sha256[..12]}…");
            }

            return string.Join(" · ", parts);
        }
    }
}

/// <summary>The Quarantine page: what's in quarantine, with restore and delete.</summary>
public sealed partial class QuarantineViewModel : ObservableObject
{
    public ObservableCollection<QuarantineItemViewModel> Items { get; } = [];

    [ObservableProperty] public partial bool HasItems { get; set; }
    [ObservableProperty] public partial bool HasMissing { get; set; }
    [ObservableProperty] public partial string SummaryText { get; set; } = "";

    /// <summary>Re-reads the manifest (v1 may have changed it) and checks which files are still there.</summary>
    public async Task LoadAsync()
    {
        var store = AppServices.Instance.Quarantine;
        var items = await Task.Run(() =>
        {
            store.Reload();
            return store.Entries.Select(entry => new QuarantineItemViewModel(entry, !HashGuardLogic.QuarantineEntryIsRestorable(entry))).ToList();
        });

        Items.Clear();
        foreach (var item in items)
        {
            Items.Add(item);
        }

        UpdateSummary();
    }

    /// <summary>Restores the file; returns an error message, or null when it worked.</summary>
    public async Task<string?> RestoreAsync(QuarantineItemViewModel item, string target, bool replaceExisting)
    {
        item.IsBusy = true;
        try
        {
            await AppServices.Instance.Quarantine.RestoreAsync(item.Entry, target, replaceExisting);
            Items.Remove(item);
            UpdateSummary();
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return $"Windows didn't allow writing to {Path.GetDirectoryName(target)}. Run HashGuard as administrator, or restore to the Desktop.";
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
        finally
        {
            item.IsBusy = false;
        }
    }

    public string? Delete(QuarantineItemViewModel item)
    {
        try
        {
            AppServices.Instance.Quarantine.Delete(item.Entry);
            Items.Remove(item);
            UpdateSummary();
            return null;
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    public void RemoveMissing()
    {
        AppServices.Instance.Quarantine.RemoveMissing();
        foreach (var item in Items.Where(item => item.IsMissing).ToList())
        {
            Items.Remove(item);
        }

        UpdateSummary();
    }

    private void UpdateSummary()
    {
        HasItems = Items.Count > 0;
        var missing = Items.Count(item => item.IsMissing);
        HasMissing = missing > 0;
        var present = Items.Count - missing;
        SummaryText = present switch
        {
            0 when missing == 0 => "Nothing in quarantine. Files you quarantine from a scan show up here.",
            0 => "No restorable files.",
            1 => "1 file in quarantine. It can't run while it's here.",
            _ => $"{present.ToString("N0", CultureInfo.CurrentCulture)} files in quarantine. They can't run while they're here.",
        };
        if (missing > 0)
        {
            SummaryText += missing == 1
                ? " 1 entry's file is missing from the quarantine folder."
                : $" {missing} entries' files are missing from the quarantine folder.";
        }
    }
}
