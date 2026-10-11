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
    private void QueueRecentShortcutTarget(string shortcutPath)
    {
        var targetPath = ResolveShortcutTarget(shortcutPath);
        if (!string.IsNullOrWhiteSpace(targetPath))
        {
            QueueAllFileScan(targetPath);
        }
    }

    private static string? ResolveShortcutTarget(string shortcutPath)
    {
        try
        {
            var shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType is null)
            {
                return null;
            }

            dynamic shell = Activator.CreateInstance(shellType)!;
            dynamic shortcut = shell.CreateShortcut(shortcutPath);
            string? targetPath = shortcut.TargetPath;
            return targetPath;
        }
        catch
        {
            return null;
        }
    }

    private void QueueExplorerSelectedFiles()
    {
        foreach (var path in GetExplorerSelectedFilePaths())
        {
            QueueAllFileScan(path);
        }
    }

    private static IEnumerable<string> GetExplorerSelectedFilePaths()
    {
        var shellType = Type.GetTypeFromProgID("Shell.Application");
        if (shellType is null)
        {
            yield break;
        }

        dynamic? shell = null;
        try
        {
            shell = Activator.CreateInstance(shellType);
        }
        catch
        {
            yield break;
        }

        if (shell is null)
        {
            yield break;
        }

        dynamic windows;
        try
        {
            windows = shell.Windows();
        }
        catch
        {
            yield break;
        }

        foreach (var window in windows)
        {
            if (!IsExplorerWindow(window))
            {
                continue;
            }

            foreach (var path in GetExplorerWindowFilePaths(window))
            {
                yield return path;
            }
        }
    }

    private static bool IsExplorerWindow(dynamic window)
    {
        try
        {
            var fullName = (string?)window.FullName;
            return !string.IsNullOrWhiteSpace(fullName) &&
                string.Equals(Path.GetFileName(fullName), "explorer.exe", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static IEnumerable<string> GetExplorerWindowFilePaths(dynamic window)
    {
        dynamic document;
        try
        {
            document = window.Document;
        }
        catch
        {
            yield break;
        }

        var yieldedSelected = false;
        dynamic selectedItems;
        try
        {
            selectedItems = document.SelectedItems();
        }
        catch
        {
            selectedItems = null!;
        }

        if (selectedItems is not null)
        {
            foreach (var item in selectedItems)
            {
                string? path = TryGetShellItemPath(item);
                if (!string.IsNullOrWhiteSpace(path))
                {
                    yieldedSelected = true;
                    yield return path;
                }
            }
        }

        if (yieldedSelected)
        {
            yield break;
        }

        string? focusedPath;
        try
        {
            focusedPath = TryGetShellItemPath(document.FocusedItem);
        }
        catch
        {
            yield break;
        }

        if (!string.IsNullOrWhiteSpace(focusedPath))
        {
            yield return focusedPath;
        }
    }

    private static string? TryGetShellItemPath(dynamic item)
    {
        try
        {
            string? path = item.Path;
            return path;
        }
        catch
        {
            return null;
        }
    }
}
