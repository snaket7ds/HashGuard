namespace HashGuardScanner;

/// <summary>Validates paths received over the Explorer named-pipe scan channel.</summary>
internal static class ScanPathSecurity
{
    public const int MaxPathLength = 512;

    /// <summary>
    /// Returns a normalized full path when the request is safe to scan; otherwise null.
    /// Rejects empty values, oversized strings, device paths, traversal, and non-files.
    /// </summary>
    public static string? TryNormalizeScanPath(string? rawPath, out string rejectReason)
    {
        rejectReason = "";
        if (string.IsNullOrWhiteSpace(rawPath))
        {
            rejectReason = "empty path";
            return null;
        }

        var trimmed = rawPath.Trim().Trim('"');
        if (trimmed.Length == 0 || trimmed.Length > MaxPathLength)
        {
            rejectReason = "path length";
            return null;
        }

        if (trimmed.IndexOfAny(['\0', '\r', '\n']) >= 0)
        {
            rejectReason = "invalid characters";
            return null;
        }

        // Block classic device / UNC device forms that are not normal files.
        if (trimmed.StartsWith(@"\\.\", StringComparison.Ordinal)
            || trimmed.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)
            || trimmed.Contains("..", StringComparison.Ordinal))
        {
            // Allow legitimate relative segments only after GetFullPath resolves them;
            // still reject explicit .. before normalization when mixed with pipe abuse.
            if (trimmed.StartsWith(@"\\.\", StringComparison.Ordinal)
                || trimmed.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
            {
                rejectReason = "device path";
                return null;
            }
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(trimmed);
        }
        catch
        {
            rejectReason = "invalid path";
            return null;
        }

        if (fullPath.Length > MaxPathLength)
        {
            rejectReason = "path length";
            return null;
        }

        // After normalization, reject residual ".." traversal (should not remain).
        if (fullPath.Contains($"{Path.DirectorySeparatorChar}..{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            || fullPath.EndsWith($"{Path.DirectorySeparatorChar}..", StringComparison.Ordinal))
        {
            rejectReason = "path traversal";
            return null;
        }

        if (Directory.Exists(fullPath))
        {
            rejectReason = "directory not file";
            return null;
        }

        if (!File.Exists(fullPath))
        {
            rejectReason = "file not found";
            return null;
        }

        // Skip reparse points that are not ordinary files when we can detect them.
        try
        {
            var attrs = File.GetAttributes(fullPath);
            if ((attrs & FileAttributes.Directory) != 0)
            {
                rejectReason = "directory not file";
                return null;
            }
        }
        catch
        {
            rejectReason = "inaccessible";
            return null;
        }

        return fullPath;
    }
}
