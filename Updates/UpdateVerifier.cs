using System.Security.Cryptography.X509Certificates;

namespace HashGuardScanner;

/// <summary>SHA-256 + optional Authenticode publisher checks for downloaded updates.</summary>
internal static class UpdateVerifier
{
    public static string ParseSha256Text(string text)
    {
        foreach (var token in text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (token.Length == 64 && token.All(Uri.IsHexDigit))
            {
                return token.ToLowerInvariant();
            }
        }

        return "";
    }

    public static string GetReleaseAssetSha256(GitHubAsset asset)
    {
        if (string.IsNullOrWhiteSpace(asset.Digest))
        {
            return "";
        }

        const string prefix = "sha256:";
        return asset.Digest.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            ? asset.Digest[prefix.Length..].Trim()
            : "";
    }

    public static string? TryGetPublisher(string path)
    {
        try
        {
            var certificate = X509Certificate.CreateFromSignedFile(path);
            using var cert2 = new X509Certificate2(certificate);
            return cert2.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// When the current executable is signed, require the update to share the same publisher name.
    /// Unsigned current builds skip the publisher check (local/dev).
    /// </summary>
    public static bool PublisherMatchesCurrentBuild(string currentExePath, string updateExePath, out string detail)
    {
        detail = "";
        var currentPublisher = TryGetPublisher(currentExePath);
        if (string.IsNullOrWhiteSpace(currentPublisher))
        {
            detail = "Current build is unsigned; publisher check skipped.";
            return true;
        }

        var updatePublisher = TryGetPublisher(updateExePath);
        if (string.IsNullOrWhiteSpace(updatePublisher))
        {
            detail = "Update is not Authenticode-signed.";
            return false;
        }

        if (!string.Equals(currentPublisher, updatePublisher, StringComparison.OrdinalIgnoreCase))
        {
            detail = $"Publisher mismatch: current '{currentPublisher}', update '{updatePublisher}'.";
            return false;
        }

        detail = $"Publisher matched: {updatePublisher}";
        return true;
    }
}
