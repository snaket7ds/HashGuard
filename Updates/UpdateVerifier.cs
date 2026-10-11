using System.Security.Cryptography;
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

    /// <summary>
    /// Public key that signs release builds: ECDSA P-256, SubjectPublicKeyInfo DER, base64.
    /// It is not secret. It stays empty until the release key is generated, and while it is
    /// empty no update installs (fail closed). See scripts/sign-release.sh.
    /// </summary>
    internal const string ReleasePublicKeyBase64 = "";

    /// <summary>
    /// Checks a detached release signature: the file's SHA-256 must verify against an
    /// ECDSA P-256 signature (DER) made with the release key. The SHA-256 check alone
    /// cannot tell a genuine release from a tampered one, because the expected hash
    /// comes from the same GitHub release as the binary.
    /// </summary>
    public static bool VerifyDetachedSignature(string filePath, byte[] signatureDer, string publicKeyBase64, out string detail)
    {
        detail = "";
        if (string.IsNullOrWhiteSpace(publicKeyBase64))
        {
            detail = "No release signing key is configured in this build; refusing the update.";
            return false;
        }

        if (signatureDer.Length == 0)
        {
            detail = "Release signature is empty.";
            return false;
        }

        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyBase64), out _);
            byte[] hash;
            using (var stream = File.OpenRead(filePath))
            {
                hash = SHA256.HashData(stream);
            }

            if (!ecdsa.VerifyHash(hash, signatureDer, DSASignatureFormat.Rfc3279DerSequence))
            {
                detail = "Release signature does not match the downloaded file.";
                return false;
            }
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or IOException)
        {
            detail = $"Release signature could not be checked: {ex.GetType().Name}.";
            return false;
        }

        detail = "Release signature verified.";
        return true;
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
    /// Authenticode publisher check after SHA-256 verification.
    /// GitHub release builds are often unsigned; only fail when BOTH files are signed
    /// and the publisher names differ. Never block a hash-verified update solely because
    /// the download is unsigned.
    /// </summary>
    public static bool PublisherMatchesCurrentBuild(string currentExePath, string updateExePath, out string detail)
    {
        detail = "";
        var currentPublisher = TryGetPublisher(currentExePath);
        var updatePublisher = TryGetPublisher(updateExePath);

        if (string.IsNullOrWhiteSpace(updatePublisher))
        {
            detail = "Update is unsigned; relying on SHA-256 only.";
            return true;
        }

        if (string.IsNullOrWhiteSpace(currentPublisher))
        {
            detail = "Current build is unsigned; update publisher accepted after SHA-256.";
            return true;
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
