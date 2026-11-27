using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;

namespace HashGuard.Core;

/// <summary>Reads a file's Authenticode signer, cached by path, size and last-write time.</summary>
public static class SignatureReader
{
    public const string UnsignedSummary = "Unsigned or signature unavailable";

    private static readonly ConcurrentDictionary<string, SignatureInfo> Cache = new(StringComparer.OrdinalIgnoreCase);

    public static SignatureInfo Read(string path)
    {
        string cacheKey;
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                return new SignatureInfo(UnsignedSummary, "");
            }

            cacheKey = $"{path}|{info.Length}|{info.LastWriteTimeUtc.Ticks}";
        }
        catch
        {
            return new SignatureInfo(UnsignedSummary, "");
        }

        if (Cache.TryGetValue(cacheKey, out var cached))
        {
            return cached;
        }

        var signature = ReadUncached(path);
        if (Cache.Count > 20000)
        {
            Cache.Clear();
        }

        Cache[cacheKey] = signature;
        return signature;
    }

    private static SignatureInfo ReadUncached(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057 // No replacement API reads the Authenticode signer of a PE file.
            var certificate = X509Certificate.CreateFromSignedFile(path);
            using var cert2 = new X509Certificate2(certificate);
#pragma warning restore SYSLIB0057
            var publisher = cert2.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            var expired = DateTime.Now < cert2.NotBefore || DateTime.Now > cert2.NotAfter;
            using var chain = new X509Chain();
            // Offline revocation: online CRL/OCSP lookups cost up to seconds per file, and the
            // local cache is enough for the risk heuristic.
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(1);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            var chainValid = chain.Build(cert2);
            var chainStatus = chainValid
                ? "chain valid"
                : string.Join(", ", chain.ChainStatus.Select(status => status.Status.ToString()).Distinct());
            var summary = expired
                ? $"Signed by {publisher}; certificate outside validity period; {chainStatus}"
                : $"Signed by {publisher}; {chainStatus}";
            return new SignatureInfo(summary, publisher);
        }
        catch
        {
            return new SignatureInfo(UnsignedSummary, "");
        }
    }
}
