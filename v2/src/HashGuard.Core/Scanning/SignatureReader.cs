using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace HashGuard.Core;

/// <summary>
/// Checks a file's signature the way Windows does (WinVerifyTrust): an embedded Authenticode
/// signature, or for files Windows signs through its catalogs (notepad.exe and most of System32),
/// the catalog that lists the file's hash. Revocation is not checked online, so a check costs
/// milliseconds. Results are cached by path, size and last-write time.
/// </summary>
/// <remarks>
/// Summaries keep v1's wording, which the risk score and Activity page read: "Signed by X; chain
/// valid" when Windows trusts the signature, "Signed by X; reason" when it doesn't, and
/// "Unsigned…" when there is no signature or it doesn't match the file.
/// </remarks>
public static partial class SignatureReader
{
    public const string UnsignedSummary = "Unsigned or signature unavailable";
    public const string MismatchSummary = "Unsigned: the signature doesn't match the file";
    public const string CatalogNote = "Windows catalog";

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
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
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

    internal static SignatureInfo ReadUncached(string path)
    {
        try
        {
            var embedded = VerifyEmbedded(path);
            // No signature, or a file type that can't carry one: Windows may still list it in a catalog.
            if (embedded is TrustNoSignature or TrustSubjectFormUnknown)
            {
                return ReadCatalogSigned(path);
            }

            if (embedded == TrustBadDigest)
            {
                return new SignatureInfo(MismatchSummary, "");
            }

            var publisher = SignerName(path);
            return publisher.Length == 0
                ? new SignatureInfo(UnsignedSummary, "")
                : new SignatureInfo(Summarize(publisher, embedded, catalog: false), publisher);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return new SignatureInfo(UnsignedSummary, "");
        }
    }

    private static SignatureInfo ReadCatalogSigned(string path)
    {
        if (FindCatalog(path) is not { } match)
        {
            return new SignatureInfo(UnsignedSummary, "");
        }

        var result = VerifyCatalogMember(path, match.CatalogPath, match.MemberTag);
        var publisher = SignerName(match.CatalogPath);
        return publisher.Length == 0
            ? new SignatureInfo(UnsignedSummary, "")
            : new SignatureInfo(Summarize(publisher, result, catalog: true), publisher);
    }

    /// <summary>"Signed by X; chain valid", or the reason Windows doesn't trust it.</summary>
    internal static string Summarize(string publisher, int trustResult, bool catalog)
    {
        var status = trustResult switch
        {
            0 => "chain valid",
            CertExpired => "certificate outside validity period",
            CertUntrustedRoot => "UntrustedRoot",
            CertRevoked => "Revoked",
            TrustExplicitDistrust => "ExplicitDistrust",
            _ => $"not trusted (0x{trustResult:X8})",
        };
        return catalog ? $"Signed by {publisher}; {status}; {CatalogNote}" : $"Signed by {publisher}; {status}";
    }

    /// <summary>The signer's name from a signed file or catalog, or "" when there is none.</summary>
    private static string SignerName(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057 // No replacement API reads the Authenticode signer of a PE file or catalog.
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false) ?? "";
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or IOException or UnauthorizedAccessException)
        {
            return "";
        }
    }

    // ---- WinVerifyTrust ----

    private const int TrustNoSignature = unchecked((int)0x800B0100);
    private const int TrustBadDigest = unchecked((int)0x80096010);
    private const int TrustSubjectFormUnknown = unchecked((int)0x800B0003);
    private const int TrustExplicitDistrust = unchecked((int)0x800B0111);
    private const int CertExpired = unchecked((int)0x800B0101);
    private const int CertUntrustedRoot = unchecked((int)0x800B0109);
    private const int CertRevoked = unchecked((int)0x800B010C);

    private const uint UiNone = 2;
    private const uint RevokeNone = 0;
    private const uint ChoiceFile = 1;
    private const uint ChoiceCatalog = 2;
    private const uint StateVerify = 1;
    private const uint StateClose = 2;
    private const uint RevocationCheckNone = 0x10;
    private const uint CacheOnlyUrlRetrieval = 0x1000;

    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private static readonly Guid DriverActionVerify = new("F750E6C3-38EE-11d1-85E5-00C04FC295EE");

    private static unsafe int VerifyEmbedded(string path)
    {
        fixed (char* filePath = path)
        {
            var file = new WinTrustFileInfo { Size = (uint)sizeof(WinTrustFileInfo), FilePath = (nint)filePath };
            return Verify(ChoiceFile, &file);
        }
    }

    private static unsafe int VerifyCatalogMember(string path, string catalogPath, string memberTag)
    {
        fixed (char* member = path)
        fixed (char* catalog = catalogPath)
        fixed (char* tag = memberTag)
        {
            var info = new WinTrustCatalogInfo
            {
                Size = (uint)sizeof(WinTrustCatalogInfo),
                CatalogFilePath = (nint)catalog,
                MemberTag = (nint)tag,
                MemberFilePath = (nint)member,
            };
            return Verify(ChoiceCatalog, &info);
        }
    }

    private static unsafe int Verify(uint choice, void* subject)
    {
        var data = new WinTrustData
        {
            Size = (uint)sizeof(WinTrustData),
            UiChoice = UiNone,
            RevocationChecks = RevokeNone,
            UnionChoice = choice,
            Subject = (nint)subject,
            StateAction = StateVerify,
            ProviderFlags = RevocationCheckNone | CacheOnlyUrlRetrieval,
        };
        var action = GenericVerifyV2;
        var result = WinVerifyTrust(-1, &action, &data);
        data.StateAction = StateClose;
        _ = WinVerifyTrust(-1, &action, &data);
        return result;
    }

    // ---- Catalog lookup ----

    private sealed record CatalogMatch(string CatalogPath, string MemberTag);

    /// <summary>The system catalog listing this file's hash (SHA-256 first, then SHA-1 for older catalogs).</summary>
    private static CatalogMatch? FindCatalog(string path)
    {
        using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return FindCatalog(handle, "SHA256") ?? FindCatalog(handle, null);
    }

    private static unsafe CatalogMatch? FindCatalog(SafeFileHandle file, string? hashAlgorithm)
    {
        var subsystem = DriverActionVerify;
        nint admin;
        fixed (char* algorithm = hashAlgorithm)
        {
            if (!CryptCATAdminAcquireContext2(&admin, &subsystem, (nint)algorithm, 0, 0))
            {
                return null;
            }
        }

        try
        {
            uint hashSize = 0;
            _ = CryptCATAdminCalcHashFromFileHandle2(admin, file.DangerousGetHandle(), &hashSize, null, 0);
            if (hashSize is 0 or > 64)
            {
                return null;
            }

            var hash = stackalloc byte[(int)hashSize];
            if (!CryptCATAdminCalcHashFromFileHandle2(admin, file.DangerousGetHandle(), &hashSize, hash, 0))
            {
                return null;
            }

            var catalogInfo = CryptCATAdminEnumCatalogFromHash(admin, hash, hashSize, 0, null);
            if (catalogInfo == 0)
            {
                return null;
            }

            try
            {
                var info = new CatalogInfo { Size = (uint)sizeof(CatalogInfo) };
                if (!CryptCATCatalogInfoFromContext(catalogInfo, &info, 0))
                {
                    return null;
                }

                var catalogPath = new string(info.CatalogFile);
                return new CatalogMatch(catalogPath, Convert.ToHexString(new ReadOnlySpan<byte>(hash, (int)hashSize)));
            }
            finally
            {
                _ = CryptCATAdminReleaseCatalogContext(admin, catalogInfo, 0);
            }
        }
        finally
        {
            _ = CryptCATAdminReleaseContext(admin, 0);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint Size;
        public nint FilePath;
        public nint File;
        public nint KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustCatalogInfo
    {
        public uint Size;
        public uint CatalogVersion;
        public nint CatalogFilePath;
        public nint MemberTag;
        public nint MemberFilePath;
        public nint MemberFile;
        public nint CalculatedFileHash;
        public uint CalculatedFileHashSize;
        public nint CatalogContext;
        public nint CatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint Size;
        public nint PolicyCallbackData;
        public nint SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public nint Subject;
        public uint StateAction;
        public nint StateData;
        public nint UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public nint SignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private unsafe struct CatalogInfo
    {
        public uint Size;
        public fixed char CatalogFile[260];
    }

    [LibraryImport("wintrust.dll")]
    private static unsafe partial int WinVerifyTrust(nint window, Guid* action, WinTrustData* data);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool CryptCATAdminAcquireContext2(nint* catAdmin, Guid* subsystem, nint hashAlgorithm, nint strongHashPolicy, uint flags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool CryptCATAdminCalcHashFromFileHandle2(nint catAdmin, nint file, uint* hashSize, byte* hash, uint flags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    private static unsafe partial nint CryptCATAdminEnumCatalogFromHash(nint catAdmin, byte* hash, uint hashSize, uint flags, nint* previousCatalog);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool CryptCATCatalogInfoFromContext(nint catalogInfo, CatalogInfo* info, uint flags);

    [LibraryImport("wintrust.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATAdminReleaseCatalogContext(nint catAdmin, nint catalogInfo, uint flags);

    [LibraryImport("wintrust.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATAdminReleaseContext(nint catAdmin, uint flags);
}
