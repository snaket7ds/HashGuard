using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace HashGuard.Core;

/// <summary>The reputation services' API keys, decrypted.</summary>
public sealed record ApiKeys(string VirusTotal, string MetaDefender)
{
    public static readonly ApiKeys None = new("", "");
}

/// <summary>
/// Reads and writes <c>config\settings.json</c>, the same file and format as v1, so an upgrade
/// keeps every setting. API keys are stored encrypted for the current Windows user (DPAPI).
/// </summary>
public sealed class SettingsStore(string? path = null)
{
    private static readonly JsonSerializerOptions WriteOptions = new() { WriteIndented = true };

    public string Path { get; } = path ?? AppPaths.GetAppSettingsPath();

    /// <summary>Loads settings; a missing or unreadable file gives the defaults.</summary>
    public AppSettings Load()
    {
        try
        {
            if (!File.Exists(Path))
            {
                return new AppSettings();
            }

            var json = File.ReadAllText(Path, Encoding.UTF8);
            var settings = JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
            settings.TrustedPublishers ??= new AppSettings().TrustedPublishers;
            settings.TrustedPublishers = HashGuardLogic.ExpandLegacyTrustedPublishers(settings.TrustedPublishers);
            settings.AutoBlockExceptions ??= [];
            ReadLegacyPlaintextKeys(settings, json);
            return settings;
        }
        catch
        {
            return new AppSettings();
        }
    }

    /// <summary>Saves settings with <paramref name="keys"/> encrypted. Plaintext keys are never written.</summary>
    public void Save(AppSettings settings, ApiKeys keys)
    {
        settings.ApiKeyEncrypted = Dpapi.Protect(keys.VirusTotal.Trim());
        settings.MetaDefenderApiKeyEncrypted = Dpapi.Protect(keys.MetaDefender.Trim());
        settings.ApiKey = "";
        settings.MetaDefenderApiKey = "";
        if (settings.TelemetryEnabled && string.IsNullOrWhiteSpace(settings.AnonymousInstallId))
        {
            settings.AnonymousInstallId = Guid.NewGuid().ToString("N");
        }

        settings.UseSystemDefaultColors = settings.ColorMode == AppConstants.ColorModeSystem;
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
        var temp = Path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(settings, WriteOptions), Encoding.UTF8);
        File.Move(temp, Path, overwrite: true);
    }

    /// <summary>
    /// The saved keys. A key that can't be decrypted (for example the file came from another
    /// Windows user) counts as missing; a legacy plaintext key is used until the next save encrypts it.
    /// </summary>
    public static ApiKeys ReadKeys(AppSettings settings) => new(
        ReadKey(settings.ApiKeyEncrypted, settings.ApiKey),
        ReadKey(settings.MetaDefenderApiKeyEncrypted, settings.MetaDefenderApiKey));

    private static string ReadKey(string encrypted, string legacyPlaintext)
    {
        if (!string.IsNullOrWhiteSpace(encrypted))
        {
            try
            {
                var key = Dpapi.Unprotect(encrypted).Trim();
                if (key.Length > 0)
                {
                    return key;
                }
            }
            catch
            {
                // Fall through to the legacy key.
            }
        }

        return legacyPlaintext.Trim();
    }

    /// <summary>Pre-DPAPI builds wrote plaintext keys; those properties are [JsonIgnore] now, so read them by hand.</summary>
    private static void ReadLegacyPlaintextKeys(AppSettings settings, string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return;
            }

            if (document.RootElement.TryGetProperty("ApiKey", out var vt) && vt.ValueKind == JsonValueKind.String)
            {
                settings.ApiKey = vt.GetString() ?? "";
            }

            if (document.RootElement.TryGetProperty("MetaDefenderApiKey", out var md) && md.ValueKind == JsonValueKind.String)
            {
                settings.MetaDefenderApiKey = md.GetString() ?? "";
            }
        }
        catch
        {
            // Legacy migration is best effort.
        }
    }
}

/// <summary>
/// Windows DPAPI for the current user, called directly. Same blobs as .NET's ProtectedData
/// (CurrentUser scope, no entropy), so keys saved by v1 decrypt here and the other way round.
/// </summary>
public static partial class Dpapi
{
    private const int UiForbidden = 0x1;

    public static string Protect(string plaintext)
    {
        if (string.IsNullOrEmpty(plaintext))
        {
            return "";
        }

        return Convert.ToBase64String(Transform(Encoding.UTF8.GetBytes(plaintext), protect: true));
    }

    public static string Unprotect(string base64)
    {
        if (string.IsNullOrWhiteSpace(base64))
        {
            return "";
        }

        return Encoding.UTF8.GetString(Transform(Convert.FromBase64String(base64), protect: false));
    }

    private static byte[] Transform(byte[] data, bool protect)
    {
        var input = new DataBlob();
        var output = new DataBlob();
        var handle = GCHandle.Alloc(data, GCHandleType.Pinned);
        try
        {
            input.Size = data.Length;
            input.Data = handle.AddrOfPinnedObject();
            var ok = protect
                ? CryptProtectData(ref input, 0, 0, 0, 0, UiForbidden, out output)
                : CryptUnprotectData(ref input, 0, 0, 0, 0, UiForbidden, out output);
            if (!ok)
            {
                throw new System.Security.Cryptography.CryptographicException(Marshal.GetLastPInvokeError());
            }

            var result = new byte[output.Size];
            Marshal.Copy(output.Data, result, 0, output.Size);
            return result;
        }
        finally
        {
            handle.Free();
            if (output.Data != 0)
            {
                LocalFree(output.Data);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int Size;
        public nint Data;
    }

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptProtectData(ref DataBlob dataIn, nint description, nint entropy, nint reserved, nint prompt, int flags, out DataBlob dataOut);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptUnprotectData(ref DataBlob dataIn, nint description, nint entropy, nint reserved, nint prompt, int flags, out DataBlob dataOut);

    [LibraryImport("kernel32.dll")]
    private static partial nint LocalFree(nint memory);
}
