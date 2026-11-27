using System.Drawing;
using System.Drawing.Text;
using System.Reflection;
using System.Runtime.InteropServices;

namespace HashGuardScanner;

/// <summary>
/// The design's typeface, Inter (SIL Open Font License, Assets/Fonts), bundled so HashGuard looks
/// the same on every PC. The fonts are loaded once from embedded resources into a private font
/// collection (for GDI+) and into this process's GDI font table (for TextRenderer and native
/// controls), so nothing is installed system-wide.
///
/// The UI code still names fonts the way it always did ("Segoe UI", "Segoe UI Semibold");
/// <see cref="Create"/> maps those names to the matching Inter weight and falls back to the
/// original font if Inter could not be loaded. Icon fonts (Segoe MDL2 Assets) and Consolas pass
/// through unchanged. Every call returns a new Font, so callers may dispose it.
/// </summary>
internal static class UiFonts
{
    private static readonly object Gate = new();
    private static PrivateFontCollection? collection;
    private static Dictionary<string, FontFamily>? families;
    private static bool loadAttempted;

    public static Font Create(string family, float size) => Create(family, size, FontStyle.Regular);

    private static readonly Dictionary<(string Family, float Size, FontStyle Style), Font> Shared = [];

    /// <summary>
    /// A shared, cached font for paint code. Creating a Font from the private Inter collection on
    /// every repaint is what made page switches slow; these are created once. Never dispose them.
    /// </summary>
    public static Font Get(string family, float size, FontStyle style = FontStyle.Regular)
    {
        var key = (family, size, style);
        lock (Shared)
        {
            if (!Shared.TryGetValue(key, out var font))
            {
                font = Create(family, size, style);
                Shared[key] = font;
            }

            return font;
        }
    }

    public static Font Create(string family, float size, FontStyle style)
    {
        var mapped = Map(family);
        if (mapped is not null)
        {
            try
            {
                return new Font(mapped, size, style, GraphicsUnit.Point);
            }
            catch (ArgumentException)
            {
                // The style isn't available in that face; fall back below.
            }
        }

        return new Font(family, size, style);
    }

    /// <summary>True when Inter loaded (exposed for diagnostics and tests).</summary>
    public static bool InterAvailable => Families().Count > 0;

    private static FontFamily? Map(string family)
    {
        var loaded = Families();
        if (loaded.Count == 0)
        {
            return null;
        }

        var key = family.Trim().ToLowerInvariant() switch
        {
            "segoe ui" or "inter" => "Inter",
            "segoe ui semibold" or "inter semibold" => "Inter SemiBold",
            "segoe ui bold" => "Inter",
            "segoe ui medium" or "inter medium" => "Inter Medium",
            _ => null,
        };

        return key is not null && loaded.TryGetValue(key, out var match) ? match : null;
    }

    private static Dictionary<string, FontFamily> Families()
    {
        if (loadAttempted)
        {
            return families ?? [];
        }

        lock (Gate)
        {
            if (loadAttempted)
            {
                return families ?? [];
            }

            loadAttempted = true;
            try
            {
                var assembly = Assembly.GetExecutingAssembly();
                var pfc = new PrivateFontCollection();
                foreach (var name in assembly.GetManifestResourceNames().Where(name => name.EndsWith(".ttf", StringComparison.OrdinalIgnoreCase)))
                {
                    using var stream = assembly.GetManifestResourceStream(name);
                    if (stream is null)
                    {
                        continue;
                    }

                    var bytes = new byte[stream.Length];
                    stream.ReadExactly(bytes);
                    var memory = Marshal.AllocCoTaskMem(bytes.Length);
                    Marshal.Copy(bytes, 0, memory, bytes.Length);
                    // GDI+ copy (kept for the life of the process, as PrivateFontCollection requires).
                    pfc.AddMemoryFont(memory, bytes.Length);
                    // GDI copy, so TextRenderer and native controls draw the same face.
                    uint installed = 0;
                    AddFontMemResourceEx(memory, (uint)bytes.Length, IntPtr.Zero, ref installed);
                }

                collection = pfc;
                families = pfc.Families.ToDictionary(family => family.Name, StringComparer.OrdinalIgnoreCase);
            }
            catch
            {
                families = [];
            }

            return families;
        }
    }

    [DllImport("gdi32.dll")]
    private static extern IntPtr AddFontMemResourceEx(IntPtr pbFont, uint cbFont, IntPtr pdv, ref uint pcFonts);
}
