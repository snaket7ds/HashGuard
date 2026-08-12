using System.Drawing;

namespace HashGuardScanner;

internal readonly record struct ThemePalette(
    Color AppBack,
    Color Surface,
    Color PillBack,
    Color InputBack,
    Color Text,
    Color MutedText,
    Color ButtonBack,
    Color Border,
    Color CalloutBack,
    Color HeaderBack,
    Color HeaderText,
    Color HeaderButtonBack,
    Color HeaderButtonBorder)
{
    // Soft consumer-security light theme (Webroot SecureAnywhere–inspired).
    public static ThemePalette Light { get; } = new(
        Color.FromArgb(242, 245, 247),
        Color.White,
        Color.FromArgb(236, 245, 230),
        Color.White,
        Color.FromArgb(32, 40, 48),
        Color.FromArgb(100, 110, 120),
        Color.FromArgb(245, 248, 250),
        Color.FromArgb(220, 226, 232),
        Color.FromArgb(248, 252, 245),
        Color.White,
        Color.FromArgb(32, 40, 48),
        Color.FromArgb(245, 248, 250),
        Color.FromArgb(220, 226, 232));

    public static ThemePalette Dark { get; } = new(
        Color.FromArgb(22, 28, 26),
        Color.FromArgb(32, 40, 36),
        Color.FromArgb(40, 52, 42),
        Color.FromArgb(28, 34, 30),
        Color.FromArgb(232, 240, 234),
        Color.FromArgb(150, 168, 156),
        Color.FromArgb(44, 54, 48),
        Color.FromArgb(60, 74, 64),
        Color.FromArgb(36, 48, 40),
        Color.FromArgb(28, 36, 32),
        Color.FromArgb(232, 240, 234),
        Color.FromArgb(44, 54, 48),
        Color.FromArgb(70, 86, 74));
}
