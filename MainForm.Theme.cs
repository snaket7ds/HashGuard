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
    private ThemePalette activePalette = ThemePalette.Light;

    private void ApplyAppTheme(Control root)
    {
        var palette = GetCurrentPalette();
        activePalette = palette;
        ApplyTheme(root, palette, inHeader: false);
        if (scanCancellation is null)
        {
            SetScanButtonReadyStyle();
        }
        else
        {
            SetScanButtonStopStyle();
        }
        resultsView.BackColor = palette.Surface;
        resultsView.ForeColor = palette.Text;
        resultsEmptyLabel.ForeColor = palette.MutedText;
        summaryLabel.PillColor = palette.PillBack;
        statusSubtitle.ForeColor = palette.MutedText;
        UpdateReviewCount();
        UpdateReputationTile();
        UpdateQuarantineTile();
        statusDot.Invalidate();
    }

    private ThemePalette GetCurrentPalette()
    {
        return appSettings.ColorMode switch
        {
            AppConstants.ColorModeDark => ThemePalette.Dark,
            AppConstants.ColorModeLight => ThemePalette.Light,
            _ => IsWindowsDarkAppTheme() ? ThemePalette.Dark : ThemePalette.Light,
        };
    }

    private static int ColorModeToIndex(string colorMode, bool legacyUseSystemDefaultColors)
    {
        return colorMode switch
        {
            AppConstants.ColorModeLight => 1,
            AppConstants.ColorModeDark => 2,
            AppConstants.ColorModeSystem => 0,
            _ => legacyUseSystemDefaultColors ? 0 : 1,
        };
    }

    private static string IndexToColorMode(int index)
    {
        return index switch
        {
            1 => AppConstants.ColorModeLight,
            2 => AppConstants.ColorModeDark,
            _ => AppConstants.ColorModeSystem,
        };
    }

    private static bool IsWindowsDarkAppTheme()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int value && value == 0;
        }
        catch
        {
            return false;
        }
    }

    private static void ApplyTheme(Control control, ThemePalette palette, bool inHeader)
    {
        var header = inHeader || control.Tag as string == "header";
        var brandStrip = control.Tag as string == "brand-strip";
        switch (control)
        {
            case Form:
                control.BackColor = palette.AppBack;
                control.ForeColor = palette.Text;
                break;
            case ListView listView:
                listView.BackColor = palette.Surface;
                listView.ForeColor = palette.Text;
                break;
            case TextBox textBox:
                textBox.BackColor = palette.InputBack;
                textBox.ForeColor = palette.Text;
                break;
            case NumericUpDown numeric:
                numeric.BackColor = palette.InputBack;
                numeric.ForeColor = palette.Text;
                break;
            case ComboBox comboBox:
                comboBox.BackColor = palette.InputBack;
                comboBox.ForeColor = palette.Text;
                break;
            case Button button when button.Text is "Scan Now" or "Run Scan" or "Stop Scan":
                break;
            case Button button:
                button.FlatStyle = FlatStyle.Flat;
                button.FlatAppearance.BorderSize = 1;
                button.FlatAppearance.BorderColor = header ? palette.HeaderButtonBorder : palette.Border;
                button.BackColor = header ? palette.HeaderButtonBack : palette.ButtonBack;
                button.ForeColor = header ? palette.HeaderText : palette.Text;
                // Feedback on press, not on release.
                button.FlatAppearance.MouseOverBackColor = palette.SurfaceHover;
                button.FlatAppearance.MouseDownBackColor = palette.SurfacePressed;
                if (button.Tag as string == "danger-button")
                {
                    button.ForeColor = palette.DangerText;
                    button.FlatAppearance.BorderColor = Color.FromArgb(110, palette.DangerText);
                }
                else if (button.Tag as string == "quiet-button")
                {
                    button.FlatAppearance.BorderSize = 0;
                    button.BackColor = palette.Surface;
                    button.ForeColor = palette.MutedText;
                }
                break;
            case CardPanel card:
                card.BackColor = palette.AppBack;
                card.SurfaceColor = palette.Surface;
                card.HoverColor = palette.SurfaceHover;
                card.PressedColor = palette.SurfacePressed;
                card.EdgeColor = palette.Hairline;
                card.ShadowColor = palette.CardShadow;
                card.ForeColor = palette.Text;
                card.Invalidate();
                break;
            case IconBadge badge:
                badge.TintColor = (badge.Tag as string) switch
                {
                    "brand" => BrandGreen,
                    "neutral" => palette.NeutralTint,
                    _ => palette.AccentTint,
                };
                badge.GlyphColor = (badge.Tag as string) switch
                {
                    "brand" => Color.FromArgb(18, 38, 10),
                    "neutral" => palette.MutedText,
                    _ => palette.AccentText,
                };
                badge.Invalidate();
                break;
            case CheckBox:
            case Label:
                if (control.Tag as string == "callout")
                {
                    control.BackColor = palette.CalloutBack;
                    control.ForeColor = palette.Text;
                    break;
                }

                if (control.Tag as string is "header-title")
                {
                    control.ForeColor = palette.HeaderText;
                    control.BackColor = Color.Transparent;
                    break;
                }

                if (control.Tag as string is "header-sub" or "muted")
                {
                    control.ForeColor = palette.MutedText;
                    control.BackColor = Color.Transparent;
                    break;
                }

                if (control.Tag as string is "tile-ok")
                {
                    control.ForeColor = palette.AccentText;
                    control.BackColor = Color.Transparent;
                    break;
                }

                if (control.Tag as string is "chevron")
                {
                    control.ForeColor = palette.SubtleText;
                    control.BackColor = Color.Transparent;
                    break;
                }

                if (control is PillLabel)
                {
                    control.ForeColor = palette.Text;
                    break;
                }

                if (!header && control.ForeColor != DangerRed && control.ForeColor != SuccessGreen && control.ForeColor != BrandGreen)
                {
                    control.ForeColor = control.ForeColor == Color.DimGray ? palette.MutedText : palette.Text;
                }
                if (!header)
                {
                    control.BackColor = Color.Transparent;
                }
                break;
            case TabControl:
            case TabPage:
                control.BackColor = palette.Surface;
                control.ForeColor = palette.Text;
                break;
            case TableLayoutPanel:
            case FlowLayoutPanel:
            case Panel:
                if (brandStrip)
                {
                    control.BackColor = BrandGreen;
                    break;
                }

                if (control.Tag as string == "separator")
                {
                    control.BackColor = palette.Border;
                    break;
                }

                if (control.Tag as string == "footer")
                {
                    control.BackColor = palette.HeaderBack;
                    control.ForeColor = palette.Text;
                    break;
                }

                if (header)
                {
                    control.BackColor = palette.HeaderBack;
                    control.ForeColor = palette.HeaderText;
                    break;
                }

                // Keep soft app background on root layout panels.
                if (control.BackColor == SoftAppBack || control.BackColor == ThemePalette.Light.AppBack || control.BackColor == ThemePalette.Dark.AppBack || control.BackColor == Color.FromArgb(246, 247, 249))
                {
                    control.BackColor = palette.AppBack;
                }
                else if (control.BackColor == Color.White || control.BackColor == ThemePalette.Light.Surface || control.BackColor == ThemePalette.Dark.Surface)
                {
                    control.BackColor = palette.Surface;
                }
                control.ForeColor = palette.Text;
                break;
        }

        foreach (Control child in control.Controls)
        {
            ApplyTheme(child, palette, header);
        }
    }

    private static Label SectionLabel(string text)
    {
        return new Label
        {
            Text = text,
            AutoSize = true,
            Font = new Font("Segoe UI", 9, FontStyle.Bold),
            ForeColor = Color.FromArgb(35, 35, 35),
            Margin = new Padding(0, 10, 0, 4),
        };
    }
}
