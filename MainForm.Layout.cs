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
    private static void DrawHairline(Graphics graphics, int x, int y, int width, Color color)
    {
        using var pen = new Pen(color, 1);
        graphics.DrawLine(pen, x, y, x + width, y);
    }

    private void UpdateReviewCount()
    {
        UpdateReviewCount(results.Count(ResultNeedsAction));
    }

    private void UpdateReviewCount(int needsReview)
    {
        reviewCountLabel.Text = needsReview.ToString("N0");
        // Solid red with white text when something waits, as designed.
        reviewCountLabel.PillColor = needsReview > 0 ? Color.FromArgb(180, 35, 24) : activePalette.PillBack;
        reviewCountLabel.ForeColor = needsReview > 0 ? Color.White : activePalette.MutedText;
        reviewCountLabel.Invalidate();
        RefreshReviewList();
    }

    private IEnumerable<string> GetEnabledReputationProviders()
    {
        if (metaDefenderEnabledBox.Checked)
        {
            yield return "MetaDefender";
        }

        if (virusTotalEnabledBox.Checked)
        {
            yield return "VT";
        }

        if (mhrEnabledBox.Checked)
        {
            yield return "Malware Hash History";
        }
    }

    private static void WireClick(Control control, Action action)
    {
        control.Cursor = Cursors.Hand;
        control.Click += (_, _) => action();
        foreach (Control child in control.Controls)
        {
            WireClick(child, action);
        }
    }

    private static void ConfigureResultsView(ListView view)
    {
        if (view.Columns.Count > 0)
        {
            return;
        }

        if (view.Name == MainResultsViewName)
        {
            view.Columns.Add("Status", 112);
            view.Columns.Add("Risk", 92);
            view.Columns.Add("Trust / Publisher", 240);
            view.Columns.Add("Malicious", 0);
            view.Columns.Add("Suspicious", 0);
            view.Columns.Add("Process", 190);
            view.Columns.Add("PID(s)", 0);
            view.Columns.Add("SHA-256", 0);
            view.Columns.Add("Location", 440);
            view.Columns.Add("Recommended Review", 360);
        }
        else
        {
            view.Columns.Add("Status", 100);
            view.Columns.Add("Risk", 92);
            view.Columns.Add("Trust", 240);
            view.Columns.Add("Malicious", 84);
            view.Columns.Add("Suspicious", 84);
            view.Columns.Add("Process", 170);
            view.Columns.Add("PID(s)", 95);
            view.Columns.Add("SHA-256", 420);
            view.Columns.Add("Path", 520);
            view.Columns.Add("Notes", 360);
        }

        view.Dock = DockStyle.Fill;
        view.BackColor = Color.White;
        view.GridLines = false;
        view.HideSelection = false;
        view.BorderStyle = view.Name == MainResultsViewName ? BorderStyle.None : BorderStyle.FixedSingle;
        view.Font = new Font("Segoe UI", 9, FontStyle.Regular);
    }

    private static void PaintStatusBadge(Graphics graphics, Rectangle bounds, string state, ThemePalette palette)
    {
        // As designed: a soft halo, a solid circle, and a white outlined shield with a check
        // (protected), dot (scanning) or "!" (action needed). Static, no animation.
        graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        var size = Math.Max(24, Math.Min(bounds.Width, bounds.Height) - 2);
        var halo = new RectangleF(bounds.X + (bounds.Width - size) / 2f, bounds.Y + (bounds.Height - size) / 2f, size, size);
        var (fill, tint, symbol) = state switch
        {
            "action" => (Color.FromArgb(217, 45, 32), palette.DangerTint, SidebarNav.ShieldSymbol.Exclamation),
            "scanning" or "stopped" => (Color.FromArgb(217, 119, 6), palette.AttentionTint, SidebarNav.ShieldSymbol.Dot),
            "idle" => (Color.FromArgb(152, 162, 179), palette.NeutralTint, SidebarNav.ShieldSymbol.Check),
            _ => (ShieldGreen, palette.AccentTint, SidebarNav.ShieldSymbol.Check),
        };
        using (var haloBrush = new SolidBrush(tint))
        {
            graphics.FillEllipse(haloBrush, halo);
        }

        var inner = size * 0.72f;
        var disc = new RectangleF(halo.X + (size - inner) / 2, halo.Y + (size - inner) / 2, inner, inner);
        using (var discBrush = new SolidBrush(fill))
        {
            graphics.FillEllipse(discBrush, disc);
        }

        var shieldWidth = inner * 0.44f;
        var shieldHeight = shieldWidth * 1.16f;
        SidebarNav.PaintShieldOutline(graphics, new RectangleF(disc.X + (inner - shieldWidth) / 2, disc.Y + (inner - shieldHeight) / 2, shieldWidth, shieldHeight), symbol);
    }

    private static Icon CreateTrayStatusIcon(TrayState state)
    {
        using var bitmap = new Bitmap(64, 64);
        using var graphics = Graphics.FromImage(bitmap);
        graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        graphics.Clear(Color.Transparent);

        PaintTrayStatusIcon(graphics, state);

        var handle = bitmap.GetHicon();
        try
        {
            return (Icon)Icon.FromHandle(handle).Clone();
        }
        finally
        {
            DestroyIcon(handle);
        }
    }

    private static void PaintTrayStatusIcon(Graphics graphics, TrayState state)
    {
        // The HashGuard shield, matching the app: green + check (protected), amber + dot
        // (scanning), red + "!" (action needed). A thin white edge keeps it visible on dark taskbars.
        var (color, symbol) = state switch
        {
            TrayState.ActionNeeded => (Color.FromArgb(180, 35, 24), SidebarNav.ShieldSymbol.Exclamation),
            TrayState.Scanning => (Color.FromArgb(217, 119, 6), SidebarNav.ShieldSymbol.Dot),
            _ => (Color.FromArgb(24, 134, 74), SidebarNav.ShieldSymbol.Check),
        };
        SidebarNav.PaintShield(graphics, new RectangleF(7, 3, 50, 58), color, symbol, Color.FromArgb(235, 255, 255, 255));
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr handle);
}
