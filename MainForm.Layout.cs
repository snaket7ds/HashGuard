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

    private static Panel CreateActionSeparator()
    {
        return new Panel { Width = 1, Height = 18, Margin = new Padding(6, 7, 12, 0), Tag = "separator" };
    }

    private void UpdateReviewCount()
    {
        UpdateReviewCount(results.Count(ResultNeedsAction));
    }

    private void UpdateReviewCount(int needsReview)
    {
        reviewCountLabel.Text = needsReview.ToString("N0");
        reviewCountLabel.PillColor = needsReview > 0 ? activePalette.DangerTint : activePalette.PillBack;
        reviewCountLabel.ForeColor = needsReview > 0 ? activePalette.DangerText : activePalette.MutedText;
        reviewCountLabel.Invalidate();
        actionLabel.PillColor = needsReview > 0 ? activePalette.DangerTint : activePalette.PillBack;
        actionLabel.ForeColor = needsReview > 0 ? activePalette.DangerText : activePalette.Text;
        actionLabel.Invalidate();
    }

    private static CardPanel CreateSoftCardPanel()
    {
        return new CardPanel
        {
            Dock = DockStyle.Fill,
            BackColor = SoftAppBack,
            BorderStyle = BorderStyle.None,
            Padding = new Padding(14),
        };
    }

    private static void ConfigureHeaderButton(Button button)
    {
        // Outline buttons on light chrome; the theme pass sets their colors.
        button.BackColor = Color.White;
        button.ForeColor = Color.FromArgb(27, 31, 36);
        button.FlatStyle = FlatStyle.Flat;
        button.FlatAppearance.BorderSize = 1;
        button.FlatAppearance.BorderColor = SoftBorder;
        button.UseVisualStyleBackColor = false;
    }

    private static Button CreateQueueActionButton(string text)
    {
        return new Button
        {
            Text = text,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            MinimumSize = new Size(84, 32),
            Height = 32,
            Margin = new Padding(0, 0, 6, 0),
            Padding = new Padding(8, 0, 8, 0),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.White,
            ForeColor = Color.FromArgb(27, 31, 36),
            Font = new Font("Segoe UI", 9, FontStyle.Regular),
            UseVisualStyleBackColor = false,
        };
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
        graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        // Static badge (no animation): a solid state circle inside a soft halo of the same hue.
        var outer = Math.Max(20, Math.Min(bounds.Width, bounds.Height) - 4);
        var actionNeeded = state == "action";
        var scanning = state is "scanning" or "stopped";
        var idle = state == "idle";
        var fillColor = actionNeeded
            ? DangerRed
            : scanning
                ? AttentionYellow
                : idle
                    ? Color.FromArgb(169, 180, 187)
                    : BrandGreen;
        var haloColor = actionNeeded
            ? palette.DangerTint
            : scanning
                ? palette.AttentionTint
                : idle
                    ? palette.NeutralTint
                    : palette.AccentTint;
        var haloRect = new RectangleF((bounds.Width - outer) / 2f, (bounds.Height - outer) / 2f, outer, outer);
        using (var halo = new SolidBrush(haloColor))
        {
            graphics.FillEllipse(halo, haloRect);
        }

        var size = outer * 0.74f;
        var rect = new RectangleF((bounds.Width - size) / 2f, (bounds.Height - size) / 2f, size, size);
        using (var fill = new SolidBrush(fillColor))
        {
            graphics.FillEllipse(fill, rect);
        }

        var glyphColor = actionNeeded || idle ? Color.White : Color.FromArgb(18, 38, 10);
        using var pen = new Pen(glyphColor, Math.Max(3, size / 11))
        {
            StartCap = System.Drawing.Drawing2D.LineCap.Round,
            EndCap = System.Drawing.Drawing2D.LineCap.Round,
            LineJoin = System.Drawing.Drawing2D.LineJoin.Round,
        };
        if (actionNeeded)
        {
            var centerX = rect.Left + rect.Width / 2f;
            graphics.DrawLine(pen, centerX, rect.Top + rect.Height * 0.25f, centerX, rect.Top + rect.Height * 0.58f);
            using var dot = new SolidBrush(Color.White);
            graphics.FillEllipse(dot, centerX - size * 0.065f, rect.Top + rect.Height * 0.70f, size * 0.13f, size * 0.13f);
        }
        else if (idle)
        {
            using var idlePen = new Pen(Color.White, Math.Max(3, size / 12));
            graphics.DrawEllipse(idlePen, rect.Left + size * 0.32f, rect.Top + size * 0.32f, size * 0.36f, size * 0.36f);
        }
        else if (scanning)
        {
            // Static activity bars (no animation).
            var cx = rect.Left + rect.Width / 2f;
            var cy = rect.Top + rect.Height / 2f;
            var barW = Math.Max(3f, size * 0.09f);
            var gap = size * 0.15f;
            using var barBrush = new SolidBrush(Color.FromArgb(42, 28, 0));
            for (var i = -1; i <= 1; i++)
            {
                var h = i == 0 ? size * 0.40f : size * 0.22f;
                var barRect = new RectangleF(cx + i * gap - barW / 2f, cy - h / 2f, barW, h);
                using var bar = RoundedPaint.RoundedRect(barRect, barW / 2f);
                graphics.FillPath(barBrush, bar);
            }
        }
        else
        {
            graphics.DrawLines(pen, new[]
            {
                new PointF(rect.Left + rect.Width * 0.28f, rect.Top + rect.Height * 0.51f),
                new PointF(rect.Left + rect.Width * 0.44f, rect.Top + rect.Height * 0.66f),
                new PointF(rect.Left + rect.Width * 0.73f, rect.Top + rect.Height * 0.35f),
            });
        }
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
        var badgeColor = state switch
        {
            TrayState.ActionNeeded => DangerRed,
            TrayState.Scanning => AttentionYellow,
            _ => BrandGreen,
        };

        using var badgeFill = new SolidBrush(badgeColor);
        using var badgeRing = new Pen(Color.FromArgb(24, 24, 24), 5.0f);
        using var badgeHighlight = new Pen(Color.White, 2.4f);
        using var badgePen = new Pen(Color.White, 8.0f) { StartCap = System.Drawing.Drawing2D.LineCap.Round, EndCap = System.Drawing.Drawing2D.LineCap.Round };
        graphics.FillEllipse(badgeFill, 4, 4, 56, 56);
        graphics.DrawEllipse(badgeRing, 4, 4, 56, 56);
        graphics.DrawArc(badgeHighlight, 12, 10, 38, 34, 205, 105);

        if (state == TrayState.Clean)
        {
            graphics.DrawLines(badgePen, new[] { new Point(17, 34), new Point(27, 45), new Point(47, 22) });
        }
        else if (state == TrayState.ActionNeeded)
        {
            graphics.DrawLine(badgePen, 32, 16, 32, 39);
            graphics.FillEllipse(Brushes.White, 27, 46, 10, 10);
        }
        else if (state == TrayState.Scanning)
        {
            graphics.FillEllipse(Brushes.White, 22, 22, 20, 20);
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr handle);
}
