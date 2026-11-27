using System.Drawing;
using System.Drawing.Drawing2D;

namespace HashGuardScanner;

/// <summary>
/// The design's line icons (24×24 grid, 1.8 stroke, round caps), drawn as vectors so the sidebar
/// and Home cards match the mockup instead of approximating it with Segoe MDL2 glyphs.
/// A glyph string "icon:&lt;name&gt;" selects one of these; anything else is drawn as text.
/// </summary>
internal static class LineIcons
{
    public const string Prefix = "icon:";

    public static bool IsIcon(string glyph) => glyph.StartsWith(Prefix, StringComparison.Ordinal);

    public static void Draw(Graphics g, string glyph, RectangleF box, Color color)
    {
        var name = IsIcon(glyph) ? glyph[Prefix.Length..] : glyph;
        var state = g.Save();
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TranslateTransform(box.X, box.Y);
        var scale = Math.Min(box.Width, box.Height) / 24f;
        g.ScaleTransform(scale, scale);
        using var pen = new Pen(color, 1.8f) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round };
        switch (name)
        {
            case "home":
                g.DrawLines(pen, new[] { new PointF(3.5f, 10.5f), new PointF(12, 3.5f), new PointF(20.5f, 10.5f) });
                g.DrawLines(pen, new[] { new PointF(5.5f, 9), new PointF(5.5f, 20), new PointF(18.5f, 20), new PointF(18.5f, 9) });
                break;
            case "scan":
                g.DrawEllipse(pen, 4.5f, 4.5f, 13, 13);
                g.DrawLine(pen, 20, 20, 15.8f, 15.8f);
                break;
            case "quarantine":
                g.DrawPolygon(pen, new[] { new PointF(4, 8.5f), new PointF(12, 4), new PointF(20, 8.5f), new PointF(20, 15.5f), new PointF(12, 20), new PointF(4, 15.5f) });
                g.DrawLines(pen, new[] { new PointF(4, 8.5f), new PointF(12, 13), new PointF(20, 8.5f) });
                g.DrawLine(pen, 12, 13, 12, 20);
                break;
            case "firewall":
                using (var frame = RoundedPaint.RoundedRect(new RectangleF(3.5f, 4.5f, 17, 15), 2))
                {
                    g.DrawPath(pen, frame);
                }

                g.DrawLine(pen, 3.5f, 9.5f, 20.5f, 9.5f);
                g.DrawLine(pen, 3.5f, 14.5f, 20.5f, 14.5f);
                g.DrawLine(pen, 9, 4.5f, 9, 9.5f);
                g.DrawLine(pen, 15, 9.5f, 15, 14.5f);
                g.DrawLine(pen, 9, 14.5f, 9, 19.5f);
                break;
            case "activity":
                g.DrawEllipse(pen, 3.5f, 3.5f, 17, 17);
                g.DrawLines(pen, new[] { new PointF(12, 7.5f), new PointF(12, 12), new PointF(15, 14) });
                break;
            case "shield":
                using (var shield = new GraphicsPath())
                {
                    shield.AddLine(12, 3, 5.5f, 5.6f);
                    shield.AddLine(5.5f, 5.6f, 5.5f, 11.2f);
                    shield.AddBezier(5.5f, 11.2f, 5.5f, 15.2f, 8.2f, 18.7f, 12, 20);
                    shield.AddBezier(12, 20, 15.8f, 18.7f, 18.5f, 15.2f, 18.5f, 11.2f);
                    shield.AddLine(18.5f, 11.2f, 18.5f, 5.6f);
                    shield.CloseFigure();
                    g.DrawPath(pen, shield);
                }

                break;
        }

        g.Restore(state);
    }
}
