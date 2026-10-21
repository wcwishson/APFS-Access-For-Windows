using System.ComponentModel;
using System.Drawing.Drawing2D;
using System.Drawing.Text;

namespace ApfsAccess.Tray;

public sealed class ApfsStorageBarControl : Control
{
    public sealed record Segment(string Name, long Bytes, Color Color);

    private long _totalBytes;
    private long _freeBytes;
    private IReadOnlyList<Segment> _segments = [];
    private string _title = "APFS Container Storage Pool";

    public ApfsStorageBarControl()
    {
        SetStyle(
            ControlStyles.AllPaintingInWmPaint |
            ControlStyles.UserPaint |
            ControlStyles.OptimizedDoubleBuffer |
            ControlStyles.ResizeRedraw,
            true);

        DoubleBuffered = true;
        Dock = DockStyle.Top;
        Margin = new Padding(0, 0, 0, 8);
        Font = new Font("Segoe UI", 9F, FontStyle.Regular, GraphicsUnit.Point);
        BackColor = Color.FromArgb(248, 250, 252);
        UpdateControlHeight();
    }

    private int ScaleDpi(int value) => (int)Math.Round(value * DeviceDpi / 96.0f);

    public int CalculateRequiredHeight()
    {
        using var titleFont = new Font(Font, FontStyle.Bold);
        var titleHeight = TextRenderer.MeasureText("W", titleFont).Height;
        var barHeight = Math.Max(12, ScaleDpi(16));
        var legendHeight = TextRenderer.MeasureText("W", Font).Height;
        return titleHeight + barHeight + legendHeight + ScaleDpi(18);
    }

    private void UpdateControlHeight()
    {
        var req = CalculateRequiredHeight();
        if (Height != req)
        {
            Height = req;
            MinimumSize = new Size(0, req);
        }
    }

    protected override void OnFontChanged(EventArgs e)
    {
        base.OnFontChanged(e);
        UpdateControlHeight();
        Invalidate();
    }

    protected override void OnParentChanged(EventArgs e)
    {
        base.OnParentChanged(e);
        UpdateControlHeight();
    }

    public override Size GetPreferredSize(Size proposedSize)
    {
        var h = CalculateRequiredHeight();
        return new Size(proposedSize.Width > 0 ? proposedSize.Width : ScaleDpi(300), h);
    }

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public long TotalBytes
    {
        get => _totalBytes;
        set
        {
            if (_totalBytes != value)
            {
                _totalBytes = value;
                Invalidate();
            }
        }
    }

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public long FreeBytes
    {
        get => _freeBytes;
        set
        {
            if (_freeBytes != value)
            {
                _freeBytes = value;
                Invalidate();
            }
        }
    }

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public IReadOnlyList<Segment> Segments
    {
        get => _segments;
        set
        {
            _segments = value ?? [];
            Invalidate();
        }
    }

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string Title
    {
        get => _title;
        set
        {
            if (_title != value)
            {
                _title = value ?? string.Empty;
                Invalidate();
            }
        }
    }

    public void SetStorage(long totalBytes, long freeBytes, IReadOnlyList<Segment> segments, string? title = null)
    {
        _totalBytes = totalBytes;
        _freeBytes = freeBytes;
        _segments = segments ?? [];
        if (title is not null)
        {
            _title = title;
        }

        UpdateControlHeight();
        Invalidate();
    }

    private bool _isDarkMode;

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public bool IsDarkMode
    {
        get => _isDarkMode;
        set
        {
            if (_isDarkMode != value)
            {
                _isDarkMode = value;
                Invalidate();
            }
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);

        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;

        var client = ClientRectangle;
        if (client.Width < 20 || client.Height < 20)
        {
            return;
        }

        using var titleFont = new Font(Font, FontStyle.Bold);
        using var textBrush = new SolidBrush(_isDarkMode ? Color.FromArgb(241, 245, 249) : Color.FromArgb(51, 65, 85));
        using var mutedBrush = new SolidBrush(_isDarkMode ? Color.FromArgb(148, 163, 184) : Color.FromArgb(100, 116, 139));
        using var borderPen = new Pen(_isDarkMode ? Color.FromArgb(64, 68, 78) : Color.FromArgb(203, 213, 225), 1F);

        var titleHeight = TextRenderer.MeasureText(g, "W", titleFont).Height;
        var barHeight = Math.Max(10, ScaleDpi(16));
        var legendHeight = TextRenderer.MeasureText(g, "W", Font).Height;

        var titleText = _title;
        if (_totalBytes > 0)
        {
            var suffix = _title.Contains("Pool", StringComparison.OrdinalIgnoreCase) ? "Total Pool" : "Total Capacity";
            titleText += $"  ·  {DriveDashboardPresenter.FormatByteSize(_totalBytes)} {suffix}";
        }

        var padX = ScaleDpi(2);
        g.DrawString(titleText, titleFont, textBrush, new PointF(client.Left + padX, client.Top + ScaleDpi(1)));

        var barY = client.Top + titleHeight + ScaleDpi(4);
        var barWidth = client.Width - (padX * 2);
        var barRect = new Rectangle(client.Left + padX, barY, barWidth, barHeight);

        var barTrackColor = _isDarkMode ? Color.FromArgb(45, 48, 56) : Color.FromArgb(226, 232, 240);
        using var bgBrush = new SolidBrush(barTrackColor);
        g.FillRectangle(bgBrush, barRect);

        var effectiveSegments = _segments;
        if (effectiveSegments.Count == 0 && _totalBytes > 0 && _freeBytes >= 0 && _totalBytes >= _freeBytes)
        {
            var used = _totalBytes - _freeBytes;
            if (used > 0)
            {
                effectiveSegments = [new Segment("Allocated", used, Color.FromArgb(14, 165, 233))];
            }
        }

        if (_totalBytes > 0 && barWidth > 10)
        {
            var currentX = (float)barRect.Left;
            foreach (var segment in effectiveSegments)
            {
                if (segment.Bytes <= 0)
                {
                    continue;
                }

                var fraction = (float)segment.Bytes / _totalBytes;
                var segmentWidth = Math.Max(2F, fraction * barWidth);
                if (currentX + segmentWidth > barRect.Right)
                {
                    segmentWidth = barRect.Right - currentX;
                }

                if (segmentWidth > 0)
                {
                    using var segBrush = new SolidBrush(segment.Color);
                    g.FillRectangle(segBrush, currentX, barRect.Top, segmentWidth, barRect.Height);
                    currentX += segmentWidth;
                }
            }
        }

        g.DrawRectangle(borderPen, barRect);

        var legendY = barY + barHeight + ScaleDpi(6);
        var legendX = client.Left + padX;
        var swatchSize = Math.Max(7, ScaleDpi(9));
        var swatchYOffset = Math.Max(0, (legendHeight - swatchSize) / 2);

        foreach (var segment in effectiveSegments)
        {
            if (legendX > client.Right - ScaleDpi(50))
            {
                break;
            }

            var swatchRect = new Rectangle(legendX, legendY + swatchYOffset, swatchSize, swatchSize);
            using var swatchBrush = new SolidBrush(segment.Color);
            g.FillRectangle(swatchBrush, swatchRect);
            g.DrawRectangle(borderPen, swatchRect);
            legendX += swatchSize + ScaleDpi(4);

            var label = $"{segment.Name}: {DriveDashboardPresenter.FormatByteSize(segment.Bytes)}";
            var size = g.MeasureString(label, Font);
            g.DrawString(label, Font, textBrush, new PointF(legendX, legendY));
            legendX += (int)Math.Ceiling(size.Width) + ScaleDpi(14);
        }

        if (_freeBytes > 0 && legendX < client.Right - ScaleDpi(60))
        {
            var swatchRect = new Rectangle(legendX, legendY + swatchYOffset, swatchSize, swatchSize);
            using var swatchBrush = new SolidBrush(barTrackColor);
            g.FillRectangle(swatchBrush, swatchRect);
            g.DrawRectangle(borderPen, swatchRect);
            legendX += swatchSize + ScaleDpi(4);

            var label = $"Available Free: {DriveDashboardPresenter.FormatByteSize(_freeBytes)}";
            g.DrawString(label, Font, mutedBrush, new PointF(legendX, legendY));
        }
    }
}
