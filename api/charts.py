#!/usr/bin/env python3
"""Biểu đồ SVG inline, không phụ thuộc JS/CDN — an toàn cho serverless.
Màu theo palette đã validate (xem dataviz skill): status cho severity, categorical cho tool."""
from __future__ import annotations

from html import escape

BAR_HEIGHT = 26
BAR_GAP = 12
LABEL_COL = 150
VALUE_COL = 56


def bar_chart(items: list[tuple[str, float, str]], *, width: int = 520, unit: str = "") -> str:
    """items: [(label, value, color_hex), ...] đã sắp theo thứ tự muốn hiển thị."""
    if not items:
        return '<p class="chart-empty">Chưa có dữ liệu.</p>'
    max_v = max((v for _, v, _ in items), default=0) or 1
    plot_w = width - LABEL_COL - VALUE_COL
    height = len(items) * (BAR_HEIGHT + BAR_GAP)
    rows = []
    for i, (label, value, color) in enumerate(items):
        y = i * (BAR_HEIGHT + BAR_GAP)
        w = round((value / max_v) * plot_w, 1) if max_v else 0.0
        rows.append(f'''
<text x="{LABEL_COL - 12}" y="{y + BAR_HEIGHT / 2 + 4}" text-anchor="end" font-size="12.5" fill="var(--sn-ink-2)">{escape(str(label))}</text>
<rect x="{LABEL_COL}" y="{y}" width="{plot_w}" height="{BAR_HEIGHT}" rx="5" fill="var(--sn-grid)"/>
<rect x="{LABEL_COL}" y="{y}" width="{w}" height="{BAR_HEIGHT}" rx="5" fill="{color}">
  <title>{escape(str(label))}: {value}{unit}</title>
</rect>
<text x="{LABEL_COL + plot_w + 10}" y="{y + BAR_HEIGHT / 2 + 4}" font-size="12.5" font-weight="600" fill="var(--sn-ink)">{value}{unit}</text>''')
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'role="img" aria-label="bar chart" class="chart-svg">{"".join(rows)}</svg>'
    )


def stat_tile(label: str, value: str, *, hint: str = "") -> str:
    hint_html = f'<div class="stat-hint">{escape(hint)}</div>' if hint else ""
    return (
        f'<div class="stat-tile"><div class="stat-value">{escape(str(value))}</div>'
        f'<div class="stat-label">{escape(label)}</div>{hint_html}</div>'
    )
