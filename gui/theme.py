# gui/theme.py
"""Soft-blue colour palette and application-wide stylesheet."""

BG = "#eef3fb"
BG_DEEP = "#e2ebf8"
SURFACE = "#ffffff"
SURFACE_2 = "#f5f8fe"
SURFACE_3 = "#eaf1fc"
BORDER = "#e1e9f6"
TEXT = "#1d2b4f"
MUTED = "#6b7a9c"
SUBTLE = "#a6b3cf"

ACCENT = "#4c8df6"
ACCENT_2 = "#7aa9ff"
ACCENT_DEEP = "#3a78e6"
ACCENT_SOFT = "#e6f0ff"

SUCCESS = "#2fbf8f"
WARNING = "#f2a33a"
CRITICAL = "#ef5b6e"
INFO = ACCENT

SHADOW = (76, 141, 246, 30)

LEVEL_COLORS = {
    "info": INFO,
    "success": SUCCESS,
    "warning": WARNING,
    "critical": CRITICAL,
}

LEVEL_LABELS = {
    "info": "Info",
    "success": "OK",
    "warning": "Warning",
    "critical": "Critical",
}

FONT_FAMILY = "Segoe UI"
MONO_FAMILY = "Cascadia Mono, Consolas, monospace"


def soft(color, alpha):
    """``color`` as an rgba() string with the given 0-1 alpha."""
    color = color.lstrip("#")
    r, g, b = (int(color[i:i + 2], 16) for i in (0, 2, 4))
    return f"rgba({r}, {g}, {b}, {alpha})"


STYLESHEET = f"""
* {{
    font-family: "{FONT_FAMILY}";
    font-size: 13px;
    color: {TEXT};
    outline: none;
}}
QMainWindow, QDialog {{
    background: {BG};
}}
QLabel {{
    background: transparent;
}}
QToolTip {{
    background: {TEXT};
    color: #ffffff;
    border: none;
    padding: 6px 9px;
    border-radius: 6px;
}}

#Card {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 18px;
}}
#CardTitle {{
    font-size: 15px;
    font-weight: 600;
}}
#Muted {{
    color: {MUTED};
}}
#BrandTitle {{
    font-size: 19px;
    font-weight: 700;
}}
#BrandSubtitle {{
    color: {MUTED};
    font-size: 12px;
}}
#Headline {{
    font-size: 20px;
    font-weight: 700;
}}

QPushButton {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 11px;
    padding: 8px 14px;
    font-weight: 600;
}}
QPushButton:hover {{
    background: {SURFACE_3};
    border-color: {ACCENT_2};
}}
QPushButton:pressed {{
    background: {ACCENT_SOFT};
}}
QPushButton:disabled {{
    color: {SUBTLE};
}}
QPushButton[variant="primary"] {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {ACCENT_2}, stop:1 {ACCENT});
    border: none;
    color: #ffffff;
}}
QPushButton[variant="primary"]:hover {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {ACCENT}, stop:1 {ACCENT_DEEP});
}}
QPushButton[variant="ghost"] {{
    background: transparent;
    border: 1px solid transparent;
    color: {MUTED};
}}
QPushButton[variant="ghost"]:hover {{
    background: {SURFACE};
    border-color: {BORDER};
    color: {TEXT};
}}
QPushButton[variant="chip"] {{
    background: transparent;
    border: none;
    border-radius: 9px;
    padding: 5px 12px;
    color: {MUTED};
}}
QPushButton[variant="chip"]:hover {{
    color: {TEXT};
}}
QPushButton[variant="chip"]:checked {{
    background: {SURFACE};
    color: {ACCENT_DEEP};
}}
#Segment {{
    background: {SURFACE_3};
    border-radius: 11px;
}}

QLineEdit {{
    background: {SURFACE_2};
    border: 1px solid {BORDER};
    border-radius: 11px;
    padding: 7px 12px;
    selection-background-color: {ACCENT_SOFT};
    selection-color: {TEXT};
}}
QLineEdit:focus {{
    border-color: {ACCENT_2};
    background: {SURFACE};
}}

QListView {{
    background: transparent;
    border: none;
}}
QPlainTextEdit {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 14px;
    padding: 10px;
    font-family: {MONO_FAMILY};
    font-size: 12px;
    selection-background-color: {ACCENT_SOFT};
    selection-color: {TEXT};
}}

QScrollBar:vertical {{
    background: transparent;
    width: 8px;
    margin: 4px 0;
}}
QScrollBar::handle:vertical {{
    background: {SUBTLE};
    border-radius: 4px;
    min-height: 36px;
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 8px;
    margin: 0 4px;
}}
QScrollBar::handle:horizontal {{
    background: {SUBTLE};
    border-radius: 4px;
    min-width: 36px;
}}
QScrollBar::add-line, QScrollBar::sub-line {{
    width: 0; height: 0;
}}
QScrollBar::add-page, QScrollBar::sub-page {{
    background: none;
}}

QMenu {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 12px;
    padding: 6px;
}}
QMenu::item {{
    padding: 8px 22px 8px 14px;
    border-radius: 8px;
}}
QMenu::item:selected {{
    background: {ACCENT_SOFT};
    color: {ACCENT_DEEP};
}}
QMenu::separator {{
    height: 1px;
    background: {BORDER};
    margin: 4px 8px;
}}
"""
