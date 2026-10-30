# gui/theme.py
"""Colour palette and application-wide stylesheet."""

BG = "#0b1020"
SURFACE = "#121a2d"
SURFACE_2 = "#18223a"
SURFACE_3 = "#1f2b47"
BORDER = "#25314f"
TEXT = "#e6ebf5"
MUTED = "#8b97b5"
SUBTLE = "#5c6886"

ACCENT = "#38bdf8"
ACCENT_HOVER = "#62cdfa"
ACCENT_DIM = "#0c4a6e"

SUCCESS = "#22c55e"
WARNING = "#f59e0b"
CRITICAL = "#ef4444"
INFO = ACCENT

LEVEL_COLORS = {
    "info": INFO,
    "success": SUCCESS,
    "warning": WARNING,
    "critical": CRITICAL,
}

LEVEL_LABELS = {
    "info": "INFO",
    "success": "OK",
    "warning": "WARNING",
    "critical": "CRITICAL",
}

FONT_FAMILY = "Segoe UI"
MONO_FAMILY = "Cascadia Mono, Consolas, monospace"

STYLESHEET = f"""
* {{
    font-family: "{FONT_FAMILY}";
    font-size: 13px;
    color: {TEXT};
}}
QMainWindow, QDialog, #Root {{
    background: {BG};
}}
QToolTip {{
    background: {SURFACE_3};
    color: {TEXT};
    border: 1px solid {BORDER};
    padding: 6px 8px;
    border-radius: 6px;
}}

/* Cards */
#Card {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 14px;
}}
#CardTitle {{
    font-size: 15px;
    font-weight: 600;
    background: transparent;
}}
#CardSubtitle, #Muted {{
    color: {MUTED};
    background: transparent;
}}
#StatValue {{
    font-size: 24px;
    font-weight: 700;
    background: transparent;
}}
#StatLabel {{
    color: {MUTED};
    font-size: 12px;
    font-weight: 600;
    background: transparent;
}}
#BrandTitle {{
    font-size: 22px;
    font-weight: 700;
    background: transparent;
}}
#BrandSubtitle {{
    color: {MUTED};
    font-size: 12px;
    background: transparent;
}}
QLabel {{
    background: transparent;
}}

/* Buttons */
QPushButton {{
    background: {SURFACE_2};
    border: 1px solid {BORDER};
    border-radius: 9px;
    padding: 9px 14px;
    font-weight: 600;
}}
QPushButton:hover {{
    background: {SURFACE_3};
    border-color: #34426a;
}}
QPushButton:pressed {{
    background: {BORDER};
}}
QPushButton:disabled {{
    color: {SUBTLE};
    background: {SURFACE};
}}
QPushButton[variant="primary"] {{
    background: {ACCENT};
    border: 1px solid {ACCENT};
    color: #04131f;
}}
QPushButton[variant="primary"]:hover {{
    background: {ACCENT_HOVER};
    border-color: {ACCENT_HOVER};
}}
QPushButton[variant="primary"]:disabled {{
    background: {ACCENT_DIM};
    border-color: {ACCENT_DIM};
    color: {MUTED};
}}
QPushButton[variant="ghost"] {{
    background: transparent;
    border: 1px solid transparent;
    color: {MUTED};
    padding: 6px 10px;
}}
QPushButton[variant="ghost"]:hover {{
    background: {SURFACE_2};
    color: {TEXT};
}}
QPushButton[variant="action"] {{
    text-align: left;
    padding: 12px 14px;
}}

/* Inputs */
QLineEdit, QComboBox {{
    background: {SURFACE_2};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 6px 10px;
    selection-background-color: {ACCENT_DIM};
}}
QLineEdit:focus, QComboBox:focus {{
    border-color: {ACCENT};
}}
QComboBox::drop-down {{
    border: none;
    width: 22px;
}}
QComboBox QAbstractItemView {{
    background: {SURFACE_2};
    border: 1px solid {BORDER};
    selection-background-color: {SURFACE_3};
    outline: none;
    padding: 4px;
}}

/* Tables */
QTableWidget {{
    background: transparent;
    border: none;
    gridline-color: transparent;
    selection-background-color: {SURFACE_3};
    selection-color: {TEXT};
    outline: none;
}}
QTableWidget::item {{
    padding: 4px 6px;
    border-bottom: 1px solid {SURFACE_2};
}}
QHeaderView {{
    background: {SURFACE};
    border: none;
}}
QHeaderView::section {{
    background: {SURFACE};
    color: {MUTED};
    border: none;
    border-bottom: 1px solid {BORDER};
    padding: 6px;
    font-size: 11px;
    font-weight: 700;
}}
QTableCornerButton::section {{
    background: transparent;
    border: none;
}}

QPlainTextEdit {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 10px;
    padding: 8px;
    font-family: {MONO_FAMILY};
    font-size: 12px;
    selection-background-color: {ACCENT_DIM};
}}

/* Scrollbars */
QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 2px;
}}
QScrollBar::handle:vertical {{
    background: {BORDER};
    border-radius: 3px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background: #34426a;
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
    margin: 2px;
}}
QScrollBar::handle:horizontal {{
    background: {BORDER};
    border-radius: 3px;
    min-width: 30px;
}}
QScrollBar::add-line, QScrollBar::sub-line {{
    width: 0; height: 0;
}}
QScrollBar::add-page, QScrollBar::sub-page {{
    background: none;
}}

QMenu {{
    background: {SURFACE_2};
    border: 1px solid {BORDER};
    padding: 4px;
}}
QMenu::item {{
    padding: 6px 18px;
    border-radius: 6px;
}}
QMenu::item:selected {{
    background: {SURFACE_3};
}}

QStatusBar {{
    background: {SURFACE};
    border-top: 1px solid {BORDER};
    color: {MUTED};
}}
QStatusBar QLabel {{
    color: {MUTED};
    padding: 0 8px;
}}
"""
