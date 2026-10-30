# gui/widgets.py
"""Custom-painted, animated widgets for the SecureVault dashboard."""
import os
import math
import time
import threading
from collections import deque

from PyQt6.QtCore import (
    Qt, QTimer, QPoint, QPointF, QRectF, QSize, QPropertyAnimation,
    QVariantAnimation, QEasingCurve, QAbstractListModel, QModelIndex,
    QSortFilterProxyModel, pyqtProperty, pyqtSignal,
)
from PyQt6.QtGui import (
    QColor, QPainter, QPainterPath, QPen, QBrush, QLinearGradient,
    QRadialGradient, QConicalGradient, QIcon, QPixmap, QFont, QFontMetrics,
)
from PyQt6.QtWidgets import (
    QAbstractButton, QFrame, QLabel, QVBoxLayout, QHBoxLayout, QWidget,
    QGraphicsOpacityEffect, QGraphicsDropShadowEffect, QPushButton,
    QSizePolicy, QListView, QStyledItemDelegate, QStyle,
)

from gui import theme

try:
    import winsound
except ImportError:  # Non-Windows platforms
    winsound = None


# ---------------------------------------------------------------- helpers

def mix(a, b, t):
    """Blend two colours; ``t`` = 0 gives ``a``, 1 gives ``b``."""
    a, b = QColor(a), QColor(b)
    return QColor(
        round(a.red() + (b.red() - a.red()) * t),
        round(a.green() + (b.green() - a.green()) * t),
        round(a.blue() + (b.blue() - a.blue()) * t),
        round(a.alpha() + (b.alpha() - a.alpha()) * t),
    )


def with_alpha(color, alpha):
    c = QColor(color)
    c.setAlphaF(max(0.0, min(1.0, alpha)))
    return c


def add_shadow(widget, blur=36, dy=10, alpha=None):
    r, g, b, a = theme.SHADOW
    effect = QGraphicsDropShadowEffect(widget)
    effect.setBlurRadius(blur)
    effect.setOffset(0, dy)
    effect.setColor(QColor(r, g, b, a if alpha is None else alpha))
    widget.setGraphicsEffect(effect)
    return effect


def ease_out(t):
    t = max(0.0, min(1.0, t))
    return 1 - (1 - t) ** 3


def shield_path(rect):
    """A shield outline that fits inside ``rect``."""
    x, y, w, h = rect.x(), rect.y(), rect.width(), rect.height()
    path = QPainterPath()
    path.moveTo(x + w / 2, y)
    path.cubicTo(x + w * 0.72, y + h * 0.10, x + w * 0.88, y + h * 0.12, x + w, y + h * 0.13)
    path.cubicTo(x + w, y + h * 0.55, x + w * 0.82, y + h * 0.82, x + w / 2, y + h)
    path.cubicTo(x + w * 0.18, y + h * 0.82, x, y + h * 0.55, x, y + h * 0.13)
    path.cubicTo(x + w * 0.12, y + h * 0.12, x + w * 0.28, y + h * 0.10, x + w / 2, y)
    path.closeSubpath()
    return path


def paint_shield(painter, rect, color=theme.ACCENT, mark="check"):
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    base = QColor(color)
    gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
    gradient.setColorAt(0, base.lighter(135))
    gradient.setColorAt(1, base.darker(115))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QBrush(gradient))
    painter.drawPath(shield_path(rect))
    x, y, w, h = rect.x(), rect.y(), rect.width(), rect.height()
    pen = QPen(QColor("#ffffff"), max(1.5, w * 0.09))
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    if mark == "check":
        tick = QPainterPath(QPointF(x + w * 0.30, y + h * 0.50))
        tick.lineTo(x + w * 0.45, y + h * 0.64)
        tick.lineTo(x + w * 0.71, y + h * 0.36)
        painter.drawPath(tick)
    elif mark == "alert":
        painter.drawLine(QPointF(x + w / 2, y + h * 0.28), QPointF(x + w / 2, y + h * 0.52))
        painter.drawPoint(QPointF(x + w / 2, y + h * 0.68))
    elif mark == "pause":
        painter.drawLine(QPointF(x + w * 0.41, y + h * 0.34), QPointF(x + w * 0.41, y + h * 0.60))
        painter.drawLine(QPointF(x + w * 0.59, y + h * 0.34), QPointF(x + w * 0.59, y + h * 0.60))


def make_app_icon(color=theme.ACCENT):
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        margin = size * 0.06
        paint_shield(painter, QRectF(margin, margin, size - 2 * margin, size - 2 * margin), color)
        painter.end()
        icon.addPixmap(pixmap)
    return icon


class ShieldLogo(QWidget):
    def __init__(self, size=40, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)

    def paintEvent(self, event):
        painter = QPainter(self)
        m = self.width() * 0.04
        paint_shield(painter, QRectF(m, m, self.width() - 2 * m, self.height() - 2 * m))


class SoundManager:
    """Short synthesized alerts using the Windows beeper (no-op elsewhere)."""
    enabled = True

    @classmethod
    def _play(cls, notes):
        if not (cls.enabled and winsound):
            return

        def run():
            for freq, ms in notes:
                winsound.Beep(freq, ms)
        threading.Thread(target=run, daemon=True).start()

    @classmethod
    def play_warning(cls):
        cls._play([(880, 110)])

    @classmethod
    def play_alert(cls):
        cls._play([(800, 100), (1200, 100)] * 3)


# ------------------------------------------------------------- surfaces

class Card(QFrame):
    """White rounded surface with a soft blue shadow and optional title row."""
    def __init__(self, title=None, subtitle=None, parent=None, padding=(20, 18, 20, 18)):
        super().__init__(parent)
        self.setObjectName("Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(*padding)
        self.body.setSpacing(12)
        self.header = None
        if title:
            self.header = QHBoxLayout()
            self.header.setSpacing(8)
            titles = QVBoxLayout()
            titles.setSpacing(1)
            title_label = QLabel(title)
            title_label.setObjectName("CardTitle")
            titles.addWidget(title_label)
            if subtitle:
                sub = QLabel(subtitle)
                sub.setObjectName("Muted")
                sub.setStyleSheet("font-size: 12px;")
                titles.addWidget(sub)
            self.header.addLayout(titles)
            self.header.addStretch()
            self.body.addLayout(self.header)
        add_shadow(self)


class AnimatedValue(QLabel):
    """Label that counts smoothly to new integer values."""
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self._value = None
        self._fmt = "{:,}"
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(700)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(lambda v: super(AnimatedValue, self).setText(self._fmt.format(int(v))))

    def set_value(self, value, fmt="{:,}"):
        self._fmt = fmt
        if isinstance(value, int):
            start = self._value if isinstance(self._value, int) else 0
            self._value = value
            self._anim.stop()
            self._anim.setStartValue(start)
            self._anim.setEndValue(value)
            self._anim.start()
        else:
            self._anim.stop()
            self._value = value
            self.setText(str(value))


class Sparkline(QWidget):
    def __init__(self, points=40, parent=None):
        super().__init__(parent)
        self.data = deque([0.0] * points, maxlen=points)
        self.color = QColor(theme.ACCENT)
        self.setMinimumSize(90, 34)

    def add(self, value, color=None):
        self.data.append(value)
        if color:
            self.color = QColor(color)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height() - 4
        values = list(self.data)
        step = w / (len(values) - 1)
        pts = [QPointF(i * step, 2 + h - v / 100 * h) for i, v in enumerate(values)]
        line = QPainterPath(pts[0])
        for p0, p1 in zip(pts, pts[1:]):
            mx = (p0.x() + p1.x()) / 2
            line.cubicTo(QPointF(mx, p0.y()), QPointF(mx, p1.y()), p1)
        area = QPainterPath(line)
        area.lineTo(w, h + 2)
        area.lineTo(0, h + 2)
        area.closeSubpath()
        grad = QLinearGradient(0, 0, 0, h)
        grad.setColorAt(0, with_alpha(self.color, 0.28))
        grad.setColorAt(1, with_alpha(self.color, 0.0))
        painter.fillPath(area, grad)
        painter.setPen(QPen(self.color, 2))
        painter.drawPath(line)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(self.color)
        painter.drawEllipse(pts[-1], 3, 3)


class StatChip(QFrame):
    """Compact statistic: icon bubble, label, animated value and caption."""
    def __init__(self, glyph, label, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(12)
        self.bubble = QLabel(glyph)
        self.bubble.setFixedSize(42, 42)
        self.bubble.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.bubble, 0, Qt.AlignmentFlag.AlignTop)
        text = QVBoxLayout()
        text.setSpacing(0)
        self.label = QLabel(label)
        self.label.setObjectName("Muted")
        self.label.setStyleSheet("font-size: 12px; font-weight: 600;")
        self.value = AnimatedValue("-")
        self.value.setStyleSheet("font-size: 21px; font-weight: 700;")
        self.caption = QLabel("")
        self.caption.setObjectName("Muted")
        self.caption.setStyleSheet("font-size: 11px;")
        text.addWidget(self.label)
        text.addWidget(self.value)
        text.addWidget(self.caption)
        layout.addLayout(text, 1)
        self.extra = QHBoxLayout()
        layout.addLayout(self.extra)
        self.set_color(theme.ACCENT)
        add_shadow(self, blur=28, dy=8)

    def set_color(self, color):
        self.bubble.setStyleSheet(f"background: {theme.soft(QColor(color).name(), 0.13)};"
                                  f" border-radius: 14px; font-size: 18px;")

    def set(self, value=None, caption=None, color=None, fmt="{:,}"):
        if value is not None:
            self.value.set_value(value, fmt)
        if caption is not None:
            self.caption.setText(caption)
            self.caption.setToolTip(caption)
        if color is not None:
            self.set_color(color)


# ------------------------------------------------------------ controls

class ToggleSwitch(QAbstractButton):
    """An animated on/off switch."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedSize(50, 28)
        self._offset = 0.0
        self._anim = QPropertyAnimation(self, b"offset", self)
        self._anim.setDuration(260)
        self._anim.setEasingCurve(QEasingCurve.Type.OutBack)
        self.toggled.connect(self._start_anim)

    def sizeHint(self):
        return QSize(50, 28)

    def get_offset(self):
        return self._offset

    def set_offset(self, value):
        self._offset = value
        self.update()

    offset = pyqtProperty(float, get_offset, set_offset)

    def _start_anim(self, checked):
        self._anim.stop()
        self._anim.setStartValue(self._offset)
        self._anim.setEndValue(1.0 if checked else 0.0)
        self._anim.start()

    def set_checked_silently(self, checked):
        self.blockSignals(True)
        self.setChecked(checked)
        self.blockSignals(False)
        self._start_anim(checked)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        t = max(0.0, min(1.0, self._offset))
        rect = QRectF(1, 1, self.width() - 2, self.height() - 2)
        grad = QLinearGradient(rect.topLeft(), rect.bottomRight())
        grad.setColorAt(0, mix(theme.SURFACE_3, theme.ACCENT_2, t))
        grad.setColorAt(1, mix(theme.SURFACE_3, theme.ACCENT, t))
        painter.setPen(QPen(mix(theme.BORDER, theme.ACCENT, t), 1))
        painter.setBrush(grad)
        painter.drawRoundedRect(rect, rect.height() / 2, rect.height() / 2)
        d = self.height() - 8
        x = 4 + (self.width() - d - 8) * self._offset
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(29, 43, 79, 40))
        painter.drawEllipse(QRectF(x, 5, d, d))
        painter.setBrush(QColor("#ffffff"))
        painter.drawEllipse(QRectF(x, 4, d, d))


class StatusPill(QPushButton):
    """Colour-coded pill with a pulsing dot."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._phase = 0.0
        self._color = theme.MUTED
        self._pulse = False
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(40)

    def set_state(self, text, color, pulse=False, tooltip=""):
        self._color = color
        self._pulse = pulse
        self.setText(text)
        self.setToolTip(tooltip)
        self.setStyleSheet(f"""
            QPushButton {{
                background: {theme.soft(color, 0.12)};
                border: 1px solid {theme.soft(color, 0.30)};
                border-radius: 16px;
                color: {color};
                padding: 7px 16px 7px 30px;
                font-weight: 700;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background: {theme.soft(color, 0.20)};
            }}
        """)
        self.update()

    def _tick(self):
        self._phase = (self._phase + 0.035) % 1.0
        if self._pulse:
            self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        center = QPointF(16, self.height() / 2)
        if self._pulse:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(with_alpha(self._color, 0.5 * (1 - self._phase)))
            r = 4 + 6 * self._phase
            painter.drawEllipse(center, r, r)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(self._color))
        painter.drawEllipse(center, 4, 4)


class ActionTile(QAbstractButton):
    """Painted action card with hover glow, press feedback and a busy spinner."""
    def __init__(self, glyph, title, description, primary=False, parent=None):
        super().__init__(parent)
        self.glyph, self.title, self.description = glyph, title, description
        self.primary = primary
        self.busy_text = None
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(84)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._hover = 0.0
        self._spin = 0.0
        self._hover_anim = QVariantAnimation(self)
        self._hover_anim.setDuration(220)
        self._hover_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._hover_anim.valueChanged.connect(self._set_hover)
        self._spinner = QTimer(self)
        self._spinner.timeout.connect(self._step_spinner)

    def sizeHint(self):
        return QSize(180, 84)

    def _set_hover(self, value):
        self._hover = value
        self.update()

    def _animate_hover(self, target):
        self._hover_anim.stop()
        self._hover_anim.setStartValue(self._hover)
        self._hover_anim.setEndValue(target)
        self._hover_anim.start()

    def enterEvent(self, event):
        self._animate_hover(1.0)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._animate_hover(0.0)
        super().leaveEvent(event)

    def _step_spinner(self):
        self._spin = (self._spin + 7) % 360
        self.update()

    def set_description(self, text):
        self.description = text
        self.update()

    def set_busy(self, busy, text="Working..."):
        self.busy_text = text if busy else None
        self.setEnabled(not busy)
        self.setCursor(Qt.CursorShape.BusyCursor if busy else Qt.CursorShape.PointingHandCursor)
        if busy:
            self._spinner.start(16)
        else:
            self._spinner.stop()
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        h = self._hover
        lift = 2.5 * h - (1.5 if self.isDown() else 0)
        rect = QRectF(1, 4 - lift, self.width() - 2, self.height() - 7)

        if self.primary:
            grad = QLinearGradient(rect.topLeft(), rect.bottomRight())
            grad.setColorAt(0, mix(theme.ACCENT_2, theme.ACCENT, h * 0.6))
            grad.setColorAt(1, mix(theme.ACCENT, theme.ACCENT_DEEP, h))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(grad)
            fg, sub = QColor("#ffffff"), QColor(255, 255, 255, 205)
            bubble = QColor(255, 255, 255, 50)
        else:
            painter.setPen(QPen(mix(theme.BORDER, theme.ACCENT_2, h), 1))
            painter.setBrush(mix(theme.SURFACE, theme.SURFACE_2, h))
            fg, sub = QColor(theme.TEXT), QColor(theme.MUTED)
            bubble = mix(theme.ACCENT_SOFT, QColor(theme.ACCENT_2).lighter(118), h * 0.5)
        if not self.isEnabled():
            painter.setOpacity(0.8)
        painter.drawRoundedRect(rect, 16, 16)

        b = QRectF(rect.x() + 14, rect.center().y() - 20, 40, 40)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(bubble)
        painter.drawRoundedRect(b, 13, 13)
        if self.busy_text:
            pen = QPen(fg if self.primary else QColor(theme.ACCENT), 3)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            painter.drawArc(b.adjusted(10, 10, -10, -10), int(-self._spin * 16), 270 * 16)
        else:
            painter.setPen(fg)
            painter.setFont(QFont("Segoe UI Emoji", 15))
            painter.drawText(b, Qt.AlignmentFlag.AlignCenter, self.glyph)

        tx = b.right() + 12
        tw = rect.right() - tx - 12
        title_font = QFont(theme.FONT_FAMILY, 10)
        title_font.setWeight(QFont.Weight.Bold)
        painter.setFont(title_font)
        painter.setPen(fg)
        painter.drawText(QRectF(tx, rect.center().y() - 20, tw, 20),
                         Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                         QFontMetrics(title_font).elidedText(self.busy_text or self.title,
                                                             Qt.TextElideMode.ElideRight, int(tw)))
        desc_font = QFont(theme.FONT_FAMILY, 8)
        painter.setFont(desc_font)
        painter.setPen(sub)
        painter.drawText(QRectF(tx, rect.center().y() + 1, tw, 18),
                         Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                         QFontMetrics(desc_font).elidedText(self.description, Qt.TextElideMode.ElideRight, int(tw)))


# --------------------------------------------------------- status ring

class StatusRing(QWidget):
    """Large animated protection indicator.

    ``protected``: a comet arc orbits the shield and the glow breathes.
    ``idle``: a calm, static ring.
    ``threat``: the ring turns red and ripples outwards.
    """
    def __init__(self, size=184, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.state = "idle"
        self._color = QColor(theme.SUBTLE)
        self._target = QColor(theme.SUBTLE)
        self._angle = 90.0
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(16)

    def set_state(self, state):
        self.state = state
        self._target = QColor({
            "protected": theme.ACCENT,
            "threat": theme.CRITICAL,
        }.get(state, theme.WARNING))

    def _tick(self):
        if not self.isVisible():
            return
        speed = {"protected": 1.6, "threat": 3.2}.get(self.state, 0.25)
        self._angle = (self._angle - speed) % 360
        self._phase = (self._phase + (0.012 if self.state != "threat" else 0.02)) % 1.0
        self._color = mix(self._color, self._target, 0.08)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = QPointF(self.width() / 2, self.height() / 2)
        r = self.width() / 2 - 16
        color = self._color
        breathe = 0.5 + 0.5 * math.sin(self._phase * 2 * math.pi)

        # Soft glow
        glow = QRadialGradient(c, r + 16)
        glow.setColorAt(0.55, with_alpha(color, 0.10 + 0.10 * breathe))
        glow.setColorAt(1.0, with_alpha(color, 0.0))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(glow)
        painter.drawEllipse(c, r + 16, r + 16)

        # Ripples when under threat
        if self.state == "threat":
            for k in range(3):
                p = (self._phase * 1.5 + k / 3) % 1.0
                painter.setPen(QPen(with_alpha(color, 0.45 * (1 - p)), 2))
                painter.setBrush(Qt.BrushStyle.NoBrush)
                rr = r * (0.75 + 0.4 * p)
                painter.drawEllipse(c, rr, rr)

        # Track
        ring = QRectF(c.x() - r, c.y() - r, 2 * r, 2 * r)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(QColor(theme.SURFACE_3), 10))
        painter.drawEllipse(ring)

        # Arc
        if self.state == "idle":
            pen = QPen(with_alpha(color, 0.75), 10)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            painter.drawArc(ring, int(self._angle * 16), int(70 * 16))
        else:
            conical = QConicalGradient(c, self._angle)
            conical.setColorAt(0.0, with_alpha(color, 1.0))
            conical.setColorAt(0.65, with_alpha(color, 0.0))
            conical.setColorAt(1.0, with_alpha(color, 0.0))
            pen = QPen(QBrush(conical), 10)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            painter.drawArc(ring, int(self._angle * 16), int(-230 * 16))
            head = math.radians(self._angle)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(color)
            painter.drawEllipse(QPointF(c.x() + r * math.cos(head), c.y() - r * math.sin(head)), 5, 5)

        # Inner disc
        inner = r - 18
        disc = QRadialGradient(QPointF(c.x(), c.y() - inner * 0.4), inner * 1.4)
        disc.setColorAt(0, QColor("#ffffff"))
        disc.setColorAt(1, mix(theme.SURFACE_2, color, 0.06))
        painter.setPen(QPen(with_alpha(color, 0.12), 1))
        painter.setBrush(disc)
        painter.drawEllipse(c, inner, inner)

        s = inner * 0.95
        bob = 2.5 * math.sin(self._phase * 2 * math.pi)
        mark = {"protected": "check", "threat": "alert"}.get(self.state, "pause")
        paint_shield(painter, QRectF(c.x() - s / 2, c.y() - s / 2 + bob, s, s * 1.05), color, mark)


# --------------------------------------------------------------- toasts

class Toast(QFrame):
    closed = pyqtSignal(object)

    def __init__(self, title, message, level="info", parent=None, duration=5000):
        super().__init__(parent)
        color = theme.LEVEL_COLORS.get(level, theme.INFO)
        self.setFixedWidth(350)
        self.setStyleSheet(f"""
            Toast {{
                background: {theme.SURFACE};
                border: 1px solid {theme.soft(color, 0.35)};
                border-radius: 16px;
            }}
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 12, 10, 12)
        layout.setSpacing(12)
        dot = QLabel("!" if level in ("warning", "critical") else "✓" if level == "success" else "i")
        dot.setFixedSize(30, 30)
        dot.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dot.setStyleSheet(f"background: {theme.soft(color, 0.14)}; color: {color};"
                          f" border-radius: 15px; font-weight: 800;")
        layout.addWidget(dot, 0, Qt.AlignmentFlag.AlignTop)
        text = QVBoxLayout()
        text.setSpacing(2)
        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {color}; font-weight: 700;")
        body = QLabel(message)
        body.setWordWrap(True)
        body.setFixedWidth(350 - 14 - 30 - 12 - 12 - 26 - 10)
        body.setStyleSheet(f"color: {theme.TEXT}; font-size: 12px;")
        text.addWidget(title_label)
        text.addWidget(body)
        layout.addLayout(text, 1)
        close = QPushButton("✕")
        close.setProperty("variant", "ghost")
        close.setFixedSize(26, 26)
        close.setStyleSheet("padding: 0; border-radius: 13px;")
        close.setCursor(Qt.CursorShape.PointingHandCursor)
        close.clicked.connect(self.dismiss)
        layout.addWidget(close, 0, Qt.AlignmentFlag.AlignTop)

        self._effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._effect)
        self._fade = QPropertyAnimation(self._effect, b"opacity", self)
        self._fade.setDuration(260)
        self._fade.setStartValue(0.0)
        self._fade.setEndValue(1.0)
        self._fade.start()
        self._move = QPropertyAnimation(self, b"pos", self)
        self._move.setDuration(420)
        self._move.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._closing = False
        self._placed = False
        QTimer.singleShot(duration, self.dismiss)

    def glide_to(self, target):
        if not self._placed:
            self._placed = True
            self.move(target + QPoint(60, 0))
        self._move.stop()
        self._move.setStartValue(self.pos())
        self._move.setEndValue(target)
        self._move.start()

    def dismiss(self):
        if self._closing:
            return
        self._closing = True
        self._fade.stop()
        self._fade.setStartValue(self._effect.opacity())
        self._fade.setEndValue(0.0)
        self._fade.finished.connect(self._finish)
        self._fade.start()
        self._move.stop()
        self._move.setStartValue(self.pos())
        self._move.setEndValue(self.pos() + QPoint(50, 0))
        self._move.start()

    def _finish(self):
        self.closed.emit(self)
        self.deleteLater()


class ToastManager:
    """Stacks toasts in the bottom-right corner of ``host``; they glide into place."""
    MAX_VISIBLE = 3

    def __init__(self, host):
        self.host = host
        self.toasts = []

    def show(self, title, message, level="info"):
        duration = 9000 if level == "critical" else 4500
        toast = Toast(title, message, level, self.host, duration)
        toast.closed.connect(self._remove)
        self.toasts.append(toast)
        while len(self.toasts) > self.MAX_VISIBLE:
            self.toasts.pop(0).dismiss()
        toast.adjustSize()
        toast.show()
        toast.raise_()
        self.reposition()

    def _remove(self, toast):
        if toast in self.toasts:
            self.toasts.remove(toast)
        self.reposition()

    def reposition(self):
        y = self.host.height() - 24
        for toast in reversed(self.toasts):
            toast.adjustSize()
            y -= toast.height()
            toast.glide_to(QPoint(self.host.width() - toast.width() - 24, y))
            y -= 10


# ------------------------------------------------------- activity feed

EVENT_ROLE = Qt.ItemDataRole.UserRole + 1
ADDED_ROLE = Qt.ItemDataRole.UserRole + 2
FLASH_SECONDS = 1.8


class ActivityModel(QAbstractListModel):
    """Newest-first list of events with the time each one arrived."""
    def __init__(self, max_rows=2000, parent=None):
        super().__init__(parent)
        self.rows = []
        self.max_rows = max_rows

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        event, added = self.rows[index.row()]
        if role == EVENT_ROLE:
            return event
        if role == ADDED_ROLE:
            return added
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return event.message
        return None

    def add(self, event):
        self.beginInsertRows(QModelIndex(), 0, 0)
        self.rows.insert(0, (event, time.monotonic()))
        self.endInsertRows()
        if len(self.rows) > self.max_rows:
            last = len(self.rows) - 1
            self.beginRemoveRows(QModelIndex(), last, last)
            self.rows.pop()
            self.endRemoveRows()

    def clear(self):
        self.beginResetModel()
        self.rows = []
        self.endResetModel()


class ActivityFilter(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.levels = None
        self.text = ""

    def set_filter(self, levels=None, text=None):
        if levels is not None:
            self.levels = levels or None
        if text is not None:
            self.text = text.strip().lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, row, parent):
        event = self.sourceModel().index(row, 0, parent).data(EVENT_ROLE)
        if self.levels and event.level not in self.levels:
            return False
        return not self.text or self.text in event.message.lower()


class ActivityDelegate(QStyledItemDelegate):
    ROW_HEIGHT = 62

    def __init__(self, shorten, parent=None):
        super().__init__(parent)
        self.shorten = shorten

    def sizeHint(self, option, index):
        return QSize(200, self.ROW_HEIGHT)

    def paint(self, painter, option, index):
        event = index.data(EVENT_ROLE)
        age = time.monotonic() - index.data(ADDED_ROLE)
        enter = ease_out(age / 0.55)
        flash = max(0.0, 1 - age / FLASH_SECONDS)
        color = QColor(theme.LEVEL_COLORS.get(event.level, theme.INFO))
        hovered = bool(option.state & QStyle.StateFlag.State_MouseOver)

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setOpacity(0.15 + 0.85 * enter)
        rect = QRectF(option.rect).adjusted(2, 3, -8, -3)
        rect.translate((1 - enter) * 24, 0)

        bg = QColor(theme.SURFACE_2) if hovered else QColor(theme.SURFACE)
        bg = mix(bg, with_alpha(color, 1.0).lighter(170), flash * 0.55)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(bg)
        painter.drawRoundedRect(rect, 14, 14)

        bubble = QRectF(rect.x() + 10, rect.center().y() - 17, 34, 34)
        painter.setBrush(with_alpha(color, 0.14))
        painter.drawEllipse(bubble)
        painter.setBrush(color)
        dot = 5 + (2 * math.sin(age * 6) if event.level == "critical" and age < 10 else 0)
        painter.drawEllipse(bubble.center(), dot, dot)

        # Severity pill on the right
        pill_font = QFont(theme.FONT_FAMILY, 8)
        pill_font.setWeight(QFont.Weight.Bold)
        label = theme.LEVEL_LABELS.get(event.level, event.level)
        pw = QFontMetrics(pill_font).horizontalAdvance(label) + 18
        pill = QRectF(rect.right() - pw - 10, rect.center().y() - 11, pw, 22)
        painter.setBrush(with_alpha(color, 0.12))
        painter.drawRoundedRect(pill, 11, 11)
        painter.setPen(color)
        painter.setFont(pill_font)
        painter.drawText(pill, Qt.AlignmentFlag.AlignCenter, label)

        tx = bubble.right() + 12
        tw = pill.left() - tx - 12
        title_font = QFont(theme.FONT_FAMILY, 10)
        title_font.setWeight(QFont.Weight.DemiBold if event.level != "critical" else QFont.Weight.Bold)
        painter.setFont(title_font)
        painter.setPen(QColor(theme.TEXT))
        painter.drawText(QRectF(tx, rect.y() + 9, tw, 22), Qt.AlignmentFlag.AlignVCenter,
                         QFontMetrics(title_font).elidedText(self.shorten(event), Qt.TextElideMode.ElideRight, int(tw)))
        meta = f"{time.strftime('%H:%M:%S', time.localtime(event.timestamp))}  ·  {event.category}"
        if event.path and " -> " not in event.path:
            meta += f"  ·  {os.path.dirname(event.path)}"
        meta_font = QFont(theme.FONT_FAMILY, 8)
        painter.setFont(meta_font)
        painter.setPen(QColor(theme.MUTED))
        painter.drawText(QRectF(tx, rect.y() + 31, tw, 18), Qt.AlignmentFlag.AlignVCenter,
                         QFontMetrics(meta_font).elidedText(meta, Qt.TextElideMode.ElideMiddle, int(tw)))
        painter.restore()


class ActivityFeed(QListView):
    """Animated list of events: new rows slide in and glow briefly."""
    event_activated = pyqtSignal(object)

    def __init__(self, shorten, parent=None):
        super().__init__(parent)
        self.source = ActivityModel(parent=self)
        self.proxy = ActivityFilter(self)
        self.proxy.setSourceModel(self.source)
        self.setModel(self.proxy)
        self.setItemDelegate(ActivityDelegate(shorten, self))
        self.setMouseTracking(True)
        self.setUniformItemSizes(True)
        self.setSelectionMode(QListView.SelectionMode.NoSelection)
        self.setVerticalScrollMode(QListView.ScrollMode.ScrollPerPixel)
        self.verticalScrollBar().setSingleStep(18)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.empty_text = "Nothing here yet. Events will appear as they happen."
        self._anim = QTimer(self)
        self._anim.timeout.connect(self._animate)
        self._last_add = 0.0
        self.doubleClicked.connect(lambda idx: self.event_activated.emit(idx.data(EVENT_ROLE)))

    def add(self, event):
        self.source.add(event)
        self._last_add = time.monotonic()
        if not self._anim.isActive():
            self._anim.start(16)

    def _animate(self):
        self.viewport().update()
        if time.monotonic() - self._last_add > FLASH_SECONDS:
            self._anim.stop()

    def set_filter(self, levels=None, text=None):
        self.proxy.set_filter(levels, text)
        self.viewport().update()

    def clear(self):
        self.source.clear()

    def paintEvent(self, event):
        super().paintEvent(event)
        if self.proxy.rowCount() == 0:
            painter = QPainter(self.viewport())
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            c = QPointF(self.viewport().width() / 2, self.viewport().height() / 2 - 18)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(theme.ACCENT_SOFT))
            painter.drawEllipse(c, 26, 26)
            paint_shield(painter, QRectF(c.x() - 13, c.y() - 14, 26, 28), theme.ACCENT_2)
            painter.setPen(QColor(theme.MUTED))
            painter.drawText(QRectF(0, c.y() + 34, self.viewport().width(), 24),
                             Qt.AlignmentFlag.AlignCenter, self.empty_text)
