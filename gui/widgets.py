# gui/widgets.py
"""Reusable widgets for the SecureVault dashboard."""
import threading
from collections import deque

import psutil
from PyQt6.QtCore import (
    Qt, QTimer, QPointF, QRectF, QSize, QPropertyAnimation, QEasingCurve,
    pyqtProperty, pyqtSignal,
)
from PyQt6.QtGui import (
    QColor, QPainter, QPainterPath, QPen, QBrush, QLinearGradient, QIcon,
    QPixmap, QFont,
)
from PyQt6.QtWidgets import (
    QAbstractButton, QFrame, QLabel, QVBoxLayout, QHBoxLayout, QWidget,
    QGraphicsOpacityEffect, QPushButton, QSizePolicy,
)

from gui import theme

try:
    import winsound
except ImportError:  # Non-Windows platforms
    winsound = None


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


def paint_shield(painter, rect, color=theme.ACCENT, check=True):
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    base = QColor(color)
    gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
    gradient.setColorAt(0, base.lighter(125))
    gradient.setColorAt(1, base.darker(160))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QBrush(gradient))
    painter.drawPath(shield_path(rect))
    if check:
        pen = QPen(QColor("#ffffff"), max(1.5, rect.width() * 0.09))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        x, y, w, h = rect.x(), rect.y(), rect.width(), rect.height()
        tick = QPainterPath(QPointF(x + w * 0.30, y + h * 0.50))
        tick.lineTo(x + w * 0.45, y + h * 0.64)
        tick.lineTo(x + w * 0.71, y + h * 0.36)
        painter.drawPath(tick)


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
        self._color = theme.ACCENT

    def set_color(self, color):
        self._color = color
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        m = self.width() * 0.04
        paint_shield(painter, QRectF(m, m, self.width() - 2 * m, self.height() - 2 * m), self._color)


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
    def play_success(cls):
        cls._play([(1000, 70), (1500, 110)])

    @classmethod
    def play_warning(cls):
        cls._play([(900, 120)])

    @classmethod
    def play_alert(cls):
        cls._play([(800, 100), (1200, 100)] * 3)


class Card(QFrame):
    """Rounded surface with an optional title row."""
    def __init__(self, title=None, subtitle=None, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(18, 16, 18, 16)
        self.body.setSpacing(12)
        self.header = None
        if title:
            self.header = QHBoxLayout()
            self.header.setSpacing(8)
            titles = QVBoxLayout()
            titles.setSpacing(2)
            title_label = QLabel(title)
            title_label.setObjectName("CardTitle")
            titles.addWidget(title_label)
            if subtitle:
                sub = QLabel(subtitle)
                sub.setObjectName("CardSubtitle")
                titles.addWidget(sub)
            self.header.addLayout(titles)
            self.header.addStretch()
            self.body.addLayout(self.header)


class StatCard(QFrame):
    def __init__(self, label, value="-", caption="", accent=theme.ACCENT, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._accent = accent
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(14)

        self.bar = QFrame()
        self.bar.setFixedSize(4, 46)
        layout.addWidget(self.bar)

        text = QVBoxLayout()
        text.setSpacing(2)
        self.label = QLabel(label.upper())
        self.label.setObjectName("StatLabel")
        self.value = QLabel(value)
        self.value.setObjectName("StatValue")
        self.caption = QLabel(caption)
        self.caption.setObjectName("Muted")
        self.caption.setStyleSheet("font-size: 11px;")
        text.addWidget(self.label)
        text.addWidget(self.value)
        text.addWidget(self.caption)
        layout.addLayout(text, 1)
        self.set_accent(accent)

    def set_accent(self, color):
        self._accent = color
        self.bar.setStyleSheet(f"background: {color}; border-radius: 2px;")

    def set(self, value=None, caption=None, accent=None):
        if value is not None:
            self.value.setText(str(value))
        if caption is not None:
            self.caption.setText(caption)
            self.caption.setToolTip(caption)
        if accent is not None:
            self.set_accent(accent)


class ToggleSwitch(QAbstractButton):
    """An animated on/off switch."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedSize(46, 26)
        self._offset = 0.0
        self._anim = QPropertyAnimation(self, b"offset", self)
        self._anim.setDuration(160)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.toggled.connect(self._start_anim)

    def sizeHint(self):
        return QSize(46, 26)

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
        self._anim.stop()
        self.set_offset(1.0 if checked else 0.0)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        off, on = QColor(theme.SURFACE_3), QColor(theme.SUCCESS)
        t = self._offset
        track = QColor(
            int(off.red() + (on.red() - off.red()) * t),
            int(off.green() + (on.green() - off.green()) * t),
            int(off.blue() + (on.blue() - off.blue()) * t),
        )
        if not self.isEnabled():
            track.setAlpha(110)
        rect = QRectF(0.5, 0.5, self.width() - 1, self.height() - 1)
        painter.setPen(QPen(QColor(theme.BORDER), 1))
        painter.setBrush(track)
        painter.drawRoundedRect(rect, rect.height() / 2, rect.height() / 2)
        d = self.height() - 6
        x = 3 + (self.width() - d - 6) * t
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#ffffff"))
        painter.drawEllipse(QRectF(x, 3, d, d))


class StatusPill(QPushButton):
    """Colour-coded protection status shown in the header."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._phase = 0.0
        self._color = theme.MUTED
        self._pulse = False
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(60)

    def set_state(self, text, color, pulse=False, tooltip=""):
        self._color = color
        self._pulse = pulse
        self.setText(f"   {text}")
        self.setToolTip(tooltip)
        c = QColor(color)
        self.setStyleSheet(f"""
            QPushButton {{
                background: rgba({c.red()}, {c.green()}, {c.blue()}, 0.12);
                border: 1px solid rgba({c.red()}, {c.green()}, {c.blue()}, 0.45);
                border-radius: 15px;
                color: {color};
                padding: 6px 16px 6px 22px;
                font-weight: 700;
                letter-spacing: 1px;
            }}
            QPushButton:hover {{
                background: rgba({c.red()}, {c.green()}, {c.blue()}, 0.2);
            }}
        """)
        self.update()

    def _tick(self):
        self._phase = (self._phase + 0.06) % 1.0
        if self._pulse:
            self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        center = QPointF(16, self.height() / 2)
        color = QColor(self._color)
        if self._pulse:
            halo = QColor(color)
            halo.setAlphaF(0.45 * (1 - self._phase))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(halo)
            r = 4 + 5 * self._phase
            painter.drawEllipse(center, r, r)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(color)
        painter.drawEllipse(center, 4, 4)


class SystemLoadGraph(QWidget):
    """Live CPU history as a smooth area chart, with hover read-out."""
    sampled = pyqtSignal(float, float)  # cpu %, memory %

    def __init__(self, points=60, interval_ms=1000, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(150)
        self.setMouseTracking(True)
        self.data = deque([0.0] * points, maxlen=points)
        self.interval_s = interval_ms / 1000
        self._hover_x = None
        psutil.cpu_percent(None)  # prime the counter
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.sample)
        self.timer.start(interval_ms)

    def sample(self):
        cpu = psutil.cpu_percent(None)
        mem = psutil.virtual_memory().percent
        self.data.append(cpu)
        self.sampled.emit(cpu, mem)
        self.update()

    def mouseMoveEvent(self, event):
        self._hover_x = event.position().x()
        self.update()

    def leaveEvent(self, event):
        self._hover_x = None
        self.update()

    @staticmethod
    def color_for(value):
        if value >= 85:
            return QColor(theme.CRITICAL)
        if value >= 60:
            return QColor(theme.WARNING)
        return QColor(theme.ACCENT)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        left, top, right, bottom = 34, 8, 6, 20
        w = self.width() - left - right
        h = self.height() - top - bottom
        if w <= 0 or h <= 0:
            return

        # Grid + y-axis labels
        painter.setFont(QFont(theme.FONT_FAMILY, 8))
        for pct in (0, 25, 50, 75, 100):
            y = top + h - pct / 100 * h
            painter.setPen(QPen(QColor(theme.BORDER), 1, Qt.PenStyle.DashLine if pct else Qt.PenStyle.SolidLine))
            painter.drawLine(QPointF(left, y), QPointF(left + w, y))
            painter.setPen(QColor(theme.SUBTLE))
            painter.drawText(QRectF(0, y - 8, left - 6, 16),
                             Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, f"{pct}%")
        span = int(len(self.data) * self.interval_s)
        painter.drawText(QRectF(left, top + h + 4, w, 14), Qt.AlignmentFlag.AlignLeft, f"{span}s ago")
        painter.drawText(QRectF(left, top + h + 4, w, 14), Qt.AlignmentFlag.AlignRight, "now")

        values = list(self.data)
        step = w / (len(values) - 1)
        points = [QPointF(left + i * step, top + h - v / 100 * h) for i, v in enumerate(values)]

        line = QPainterPath(points[0])
        for p0, p1 in zip(points, points[1:]):
            mid_x = (p0.x() + p1.x()) / 2
            line.cubicTo(QPointF(mid_x, p0.y()), QPointF(mid_x, p1.y()), p1)

        color = self.color_for(values[-1])
        area = QPainterPath(line)
        area.lineTo(left + w, top + h)
        area.lineTo(left, top + h)
        area.closeSubpath()
        gradient = QLinearGradient(0, top, 0, top + h)
        fill = QColor(color)
        fill.setAlpha(90)
        gradient.setColorAt(0, fill)
        fill.setAlpha(0)
        gradient.setColorAt(1, fill)
        painter.fillPath(area, QBrush(gradient))
        painter.setPen(QPen(color, 2))
        painter.drawPath(line)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(color)
        painter.drawEllipse(points[-1], 3.5, 3.5)

        if self._hover_x is not None and left <= self._hover_x <= left + w:
            i = max(0, min(len(values) - 1, round((self._hover_x - left) / step)))
            p = points[i]
            painter.setPen(QPen(QColor(theme.MUTED), 1, Qt.PenStyle.DashLine))
            painter.drawLine(QPointF(p.x(), top), QPointF(p.x(), top + h))
            painter.setPen(QPen(QColor(theme.BG), 2))
            painter.setBrush(color)
            painter.drawEllipse(p, 4.5, 4.5)
            ago = int((len(values) - 1 - i) * self.interval_s)
            text = f"{values[i]:.0f}%  ·  {ago}s ago" if ago else f"{values[i]:.0f}%  ·  now"
            box = QRectF(0, 0, 104, 22)
            box.moveCenter(QPointF(p.x(), max(top + 12, p.y() - 18)))
            box.moveLeft(max(left, min(box.left(), left + w - box.width())))
            painter.setPen(QPen(QColor(theme.BORDER), 1))
            painter.setBrush(QColor(theme.SURFACE_3))
            painter.drawRoundedRect(box, 6, 6)
            painter.setPen(QColor(theme.TEXT))
            painter.drawText(box, Qt.AlignmentFlag.AlignCenter, text)


class Toast(QFrame):
    closed = pyqtSignal(object)

    def __init__(self, title, message, level="info", parent=None, duration=5000):
        super().__init__(parent)
        color = theme.LEVEL_COLORS.get(level, theme.INFO)
        self.setFixedWidth(360)
        self.setStyleSheet(f"""
            Toast {{
                background: {theme.SURFACE_3};
                border: 1px solid {theme.BORDER};
                border-left: 4px solid {color};
                border-radius: 10px;
            }}
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 8, 10)
        layout.setSpacing(10)
        text = QVBoxLayout()
        text.setSpacing(2)
        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {color}; font-weight: 700;")
        body = QLabel(message)
        body.setWordWrap(True)
        body.setFixedWidth(self.width() - 14 - 8 - 26 - 10)
        body.setStyleSheet(f"color: {theme.TEXT};")
        text.addWidget(title_label)
        text.addWidget(body)
        layout.addLayout(text, 1)
        close = QPushButton("✕")
        close.setProperty("variant", "ghost")
        close.setFixedSize(26, 26)
        close.setStyleSheet("padding: 0;")
        close.setCursor(Qt.CursorShape.PointingHandCursor)
        close.clicked.connect(self.dismiss)
        layout.addWidget(close, 0, Qt.AlignmentFlag.AlignTop)

        self._effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._effect)
        self._anim = QPropertyAnimation(self._effect, b"opacity", self)
        self._anim.setDuration(220)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.start()
        self._closing = False
        QTimer.singleShot(duration, self.dismiss)

    def dismiss(self):
        if self._closing:
            return
        self._closing = True
        self._anim.stop()
        self._anim.setStartValue(self._effect.opacity())
        self._anim.setEndValue(0.0)
        self._anim.finished.connect(self._finish)
        self._anim.start()

    def _finish(self):
        self.closed.emit(self)
        self.deleteLater()


class ToastManager:
    """Stacks toasts in the bottom-right corner of ``host``."""
    MAX_VISIBLE = 3

    def __init__(self, host):
        self.host = host
        self.toasts = []

    def show(self, title, message, level="info"):
        duration = 9000 if level == "critical" else 5000
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
        y = self.host.height() - 48
        for toast in reversed(self.toasts):
            toast.adjustSize()
            y -= toast.height()
            toast.move(self.host.width() - toast.width() - 24, y)
            y -= 10
