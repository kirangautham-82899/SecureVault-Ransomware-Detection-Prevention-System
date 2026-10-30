# gui/splash.py
"""Short animated splash shown while the dashboard starts."""
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QRectF, pyqtSignal
from PyQt6.QtGui import QPainter, QColor, QLinearGradient, QRadialGradient, QPen, QFont
from PyQt6.QtWidgets import QWidget, QGraphicsOpacityEffect

from gui import theme
from gui.widgets import paint_shield, with_alpha

try:
    from main import APP_VERSION
except ImportError:
    APP_VERSION = ""

STEPS = [
    (0, "Loading detection engine…"),
    (35, "Preparing file integrity monitor…"),
    (70, "Building your dashboard…"),
    (96, "Ready"),
]


class SplashScreen(QWidget):
    """Frameless card: the shield draws in, a progress line fills, then it fades out."""
    finished = pyqtSignal()

    def __init__(self, duration_ms=1600):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint
                            | Qt.WindowType.SplashScreen)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(460, 320)
        self.progress = 0.0
        self.status = STEPS[0][1]
        self._duration = duration_ms
        self._elapsed = 0

        self.effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.effect)
        self.fade = QPropertyAnimation(self.effect, b"opacity", self)
        self.fade.setDuration(300)
        self.fade.setStartValue(0.0)
        self.fade.setEndValue(1.0)
        self.fade.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._advance)

    def start(self):
        screen = self.screen().availableGeometry()
        self.move(screen.center() - self.rect().center())
        self.show()
        self.fade.start()
        self._timer.start(16)

    def _advance(self):
        self._elapsed += 16
        t = min(1.0, self._elapsed / self._duration)
        self.progress = 1 - (1 - t) ** 2
        for threshold, text in STEPS:
            if self.progress * 100 >= threshold:
                self.status = text
        self.update()
        if t >= 1.0:
            self._timer.stop()
            self.fade.setStartValue(1.0)
            self.fade.setEndValue(0.0)
            self.fade.finished.connect(self._done)
            self.fade.start()

    def _done(self):
        self.close()
        self.finished.emit()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        card = QRectF(10, 10, self.width() - 20, self.height() - 20)
        bg = QLinearGradient(card.topLeft(), card.bottomRight())
        bg.setColorAt(0, QColor("#ffffff"))
        bg.setColorAt(1, QColor(theme.BG))
        painter.setPen(QPen(QColor(theme.BORDER), 1))
        painter.setBrush(bg)
        painter.drawRoundedRect(card, 24, 24)

        cx, cy = card.center().x(), card.y() + 104
        glow = QRadialGradient(cx, cy, 80)
        glow.setColorAt(0, with_alpha(theme.ACCENT_2, 0.35 * min(1, self.progress * 3)))
        glow.setColorAt(1, with_alpha(theme.ACCENT_2, 0))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(glow)
        painter.drawEllipse(QRectF(cx - 80, cy - 80, 160, 160))

        grow = min(1.0, self.progress * 2.2)
        size = 40 + 30 * (1 - (1 - grow) ** 3)
        painter.setOpacity(grow)
        paint_shield(painter, QRectF(cx - size / 2, cy - size / 2, size, size * 1.05))
        painter.setOpacity(1.0)

        painter.setPen(QColor(theme.TEXT))
        title = QFont(theme.FONT_FAMILY, 20)
        title.setWeight(QFont.Weight.Bold)
        painter.setFont(title)
        painter.drawText(QRectF(card.x(), cy + 44, card.width(), 34), Qt.AlignmentFlag.AlignCenter, "SecureVault")
        painter.setPen(QColor(theme.MUTED))
        painter.setFont(QFont(theme.FONT_FAMILY, 9))
        painter.drawText(QRectF(card.x(), cy + 76, card.width(), 20), Qt.AlignmentFlag.AlignCenter,
                         "Ransomware detection & prevention")

        bar = QRectF(card.x() + 40, card.bottom() - 46, card.width() - 80, 5)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(theme.SURFACE_3))
        painter.drawRoundedRect(bar, 2.5, 2.5)
        fill = QRectF(bar.x(), bar.y(), bar.width() * self.progress, bar.height())
        grad = QLinearGradient(fill.topLeft(), fill.topRight())
        grad.setColorAt(0, QColor(theme.ACCENT_2))
        grad.setColorAt(1, QColor(theme.ACCENT))
        painter.setBrush(grad)
        painter.drawRoundedRect(fill, 2.5, 2.5)

        painter.setPen(QColor(theme.MUTED))
        painter.setFont(QFont(theme.FONT_FAMILY, 8))
        painter.drawText(QRectF(bar.x(), bar.y() - 22, bar.width(), 16),
                         Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, self.status)
        painter.setPen(QColor(theme.SUBTLE))
        painter.drawText(QRectF(bar.x(), bar.y() - 22, bar.width(), 16),
                         Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                         f"v{APP_VERSION}" if APP_VERSION else "")
