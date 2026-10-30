# gui/splash.py
"""Short animated splash shown while the dashboard starts."""
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QFrame, QLabel, QVBoxLayout, QProgressBar, QGraphicsOpacityEffect,
)

from gui import theme
from gui.widgets import ShieldLogo

try:
    from main import APP_VERSION
except ImportError:
    APP_VERSION = ""

STEPS = [
    (0, "Loading detection engine..."),
    (35, "Preparing file integrity monitor..."),
    (70, "Building dashboard..."),
    (95, "Ready"),
]


class SplashScreen(QWidget):
    finished = pyqtSignal()

    def __init__(self, duration_ms=1400):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint
                            | Qt.WindowType.SplashScreen)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(440, 300)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        container = QFrame()
        container.setStyleSheet(f"""
            QFrame#SplashCard {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {theme.SURFACE_2}, stop:1 {theme.BG});
                border: 1px solid {theme.BORDER};
                border-radius: 18px;
            }}
        """)
        container.setObjectName("SplashCard")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(40, 36, 40, 30)
        layout.setSpacing(8)

        logo = ShieldLogo(64)
        title = QLabel("SecureVault")
        title.setStyleSheet(f"color: {theme.TEXT}; font-size: 28px; font-weight: 700;")
        subtitle = QLabel("RANSOMWARE DETECTION & PREVENTION")
        subtitle.setStyleSheet(f"color: {theme.ACCENT}; font-size: 11px; font-weight: 600; letter-spacing: 2px;")
        self.status = QLabel(STEPS[0][1])
        self.status.setStyleSheet(f"color: {theme.MUTED}; font-size: 12px;")
        version = QLabel(f"v{APP_VERSION}" if APP_VERSION else "")
        version.setStyleSheet(f"color: {theme.SUBTLE}; font-size: 11px;")

        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(4)
        self.progress.setStyleSheet(f"""
            QProgressBar {{ background: {theme.SURFACE_3}; border: none; border-radius: 2px; }}
            QProgressBar::chunk {{ background: {theme.ACCENT}; border-radius: 2px; }}
        """)

        layout.addStretch()
        layout.addWidget(logo, 0, Qt.AlignmentFlag.AlignHCenter)
        layout.addSpacing(6)
        layout.addWidget(title, 0, Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(subtitle, 0, Qt.AlignmentFlag.AlignHCenter)
        layout.addStretch()
        layout.addWidget(self.status)
        layout.addWidget(self.progress)
        layout.addWidget(version, 0, Qt.AlignmentFlag.AlignRight)
        outer.addWidget(container)

        self.effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.effect)
        self.fade = QPropertyAnimation(self.effect, b"opacity", self)
        self.fade.setDuration(250)
        self.fade.setStartValue(0.0)
        self.fade.setEndValue(1.0)
        self.fade.setEasingCurve(QEasingCurve.Type.OutCubic)

        self._value = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._advance)
        self._interval = max(5, duration_ms // 100)

    def start(self):
        screen = self.screen().availableGeometry()
        self.move(screen.center() - self.rect().center())
        self.show()
        self.fade.start()
        self._timer.start(self._interval)

    def _advance(self):
        self._value += 1
        self.progress.setValue(self._value)
        for threshold, text in STEPS:
            if self._value >= threshold:
                self.status.setText(text)
        if self._value >= 100:
            self._timer.stop()
            self.fade.setStartValue(1.0)
            self.fade.setEndValue(0.0)
            self.fade.finished.connect(self._done)
            self.fade.start()

    def _done(self):
        self.close()
        self.finished.emit()
