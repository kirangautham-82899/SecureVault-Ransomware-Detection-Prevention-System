# gui/splash.py

import sys
import os
from PyQt6.QtWidgets import QApplication, QSplashScreen, QLabel
from PyQt6.QtGui import QPixmap, QFont, QGuiApplication
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QSequentialAnimationGroup
from PyQt6.QtWidgets import QGraphicsOpacityEffect

from main_gui import run_gui


class CustomSplashScreen(QSplashScreen):
    def __init__(self, pixmap):
        super().__init__(pixmap)
        self.setFixedSize(812, 596)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.SplashScreen)
        self.setStyleSheet("background-color: black;")

        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.opacity_effect)

        # Loading Label
        self.label = QLabel("🔐 Loading SecureVault...", self)
        self.label.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        self.label.setStyleSheet("color: white;")
        self.label.setGeometry(0, self.height() - 60, self.width(), 40)
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)


def show_splash_then_launch():
    app = QApplication(sys.argv)

    splash_pix = QPixmap("C:/Users/kiran/SecureVault/gui/assets/splash.jpg").scaled(
        812, 596,
        Qt.AspectRatioMode.KeepAspectRatio,
        Qt.TransformationMode.SmoothTransformation
    )

    splash = CustomSplashScreen(splash_pix)

    # Center it on screen
    screen_geometry = QGuiApplication.primaryScreen().geometry()
    x = (screen_geometry.width() - splash.width()) // 2
    y = (screen_geometry.height() - splash.height()) // 2
    splash.move(x, y)

    # === Fade In Animation ===
    fade_in = QPropertyAnimation(splash.opacity_effect, b"opacity")
    fade_in.setDuration(2000)
    fade_in.setStartValue(0.0)
    fade_in.setEndValue(1.0)
    fade_in.setEasingCurve(QEasingCurve.Type.InOutQuad)

    # === Fade Out Animation ===
    fade_out = QPropertyAnimation(splash.opacity_effect, b"opacity")
    fade_out.setDuration(2000)
    fade_out.setStartValue(1.0)
    fade_out.setEndValue(0.0)
    fade_out.setEasingCurve(QEasingCurve.Type.OutCubic)

    # === Animation Sequence ===
    sequence = QSequentialAnimationGroup()
    sequence.addAnimation(fade_in)
    sequence.addPause(2500)  # Hold splash visible
    sequence.addAnimation(fade_out)

    # After animation, open main GUI
    sequence.finished.connect(lambda: (
        splash.close(),
        run_gui()
    ))

    splash.show()
    sequence.start()

    sys.exit(app.exec())


if __name__ == "__main__":
    show_splash_then_launch()
