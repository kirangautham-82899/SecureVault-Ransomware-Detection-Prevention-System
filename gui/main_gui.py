import sys
import os
import threading
import queue
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QLabel, QPushButton,
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QFrame,
    QLineEdit, QFileDialog, QGridLayout, QGraphicsOpacityEffect,
    QProgressBar, QSystemTrayIcon, QMenu, QStyle
)
from PyQt6.QtGui import QFont, QTextCursor, QMouseEvent, QPainter, QPainterPath, QColor, QLinearGradient, QPen, QBrush, QAction
from PyQt6.QtCore import Qt, QPropertyAnimation, QRect, QEasingCurve, QPoint, QTimer, QSequentialAnimationGroup, QParallelAnimationGroup, pyqtProperty
import psutil
from collections import deque
import random
import math
import winsound
import threading
import datetime

# Import backend functions
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from main import (
    create_baseline, check_for_changes,
    create_honeypot, start_real_time_monitor,
    monitor_processes_sustained
)

class LogViewerWindow(QWidget):
    def __init__(self, log_path):
        super().__init__()
        self.setWindowTitle("📄 SecureVault Logs")
        self.setGeometry(400, 200, 700, 500)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.start_pos = None

        self.log_path = log_path
        self.init_ui()
        self.fade_in()

    def fade_in(self):
        """Fade in animation for window"""
        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.opacity_effect)
        self.opacity_anim = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.opacity_anim.setDuration(400)
        self.opacity_anim.setStartValue(0)
        self.opacity_anim.setEndValue(1)
        self.opacity_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.opacity_anim.start()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Main container with gradient
        container = QFrame()
        container.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #1a1a2e, stop:1 #16213e);
                border: 2px solid #00ADB5;
                border-radius: 15px;
            }
        """)
        
        inner_layout = QVBoxLayout(container)
        inner_layout.setContentsMargins(20, 20, 20, 20)
        inner_layout.setSpacing(15)
        
        # Title bar
        title_bar = QFrame()
        title_bar.setStyleSheet("background: transparent; border: none;")
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(0, 0, 0, 0)
        
        title_label = QLabel("📄 Activity Logs")
        title_label.setStyleSheet("""
            color: white;
            font-size: 18px;
            font-weight: bold;
            background: transparent;
        """)
        
        close_btn = QPushButton("✕")
        close_btn.setFixedSize(30, 30)
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                border-radius: 15px;
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        close_btn.clicked.connect(self.close)
        
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        title_layout.addWidget(close_btn)
        
        # Search bar
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("🔍 Search logs...")
        self.search_bar.setStyleSheet("""
            QLineEdit {
                padding: 12px;
                border: 2px solid #00ADB5;
                border-radius: 10px;
                background-color: rgba(255, 255, 255, 0.1);
                color: white;
                font-size: 14px;
            }
            QLineEdit:focus {
                border: 2px solid #02cbd2;
                background-color: rgba(255, 255, 255, 0.15);
            }
        """)
        self.search_bar.textChanged.connect(self.search_logs)

        # Log text area
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("""
            QTextEdit {
                background-color: rgba(0, 0, 0, 0.3);
                padding: 15px;
                font-size: 13px;
                font-family: 'Consolas', 'Courier New', monospace;
                border: 1px solid #00ADB5;
                border-radius: 10px;
                color: #e0e0e0;
            }
        """)
        self.load_logs()

        # Save button
        save_button = QPushButton("💾 Save Logs")
        save_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ADB5, stop:1 #00d4ff);
                color: white;
                border: none;
                border-radius: 10px;
                padding: 12px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #02cbd2, stop:1 #02e8ff);
            }
        """)
        save_button.clicked.connect(self.save_logs)

        inner_layout.addWidget(title_bar)
        inner_layout.addWidget(self.search_bar)
        inner_layout.addWidget(self.log_text)
        inner_layout.addWidget(save_button)
        
        layout.addWidget(container)

    def load_logs(self):
        if os.path.exists(self.log_path):
            with open(self.log_path, "r", encoding="utf-8") as f:
                self.full_log = f.read()
                self.log_text.setPlainText(self.full_log)
        else:
            self.full_log = ""
            self.log_text.setPlainText("No logs found.")

    def search_logs(self, text):
        if text:
            filtered = "\n".join(
                line for line in self.full_log.splitlines()
                if text.lower() in line.lower()
            )
            self.log_text.setPlainText(filtered)
        else:
            self.log_text.setPlainText(self.full_log)

    def save_logs(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Logs", "securevault_logs.txt", "Text Files (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.full_log)

    # Drag to move
    def mousePressEvent(self, event: QMouseEvent):
        if event.button() == Qt.MouseButton.LeftButton:
            self.start_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, event: QMouseEvent):
        if self.start_pos and event.buttons() == Qt.MouseButton.LeftButton:
            self.move(event.globalPosition().toPoint() - self.start_pos)

    def mouseReleaseEvent(self, event: QMouseEvent):
        self.start_pos = None


class NotificationBanner(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(0)
        self.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ADB5, stop:1 #00d4ff);
                border: none;
                border-bottom: 2px solid rgba(255, 255, 255, 0.3);
            }
        """)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 10, 20, 10)
        
        self.icon_label = QLabel("ℹ️")
        self.icon_label.setStyleSheet("""
            font-size: 20px;
            background: transparent;
            border: none;
        """)
        
        self.message_label = QLabel("")
        self.message_label.setStyleSheet("""
            color: white;
            font-size: 14px;
            font-weight: bold;
            background: transparent;
            border: none;
        """)
        
        close_btn = QPushButton("✕")
        close_btn.setFixedSize(25, 25)
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 255, 255, 0.2);
                color: white;
                border: none;
                border-radius: 12px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(255, 255, 255, 0.4);
            }
        """)
        close_btn.clicked.connect(self.hide_banner)
        
        layout.addWidget(self.icon_label)
        layout.addWidget(self.message_label, 1)
        layout.addWidget(close_btn)
        
        self.hide_timer = QTimer()
        self.hide_timer.timeout.connect(self.hide_banner)
        
    def show_notification(self, message, notification_type="info"):
        """Show notification with animation"""
        # Set icon and color based on type
        type_config = {
            "critical": {"icon": "🚨", "color": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #e74c3c, stop:1 #c0392b)"},
            "warning": {"icon": "⚠️", "color": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f39c12, stop:1 #e67e22)"},
            "success": {"icon": "✅", "color": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #27ae60, stop:1 #229954)"},
            "info": {"icon": "ℹ️", "color": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00ADB5, stop:1 #00d4ff)"}
        }
        
        config = type_config.get(notification_type, type_config["info"])
        self.icon_label.setText(config["icon"])
        self.message_label.setText(message)
        self.setStyleSheet(f"""
            QFrame {{
                background: {config["color"]};
                border: none;
                border-bottom: 2px solid rgba(255, 255, 255, 0.3);
            }}
        """)
        
        # Animate slide down
        self.animation = QPropertyAnimation(self, b"maximumHeight")
        self.animation.setDuration(400)
        self.animation.setStartValue(0)
        self.animation.setEndValue(60)
        self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.animation.start()
        
        # Auto-hide after 5 seconds
        self.hide_timer.stop()
        self.hide_timer.start(5000)
        
    def hide_banner(self):
        """Hide notification with animation"""
        self.hide_timer.stop()
        self.animation = QPropertyAnimation(self, b"maximumHeight")
        self.animation.setDuration(300)
        self.animation.setStartValue(60)
        self.animation.setEndValue(0)
        self.animation.setEasingCurve(QEasingCurve.Type.InCubic)
        self.animation.start()


class AnimatedButton(QFrame):
    """Custom animated button with hover effects"""
    def __init__(self, label, description, callback, parent=None):
        super().__init__(parent)
        self.callback = callback
        self.original_label = label
        self.original_desc = description
        self.is_loading = False
        self.setFixedHeight(90)  # Reduced height
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
        # Initial style
        self.default_style = """
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(0, 173, 181, 0.2), stop:1 rgba(0, 212, 255, 0.1));
                border: 2px solid rgba(0, 173, 181, 0.5);
                border-radius: 12px;
            }
        """
        
        self.hover_style = """
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(0, 173, 181, 0.4), stop:1 rgba(0, 212, 255, 0.3));
                border: 2px solid #00FFF5;
                border-radius: 12px;
            }
        """
        
        self.setStyleSheet(self.default_style)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)  # Reduced padding
        layout.setSpacing(5)
        
        self.label_widget = QLabel(label)
        self.label_widget.setStyleSheet("""
            color: white;
            font-size: 14px;
            font-weight: bold;
            background: transparent;
            border: none;
        """)
        self.label_widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.desc_widget = QLabel(description)
        self.desc_widget.setStyleSheet("""
            color: #b0b0b0;
            font-size: 11px;
            background: transparent;
            border: none;
        """)
        self.desc_widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(self.label_widget)
        layout.addWidget(self.desc_widget)
        layout.addStretch()
        
        # Setup animations
        self.scale_anim = QPropertyAnimation(self, b"geometry")
        self.scale_anim.setDuration(200)
        self.scale_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        
    def enterEvent(self, event):
        """Hover enter - scale up"""
        if self.is_loading:
            return
        self.setStyleSheet(self.hover_style)
        current_geo = self.geometry()
        # Slight scale effect
        new_geo = QRect(
            current_geo.x() - 2,
            current_geo.y() - 2,
            current_geo.width() + 4,
            current_geo.height() + 4
        )
        self.scale_anim.setStartValue(current_geo)
        self.scale_anim.setEndValue(new_geo)
        self.scale_anim.start()
        
    def leaveEvent(self, event):
        """Hover leave - scale down"""
        if self.is_loading:
            return
        self.setStyleSheet(self.default_style)
        current_geo = self.geometry()
        new_geo = QRect(
            current_geo.x() + 2,
            current_geo.y() + 2,
            current_geo.width() - 4,
            current_geo.height() - 4
        )
        self.scale_anim.setStartValue(current_geo)
        self.scale_anim.setEndValue(new_geo)
        self.scale_anim.start()
        
    def mousePressEvent(self, event):
        """Click animation"""
        if self.is_loading:
            return
            
        if event.button() == Qt.MouseButton.LeftButton:
            # Quick press animation
            self.setStyleSheet("""
                QFrame {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                        stop:0 rgba(0, 173, 181, 0.6), stop:1 rgba(0, 212, 255, 0.5));
                    border: 2px solid #02e8ff;
                }
            """)
            QTimer.singleShot(100, lambda: self.setStyleSheet(self.hover_style))
            SoundManager.play_click()
            self.callback()

    def update_label(self, label, description=None):
        """Update button text dynamically"""
        self.label_widget.setText(label)
        if description:
            self.desc_widget.setText(description)

    def set_loading(self, is_loading):
        """Set loading state with pulsing animation"""
        self.is_loading = is_loading
        if is_loading:
            self.setCursor(Qt.CursorShape.WaitCursor)
            self.label_widget.setText("⏳ Processing...")
            self.desc_widget.setText("Please wait")
            
            # Pulsing animation style
            self.pulse_timer = QTimer(self)
            self.pulse_state = 0
            self.pulse_timer.timeout.connect(self._pulse_loading)
            self.pulse_timer.start(100)
        else:
            if hasattr(self, 'pulse_timer'):
                self.pulse_timer.stop()
            self.setCursor(Qt.CursorShape.PointingHandCursor)
            self.label_widget.setText(self.original_label)
            self.desc_widget.setText(self.original_desc)
            self.setStyleSheet(self.default_style)
            
            # Success flash
            self.setStyleSheet("""
                QFrame {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                        stop:0 rgba(46, 204, 113, 0.3), stop:1 rgba(39, 174, 96, 0.2));
                    border: 2px solid #2ecc71;
                    border-radius: 15px;
                }
            """)
            QTimer.singleShot(500, lambda: self.setStyleSheet(self.default_style))

    def _pulse_loading(self):
        """Internal pulse animation step"""
        self.pulse_state = (self.pulse_state + 1) % 20
        alpha = 0.2 + 0.3 * abs(10 - self.pulse_state) / 10
        self.setStyleSheet(f"""
            QFrame {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(241, 196, 15, {alpha}), stop:1 rgba(243, 156, 18, {alpha/2}));
                border: 2px solid rgba(241, 196, 15, 0.8);
                border-radius: 15px;
            }}
        """)


class NetworkBackground(QWidget):
    """Animated background with floating particles and connections"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.particles = []
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_particles)
        self.timer.start(33)  # ~30 FPS
        
        # Initialize particles
        self.num_particles = 40
        self.connection_distance = 120
        
    def resizeEvent(self, event):
        # Re-initialize particles on resize to spread them out
        if not self.particles:
            for _ in range(self.num_particles):
                self.particles.append({
                    'x': random.randint(0, self.width()),
                    'y': random.randint(0, self.height()),
                    'vx': random.uniform(-0.8, 0.8),
                    'vy': random.uniform(-0.8, 0.8),
                    'size': random.randint(2, 4)
                })
        super().resizeEvent(event)

    def update_particles(self):
        for p in self.particles:
            p['x'] += p['vx']
            p['y'] += p['vy']
            
            # Bounce off edges
            if p['x'] < 0 or p['x'] > self.width():
                p['vx'] *= -1
            if p['y'] < 0 or p['y'] > self.height():
                p['vy'] *= -1
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Draw gradient background
        gradient = QLinearGradient(0, 0, self.width(), self.height())
        gradient.setColorAt(0, QColor("#0f0c29"))
        gradient.setColorAt(0.5, QColor("#302b63"))
        gradient.setColorAt(1, QColor("#24243e"))
        painter.fillRect(self.rect(), gradient)
        
        # Draw connections
        painter.setPen(Qt.PenStyle.NoPen)
        for i, p1 in enumerate(self.particles):
            # Draw particle
            painter.setBrush(QColor(0, 173, 181, 150))
            painter.drawEllipse(QPoint(int(p1['x']), int(p1['y'])), p1['size'], p1['size'])
            
            # Draw lines
            for j in range(i + 1, len(self.particles)):
                p2 = self.particles[j]
                dx = p1['x'] - p2['x']
                dy = p1['y'] - p2['y']
                dist = math.sqrt(dx*dx + dy*dy)
                
                if dist < self.connection_distance:
                    opacity = int((1 - dist / self.connection_distance) * 100)
                    painter.setPen(QPen(QColor(0, 173, 181, opacity), 1))
                    painter.drawLine(int(p1['x']), int(p1['y']), int(p2['x']), int(p2['y']))


class SoundManager:
    """Synthesized sound effects using Windows Beep"""
    @staticmethod
    def play_click():
        threading.Thread(target=winsound.Beep, args=(1200, 30), daemon=True).start()

    @staticmethod
    def play_success():
        def _chime():
            winsound.Beep(1000, 100)
            winsound.Beep(1500, 100)
            winsound.Beep(2000, 200)
        threading.Thread(target=_chime, daemon=True).start()

    @staticmethod
    def play_alert():
        def _siren():
            for _ in range(3):
                winsound.Beep(800, 100)
                winsound.Beep(1200, 100)
        threading.Thread(target=_siren, daemon=True).start()


class SoundManager:
    """Synthesized sound effects using Windows Beep"""
    @staticmethod
    def play_click():
        threading.Thread(target=winsound.Beep, args=(1200, 30), daemon=True).start()

    @staticmethod
    def play_success():
        def _chime():
            winsound.Beep(1000, 100)
            winsound.Beep(1500, 100)
            winsound.Beep(2000, 200)
        threading.Thread(target=_chime, daemon=True).start()

    @staticmethod
    def play_alert():
        def _siren():
            for _ in range(3):
                winsound.Beep(800, 100)
                winsound.Beep(1200, 100)
        threading.Thread(target=_siren, daemon=True).start()


class CPUGraphWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(150)
        self.data = deque([0] * 60, maxlen=60)  # Store last 60 data points
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_data)
        self.timer.start(500)  # Update every 500ms
        
        self.setMouseTracking(True)  # Enable hover tracking
        self.mouse_pos = None
        
        self.setStyleSheet("background: transparent;")

    def update_data(self):
        cpu_percent = psutil.cpu_percent()
        self.data.append(cpu_percent)
        self.update()  # Trigger repaint

    def mouseMoveEvent(self, event):
        self.mouse_pos = event.pos()
        self.update()

    def leaveEvent(self, event):
        self.mouse_pos = None
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        width = self.width()
        height = self.height()
        
        # Draw background
        painter.fillRect(0, 0, width, height, QColor(0, 0, 0, 100))
        
        # Draw grid
        painter.setPen(QPen(QColor(255, 255, 255, 30), 1, Qt.PenStyle.DotLine))
        for i in range(0, height, 30):
            painter.drawLine(0, i, width, i)
        for i in range(0, width, 30):
            painter.drawLine(i, 0, i, height)
            
        if not self.data:
            return

        # Determine color based on load
        current_val = self.data[-1]
        if current_val > 80:
            main_color = QColor(231, 76, 60)  # Red
        elif current_val > 50:
            main_color = QColor(243, 156, 18)  # Orange
        else:
            main_color = QColor(0, 255, 234)  # Cyan

        # Create path for the graph
        path = QPainterPath()
        x_step = width / (len(self.data) - 1) if len(self.data) > 1 else width
        
        # Start point
        path.moveTo(0, height - (self.data[0] / 100 * height))
        
        points = []
        for i, value in enumerate(self.data):
            x = i * x_step
            y = height - (value / 100 * height)
            path.lineTo(x, y)
            points.append((x, y, value))
            
        # Draw gradient under the line
        gradient_path = QPainterPath(path)
        gradient_path.lineTo(width, height)
        gradient_path.lineTo(0, height)
        gradient_path.closeSubpath()
        
        gradient = QLinearGradient(0, 0, 0, height)
        gradient.setColorAt(0, QColor(main_color.red(), main_color.green(), main_color.blue(), 150))
        gradient.setColorAt(1, QColor(main_color.red(), main_color.green(), main_color.blue(), 10))
        painter.fillPath(gradient_path, QBrush(gradient))
        
        # Draw the line itself
        painter.setPen(QPen(main_color, 2))
        painter.drawPath(path)
        
        # Draw glowing dot at end
        last_x, last_y, _ = points[-1]
        painter.setBrush(main_color)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(QPoint(int(last_x), int(last_y)), 4, 4)
        
        # Hover effect
        if self.mouse_pos:
            mx = self.mouse_pos.x()
            # Find closest point
            closest = min(points, key=lambda p: abs(p[0] - mx))
            cx, cy, cval = closest
            
            # Draw vertical line
            painter.setPen(QPen(QColor(255, 255, 255, 100), 1, Qt.PenStyle.DashLine))
            painter.drawLine(int(cx), 0, int(cx), height)
            
            # Draw value bubble
            painter.setBrush(QColor(0, 0, 0, 200))
            painter.setPen(main_color)
            rect = QRect(int(cx) - 25, int(cy) - 25, 50, 20)
            painter.drawRoundedRect(rect, 5, 5)
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, f"{int(cval)}%")
        
        # Draw current value text (top right)
        painter.setPen(QColor(255, 255, 255))
        painter.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        painter.drawText(width - 80, 20, f"CPU: {current_val}%")


class SecureVaultGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 SecureVault - Ransomware Detection System")
        self.setGeometry(100, 80, 1300, 700)  # Wider window for side-by-side layout
        self.folder_to_monitor = os.path.expanduser("~")  # Default to User Home
        self.alert_queue = queue.Queue()
        
        # Monitoring state
        self.file_monitor_active = False
        self.cpu_monitor_active = False
        self.file_stop_event = threading.Event()
        self.cpu_stop_event = threading.Event()
        
        # Fade in effect for main window
        self.setWindowOpacity(0)
        
        self.init_ui()
        
        # Start animations
        self.fade_in_animation()
        self.animate_background()
        QTimer.singleShot(100, self.animate_buttons_entrance)

    def animate_background(self):
        """Dynamic background animation"""
        self.bg_timer = QTimer()
        self.bg_angle = 0
        
        def update_bg():
            self.bg_angle = (self.bg_angle + 1) % 360
            # Calculate colors based on angle for a subtle shift
            # We'll just shift the gradient stops slightly or rotate the gradient
            # For simplicity and performance, let's rotate the gradient vector
            
            # Actually, let's just shift the colors slightly
            # Cycle between blue-ish and purple-ish themes
            
            # Simple implementation: Update the stylesheet of the central widget
            # Note: Updating stylesheet frequently can be expensive. 
            # Let's do it less frequently or use a more optimized approach.
            # For now, let's just stick to the static gradient as frequent stylesheet updates might cause flicker.
            # Instead, let's animate the CPU graph which provides enough 'liveness'.
            pass
            
        # self.bg_timer.timeout.connect(update_bg)
        # self.bg_timer.start(100)
        pass

    def animate_buttons_entrance(self):
        """Staggered entrance animation for buttons"""
        self.button_animations = QParallelAnimationGroup()
        
        delay = 0
        for key, btn in self.buttons.items():
            # Create opacity effect
            effect = QGraphicsOpacityEffect(btn)
            btn.setGraphicsEffect(effect)
            effect.setOpacity(0)
            
            # Opacity animation
            opacity_anim = QPropertyAnimation(effect, b"opacity")
            opacity_anim.setDuration(600)
            opacity_anim.setStartValue(0)
            opacity_anim.setEndValue(1)
            opacity_anim.setEasingCurve(QEasingCurve.Type.OutBack)
            
            # Position animation (slide up)
            pos_anim = QPropertyAnimation(btn, b"pos")
            pos_anim.setDuration(600)
            start_pos = btn.pos()
            # Start slightly lower
            btn.move(start_pos.x(), start_pos.y() + 50)
            pos_anim.setStartValue(QPoint(start_pos.x(), start_pos.y() + 50))
            pos_anim.setEndValue(start_pos)
            pos_anim.setEasingCurve(QEasingCurve.Type.OutBack)
            
            # Group for this button
            btn_group = QParallelAnimationGroup()
            btn_group.addAnimation(opacity_anim)
            btn_group.addAnimation(pos_anim)
            
            # Add delay using a sequential group
            seq_group = QSequentialAnimationGroup()
            seq_group.addPause(delay)
            seq_group.addAnimation(btn_group)
            
            self.button_animations.addAnimation(seq_group)
            delay += 100
            
        self.button_animations.start()

    def fade_in_animation(self):
        """Smooth fade in for entire window"""
        self.opacity_timer = QTimer()
        self.current_opacity = 0
        
        def increase_opacity():
            self.current_opacity += 0.05
            if self.current_opacity >= 1:
                self.current_opacity = 1
                self.opacity_timer.stop()
            self.setWindowOpacity(self.current_opacity)
        
        self.opacity_timer.timeout.connect(increase_opacity)
        self.opacity_timer.start(20)

    def init_ui(self):
        # Main container with animated background
        container = NetworkBackground()
        # Removed static stylesheet as NetworkBackground handles painting
        
        # Main vertical layout for notification banner + content
        main_container_layout = QVBoxLayout(container)
        main_container_layout.setContentsMargins(0, 0, 0, 0)
        main_container_layout.setSpacing(0)
        
        # Notification banner at top
        self.notification_banner = NotificationBanner()
        main_container_layout.addWidget(self.notification_banner)
        
        # Content area
        content_area = QWidget()
        content_area.setStyleSheet("background: transparent;")
        main_layout = QVBoxLayout(content_area)
        main_layout.setContentsMargins(40, 40, 40, 40)
        main_layout.setSpacing(20)

        # Header section (Full Width)
        header_container = QWidget()
        header_container.setStyleSheet("background: transparent;")
        header_layout = QVBoxLayout(header_container)
        header_layout.setSpacing(10)
        
        # Title with glow effect
        title = QLabel("🔐 SecureVault")
        title.setStyleSheet("""
            color: white;
            font-size: 42px;
            font-weight: bold;
            background: transparent;
        """)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Subtitle
        subtitle = QLabel("Ransomware Detection & Protection System")
        subtitle.setStyleSheet("""
            color: #00ADB5;
            font-size: 16px;
            background: transparent;
            letter-spacing: 2px;
        """)
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        main_layout.addWidget(header_container)

        # Split View Container (Left: Buttons, Right: Activity)
        split_container = QWidget()
        split_layout = QHBoxLayout(split_container)
        split_layout.setContentsMargins(0, 20, 0, 0)
        split_layout.setSpacing(40)

        # === LEFT PANEL (Status + Buttons) ===
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(20)
        left_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        # === Scope Button (Compact) ===
        self.scope_btn = QPushButton(f"📂 Scope: {os.path.basename(self.folder_to_monitor) or self.folder_to_monitor}")
        self.scope_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scope_btn.setToolTip(f"Current: {self.folder_to_monitor}\nClick to change folder")
        self.scope_btn.setStyleSheet("""
            QPushButton {
                background: rgba(0, 173, 181, 0.1);
                color: #00ADB5;
                border: 1px solid rgba(0, 173, 181, 0.3);
                border-radius: 15px;
                padding: 8px 15px;
                font-size: 12px;
                font-weight: bold;
                text-align: left;
            }
            QPushButton:hover {
                background: rgba(0, 173, 181, 0.2);
                border: 1px solid #00ADB5;
            }
        """)
        self.scope_btn.clicked.connect(self.change_folder)
        left_layout.addWidget(self.scope_btn)

        # Status indicator
        self.status_label = QLabel("🟢 System Ready")
        self.status_label.setStyleSheet("""
            color: #4ecca3;
            font-size: 18px;
            font-weight: bold;
            background: transparent;
            padding: 10px;
            border: 1px solid rgba(78, 204, 163, 0.3);
            border-radius: 10px;
        """)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        left_layout.addWidget(self.status_label)
        
        # Add pulsing animation to status
        self.start_status_pulse()

        # Action buttons section
        buttons_label = QLabel("Quick Actions")
        buttons_label.setStyleSheet("""
            color: white;
            font-size: 24px;
            font-weight: bold;
            background: transparent;
            margin-top: 10px;
        """)
        left_layout.addWidget(buttons_label)

        # Action buttons grid
        buttons_container = QWidget()
        buttons_container.setStyleSheet("background: transparent;")
        buttons_layout = QGridLayout(buttons_container)
        buttons_layout.setSpacing(15)

        # Define buttons with their properties
        self.buttons = {}
        button_configs = [
            ("🛡️ Create Baseline", "Generate file hash baseline", self.create_baseline, 0, 0, "baseline"),
            ("🔍 Manual Scan", "Check for file changes", self.check_changes, 0, 1, "scan"),
            ("🧲 Create Honeypot", "Deploy trap file", self.create_honeypot, 1, 0, "honeypot"),
            ("👁️ Real-Time Monitor", "Watch files live", self.start_monitor, 1, 1, "monitor"),
            ("⚙️ CPU Monitor", "Track suspicious processes", self.start_cpu_monitor, 2, 0, "cpu"),
            ("📄 View Logs", "Activity history", self.view_logs, 2, 1, "logs")
        ]

        for label, desc, callback, row, col, key in button_configs:
            btn = AnimatedButton(label, desc, callback)
            self.buttons[key] = btn
            buttons_layout.addWidget(btn, row, col)

        left_layout.addWidget(buttons_container)
        split_layout.addWidget(left_panel, 60) # 60% width

        # === RIGHT PANEL (Activity Feed + CPU Graph) ===
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)

        # CPU Graph Label
        graph_label = QLabel("Live System Load")
        graph_label.setStyleSheet("""
            color: #00ADB5;
            font-size: 22px;
            font-weight: bold;
            background: transparent;
            margin-bottom: 5px;
        """)
        right_layout.addWidget(graph_label)

        # CPU Graph Widget
        self.cpu_graph = CPUGraphWidget()
        right_layout.addWidget(self.cpu_graph)

        # Activity feed header with Export button
        activity_header = QWidget()
        activity_header_layout = QHBoxLayout(activity_header)
        activity_header_layout.setContentsMargins(0, 10, 0, 0)
        
        activity_label = QLabel("Recent Activity")
        activity_label.setStyleSheet("""
            color: #00ADB5;
            font-size: 22px;
            font-weight: bold;
            background: transparent;
        """)
        
        export_btn = QPushButton("📄 Export Evidence")
        export_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        export_btn.setStyleSheet("""
            QPushButton {
                background: rgba(0, 173, 181, 0.2);
                color: #00ADB5;
                border: 1px solid #00ADB5;
                border-radius: 5px;
                padding: 5px 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: rgba(0, 173, 181, 0.4);
            }
        """)
        export_btn.clicked.connect(self.export_report)
        
        activity_header_layout.addWidget(activity_label)
        activity_header_layout.addStretch()
        activity_header_layout.addWidget(export_btn)
        
        right_layout.addWidget(activity_header)

        self.activity_feed = QTextEdit()
        self.activity_feed.setReadOnly(True)
        # Removed fixed height to allow expansion
        self.activity_feed.setStyleSheet("""
            QTextEdit {
                background-color: rgba(10, 10, 20, 0.9);
                border: 2px solid #00ADB5;
                border-radius: 12px;
                color: #00ffea;
                padding: 15px;
                font-size: 14px;
                font-family: 'Consolas', 'Courier New', monospace;
                selection-background-color: #00ADB5;
                selection-color: white;
            }
            QScrollBar:vertical {
                background: rgba(0, 0, 0, 0.3);
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background: #00ADB5;
                border-radius: 6px;
                min-height: 20px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                background: none;
            }
        """)
        self.activity_feed.append("System initialized successfully...")
        right_layout.addWidget(self.activity_feed)
        
        split_layout.addWidget(right_panel, 40) # 40% width

        main_layout.addWidget(split_container)

        # Add content to main container
        main_container_layout.addWidget(content_area)

        self.setCentralWidget(container)

        # Start queue polling for real-time logs
        self.start_queue_polling()

        # Setup System Tray
        self.setup_tray_icon()

    def setup_tray_icon(self):
        """Initialize system tray icon"""
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
        
        # Tray menu
        tray_menu = QMenu()
        show_action = QAction("Show SecureVault", self)
        show_action.triggered.connect(self.show)
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(QApplication.instance().quit)
        
        tray_menu.addAction(show_action)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        
        # Double click to show
        self.tray_icon.activated.connect(
            lambda reason: self.show() if reason == QSystemTrayIcon.ActivationReason.DoubleClick else None
        )

    def closeEvent(self, event):
        """Minimize to tray instead of closing"""
        if self.tray_icon.isVisible():
            self.hide()
            self.tray_icon.showMessage(
                "SecureVault",
                "Application minimized to tray. Right-click icon to quit.",
                QSystemTrayIcon.MessageIcon.Information,
                2000
            )
            event.ignore()
        else:
            event.accept()

    def export_report(self):
        """Export activity log to HTML"""
        SoundManager.play_click()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"Evidence_Report_{timestamp}.html"
        
        content = self.activity_feed.toHtml()
        
        html_template = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; background: #1a1a1a; color: #e0e0e0; padding: 20px; }}
                h1 {{ color: #00ADB5; border-bottom: 2px solid #00ADB5; padding-bottom: 10px; }}
                .timestamp {{ color: #888; font-size: 0.9em; }}
                .log-container {{ background: #2a2a2a; padding: 15px; border-radius: 10px; border: 1px solid #444; }}
            </style>
        </head>
        <body>
            <h1>🔐 SecureVault Evidence Report</h1>
            <p class="timestamp">Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <div class="log-container">
                {content}
            </div>
        </body>
        </html>
        """
        
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(html_template)
            
            SoundManager.play_success()
            self.notification_banner.show_notification(f"Report saved: {filename}", "success")
            os.startfile(filename) # Open report automatically
        except Exception as e:
            self.notification_banner.show_notification(f"Export failed: {str(e)}", "error")

    def start_status_pulse(self):
        """Pulsing animation for status indicator"""
        self.pulse_timer = QTimer()
        self.pulse_state = 0
        
        def pulse():
            self.pulse_state = (self.pulse_state + 1) % 20
            opacity = 0.7 + 0.3 * abs(10 - self.pulse_state) / 10
            current_style = self.status_label.styleSheet()
            # Keep the color but adjust opacity feel through font weight
            self.status_label.setStyleSheet(current_style)
        
        self.pulse_timer.timeout.connect(pulse)
        self.pulse_timer.start(100)

    def update_status(self, message, color="#4ecca3"):
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"""
            color: {color};
            font-size: 18px;
            font-weight: bold;
            background: transparent;
            padding: 15px;
        """)
        self.activity_feed.append(f"• {message}")
        self.activity_feed.moveCursor(QTextCursor.MoveOperation.End)
        
        # Smooth scroll animation
        scrollbar = self.activity_feed.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def start_queue_polling(self):
        """Poll the alert queue for real-time updates from backend"""
        self.queue_timer = QTimer()
        self.queue_timer.timeout.connect(self.check_alert_queue)
        self.queue_timer.start(500)  # Check every 500ms
        
    def change_folder(self):
        """Change the monitored directory"""
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Monitor", self.folder_to_monitor)
        if folder:
            self.folder_to_monitor = folder
            # Update button text with folder name (or full path if short)
            display_name = os.path.basename(folder) or folder
            self.scope_btn.setText(f"📂 Scope: {display_name}")
            self.scope_btn.setToolTip(f"Current: {folder}\nClick to change folder")
            
            self.update_status(f"📂 Scope changed to: {folder}", "#3498db")
            self.notification_banner.show_notification(f"Monitoring scope updated: {folder}", "info")
            
            # If monitoring was active, stop it (user needs to restart)
            if self.file_monitor_active:
                self.start_monitor() # This toggles it OFF
                self.notification_banner.show_notification("Monitoring stopped due to scope change. Please restart.", "warning")
    
    def check_alert_queue(self):
        """Check queue for new alerts and display them"""
        try:
            while not self.alert_queue.empty():
                message = self.alert_queue.get_nowait()
                
                # Only show banner for critical/warning events
                if "MASS FILE CHANGES" in message or "🚨" in message:
                    self.notification_banner.show_notification(message, "critical")
                    self.update_status(f"🚨 ALERT: {message}", "#e74c3c")
                    SoundManager.play_alert()
                elif "High sustained CPU" in message:
                    self.notification_banner.show_notification(message, "warning")
                    self.update_status(f"⚠️ {message}", "#f39c12")
                    SoundManager.play_alert()
                elif "modified" in message.lower() or "deleted" in message.lower():
                    # Show banner only for file changes, not for routine messages
                    if "File changed:" in message or "Deleted:" in message:
                        self.notification_banner.show_notification(f"File {message}", "warning")
                        SoundManager.play_alert()
                    self.update_status(f"⚠️ {message}", "#e67e22")
                elif "created" in message.lower() and "New file" in message:
                    # Show banner only for new file creation
                    self.notification_banner.show_notification(message, "info")
                    self.update_status(f"ℹ️ {message}", "#3498db")
                    SoundManager.play_success()
                else:
                    # Routine messages (monitoring started, no threats, etc.) - NO BANNER
                    self.update_status(message, "#00ADB5")
        except queue.Empty:
            pass

    # === Functional Connections ===
    def create_baseline(self):
        self.buttons["baseline"].set_loading(True)
        self.update_status("🛡️ Creating baseline...", "#00ADB5")
        self.notification_banner.show_notification("Creating file hash baseline...", "info")
        threading.Thread(target=create_baseline, args=(self.folder_to_monitor,), daemon=True).start()
        QTimer.singleShot(2000, lambda: [
            self.buttons["baseline"].set_loading(False),
            self.update_status("🟢 Baseline created successfully", "#4ecca3"),
            self.notification_banner.show_notification("Baseline created successfully!", "success")
        ])

    def check_changes(self):
        self.buttons["scan"].set_loading(True)
        self.update_status("🔍 Scanning for changes...", "#00ADB5")
        self.notification_banner.show_notification("Scanning for file changes...", "info")
        threading.Thread(target=check_for_changes, daemon=True).start()
        QTimer.singleShot(2000, lambda: [
            self.buttons["scan"].set_loading(False),
            self.update_status("🟢 Manual scan completed", "#4ecca3"),
            self.notification_banner.show_notification("Scan completed - No threats detected", "success")
        ])

    def create_honeypot(self):
        self.buttons["honeypot"].set_loading(True)
        self.update_status("🧲 Deploying honeypot...", "#00ADB5")
        self.notification_banner.show_notification("Deploying honeypot trap file...", "info")
        threading.Thread(target=create_honeypot, daemon=True).start()
        QTimer.singleShot(1500, lambda: [
            self.buttons["honeypot"].set_loading(False),
            self.update_status("🟢 Honeypot deployed successfully", "#4ecca3"),
            self.notification_banner.show_notification("Honeypot active - Monitoring for intrusions", "success")
        ])

    def start_monitor(self):
        if not self.file_monitor_active:
            # Start monitoring
            self.file_monitor_active = True
            self.file_stop_event.clear()
            self.buttons["monitor"].update_label("🛑 Stop Monitor", "Click to stop watching")
            self.buttons["monitor"].setStyleSheet("""
                QFrame {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                        stop:0 rgba(231, 76, 60, 0.2), stop:1 rgba(192, 57, 43, 0.1));
                    border: 2px solid rgba(231, 76, 60, 0.5);
                    border-radius: 15px;
                }
                QFrame:hover {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                        stop:0 rgba(231, 76, 60, 0.3), stop:1 rgba(192, 57, 43, 0.2));
                    border: 2px solid #e74c3c;
                }
            """)
            self.buttons["monitor"].default_style = self.buttons["monitor"].styleSheet()
            self.buttons["monitor"].hover_style = self.buttons["monitor"].styleSheet().replace("0.2", "0.4").replace("0.1", "0.3")
            
            self.update_status("👁️ Real-time file monitoring started", "#f39c12")
            threading.Thread(target=start_real_time_monitor, args=(self.folder_to_monitor, self.alert_queue, self.file_stop_event), daemon=True).start()
        else:
            # Stop monitoring
            self.file_monitor_active = False
            self.file_stop_event.set()
            self.buttons["monitor"].update_label("👁️ Real-Time Monitor", "Watch files live")
            
            # Reset style
            self.buttons["monitor"].setStyleSheet("""
                QFrame {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                        stop:0 rgba(0, 173, 181, 0.2), stop:1 rgba(0, 212, 255, 0.1));
                    border: 2px solid rgba(0, 173, 181, 0.5);
                    border-radius: 15px;
                }
            """)
            self.buttons["monitor"].default_style = self.buttons["monitor"].styleSheet()
            self.buttons["monitor"].hover_style = """
                QFrame {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                        stop:0 rgba(0, 173, 181, 0.4), stop:1 rgba(0, 212, 255, 0.3));
                    border: 2px solid #00ADB5;
                }
            """
            self.update_status("🛑 Real-time monitoring stopped", "#e74c3c")

    def start_cpu_monitor(self):
        if not self.cpu_monitor_active:
            # Start monitoring
            self.cpu_monitor_active = True
            self.cpu_stop_event.clear()
            self.buttons["cpu"].update_label("🛑 Stop CPU Monitor", "Click to stop tracking")
            self.buttons["cpu"].setStyleSheet("""
                QFrame {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                        stop:0 rgba(231, 76, 60, 0.2), stop:1 rgba(192, 57, 43, 0.1));
                    border: 2px solid rgba(231, 76, 60, 0.5);
                    border-radius: 15px;
                }
                QFrame:hover {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                        stop:0 rgba(231, 76, 60, 0.3), stop:1 rgba(192, 57, 43, 0.2));
                    border: 2px solid #e74c3c;
                }
            """)
            self.buttons["cpu"].default_style = self.buttons["cpu"].styleSheet()
            self.buttons["cpu"].hover_style = self.buttons["cpu"].styleSheet().replace("0.2", "0.4").replace("0.1", "0.3")
            
            self.update_status("⚙️ CPU process monitoring started", "#f39c12")
            threading.Thread(target=monitor_processes_sustained, kwargs={'alert_queue': self.alert_queue, 'stop_event': self.cpu_stop_event}, daemon=True).start()
        else:
            # Stop monitoring
            self.cpu_monitor_active = False
            self.cpu_stop_event.set()
            self.buttons["cpu"].update_label("⚙️ CPU Monitor", "Track suspicious processes")
            
            # Reset style
            self.buttons["cpu"].setStyleSheet("""
                QFrame {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                        stop:0 rgba(0, 173, 181, 0.2), stop:1 rgba(0, 212, 255, 0.1));
                    border: 2px solid rgba(0, 173, 181, 0.5);
                    border-radius: 15px;
                }
            """)
            self.buttons["cpu"].default_style = self.buttons["cpu"].styleSheet()
            self.buttons["cpu"].hover_style = """
                QFrame {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                        stop:0 rgba(0, 173, 181, 0.4), stop:1 rgba(0, 212, 255, 0.3));
                    border: 2px solid #00ADB5;
                }
            """
            self.update_status("🛑 CPU monitoring stopped", "#e74c3c")

    def view_logs(self):
        # Log file is in the application directory, not necessarily the monitored folder
        log_file = os.path.abspath("suspicious_activity.log")
        self.log_window = LogViewerWindow(log_file)
        self.log_window.show()
        self.update_status("📄 Logs opened", "#00ADB5")


class SplashScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(500, 350)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Main container
        container = QFrame()
        container.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0f0c29, stop:1 #24243e);
                border: 2px solid #00ADB5;
                border-radius: 20px;
            }
        """)
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(40, 40, 40, 40)
        container_layout.setSpacing(20)
        
        # Logo/Icon
        logo = QLabel("🔐")
        logo.setStyleSheet("""
            font-size: 64px;
            background: transparent;
            border: none;
        """)
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Title
        title = QLabel("SecureVault")
        title.setStyleSheet("""
            color: white;
            font-size: 36px;
            font-weight: bold;
            background: transparent;
            border: none;
        """)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Subtitle
        subtitle = QLabel("Ransomware Detection System")
        subtitle.setStyleSheet("""
            color: #00ADB5;
            font-size: 14px;
            letter-spacing: 3px;
            background: transparent;
            border: none;
        """)
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Loading Status
        self.status_label = QLabel("Initializing...")
        self.status_label.setStyleSheet("""
            color: #b0b0b0;
            font-size: 12px;
            background: transparent;
            border: none;
        """)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Progress Bar
        self.progress = QProgressBar()
        self.progress.setStyleSheet("""
            QProgressBar {
                background-color: rgba(255, 255, 255, 0.1);
                border-radius: 5px;
                height: 6px;
                text-align: center;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ADB5, stop:1 #00d4ff);
                border-radius: 5px;
            }
        """)
        self.progress.setTextVisible(False)
        
        container_layout.addStretch()
        container_layout.addWidget(logo)
        container_layout.addWidget(title)
        container_layout.addWidget(subtitle)
        container_layout.addStretch()
        container_layout.addWidget(self.status_label)
        container_layout.addWidget(self.progress)
        
        layout.addWidget(container)
        
        # Fade in animation
        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.opacity_effect)
        self.anim = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.anim.setDuration(500)
        self.anim.setStartValue(0)
        self.anim.setEndValue(1)
        self.anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.anim.start()

def run_gui():
    app = QApplication(sys.argv)
    
    # Show Splash Screen
    splash = SplashScreen()
    splash.show()
    
    # Main Window (hidden initially)
    window = SecureVaultGUI()
    
    # Simulate loading process
    progress = 0
    
    def update_loading():
        nonlocal progress
        progress += 2
        splash.progress.setValue(progress)
        
        if progress < 30:
            splash.status_label.setText("Initializing core modules...")
        elif progress < 60:
            splash.status_label.setText("Loading security definitions...")
        elif progress < 80:
            splash.status_label.setText("Starting monitoring engine...")
        elif progress < 95:
            splash.status_label.setText("Preparing user interface...")
            
        if progress >= 100:
            timer.stop()
            # Fade out splash
            fade_out = QPropertyAnimation(splash.opacity_effect, b"opacity")
            fade_out.setDuration(500)
            fade_out.setStartValue(1)
            fade_out.setEndValue(0)
            fade_out.finished.connect(lambda: [splash.close(), window.show()])
            fade_out.start()
            
            # Keep reference to avoid garbage collection
            splash.fade_out = fade_out
            
    timer = QTimer()
    timer.timeout.connect(update_loading)
    timer.start(30)  # Total time approx 3 seconds
    
    sys.exit(app.exec())

if __name__ == "__main__":
    import signal
    signal.signal(signal.SIGINT, signal.SIG_DFL)  # Allow Ctrl+C to kill the app
    try:
        run_gui()
    except KeyboardInterrupt:
        print("\n👋 SecureVault GUI closed by user.")
        sys.exit(0)
