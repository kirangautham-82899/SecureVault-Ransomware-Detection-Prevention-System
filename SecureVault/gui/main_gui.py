import sys
import os
import threading
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QLabel, QPushButton,
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QFrame,
    QLineEdit, QFileDialog
)
from PyQt6.QtGui import QFont, QTextCursor, QMouseEvent
from PyQt6.QtCore import Qt, QPropertyAnimation, QRect, QEasingCurve, QPoint

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
        self.setGeometry(400, 200, 600, 400)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.start_pos = None

        self.log_path = log_path
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.setStyleSheet("""
            QWidget {
                background-color: rgba(255, 255, 255, 0.92);
                border: 2px solid #00ADB5;
                border-radius: 12px;
            }
            QTextEdit {
                background-color: transparent;
                padding: 10px;
                font-size: 13px;
                border: none;
            }
            QLineEdit {
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 8px;
            }
            QPushButton {
                background-color: #00ADB5;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 6px 12px;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #02cbd2;
            }
        """)

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("🔍 Search logs...")
        self.search_bar.textChanged.connect(self.search_logs)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.load_logs()

        save_button = QPushButton("💾 Save Logs")
        save_button.clicked.connect(self.save_logs)

        layout.addWidget(self.search_bar)
        layout.addWidget(self.log_text)
        layout.addWidget(save_button)

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


class SecureVaultGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 SecureVault - Ransomware Detection System")
        self.setGeometry(200, 100, 1000, 600)
        self.setStyleSheet("background-color: white;")
        self.folder_to_monitor = os.getcwd()
        self.init_ui()

    def init_ui(self):
        container = QWidget()
        container.setStyleSheet("""
            QWidget {
                background-image: url('C:/Users/kiran/SecureVault/gui/assets/bg.jpg');
                background-repeat: no-repeat;
                background-position: center;
                background-size: cover;
            }
        """)
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        # === Sidebar ===
        self.sidebar = QFrame()
        self.sidebar.setFixedWidth(200)
        self.sidebar.setStyleSheet("""
            QFrame {
                background-color: rgba(34, 40, 49, 0.95);
                border-right: 2px solid #EEEEEE;
            }
        """)
        self.sidebar_layout = QVBoxLayout(self.sidebar)
        self.sidebar_layout.setContentsMargins(10, 30, 10, 10)
        self.sidebar_layout.setSpacing(20)

        # Sidebar Buttons
        buttons = [
            ("🛡️ Create Baseline", self.create_baseline),
            ("🔍 Manual Scan", self.check_changes),
            ("🧲 Create Honeypot", self.create_honeypot),
            ("👁️ Start Real-Time Monitor", self.start_monitor),
            ("⚙️ CPU Monitor", self.start_cpu_monitor),
            ("📄 View Logs", self.view_logs)
        ]

        for label, callback in buttons:
            btn = QPushButton(label)
            btn.setFixedHeight(40)
            btn.setStyleSheet("""
                QPushButton {
                    color: white;
                    background-color: #00ADB5;
                    border: none;
                    border-radius: 10px;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #02cbd2;
                }
            """)
            btn.clicked.connect(callback)
            self.sidebar_layout.addWidget(btn)

        self.sidebar_layout.addStretch()

        layout.addWidget(self.sidebar)
        self.setCentralWidget(container)

        # Redirect print to console
        sys.stdout = self
        sys.stderr = self

        # Animate sidebar
        self.animate_sidebar()

    def animate_sidebar(self):
        self.sidebar.setGeometry(-200, 0, 200, self.height())
        anim = QPropertyAnimation(self.sidebar, b"geometry")
        anim.setDuration(700)
        anim.setStartValue(QRect(-200, 0, 200, self.height()))
        anim.setEndValue(QRect(0, 0, 200, self.height()))
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.start()
        self.sidebar_anim = anim

    def write(self, message):
        print(message)

    def flush(self):
        pass

    # === Functional Connections ===
    def create_baseline(self):
        threading.Thread(target=create_baseline, args=(self.folder_to_monitor,), daemon=True).start()

    def check_changes(self):
        threading.Thread(target=check_for_changes, daemon=True).start()

    def create_honeypot(self):
        threading.Thread(target=create_honeypot, daemon=True).start()

    def start_monitor(self):
        threading.Thread(target=start_real_time_monitor, args=(self.folder_to_monitor,), daemon=True).start()

    def start_cpu_monitor(self):
        threading.Thread(target=monitor_processes_sustained, daemon=True).start()

    def view_logs(self):
        log_file = os.path.join(self.folder_to_monitor, "suspicious_activity.log")
        self.log_window = LogViewerWindow(log_file)
        self.log_window.show()


def run_gui():
    app = QApplication(sys.argv)
    window = SecureVaultGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    run_gui()
