# gui/main_gui.py
"""SecureVault desktop dashboard (PyQt6)."""
import os
import sys
import html
import time
import datetime
import threading
import itertools

from PyQt6.QtCore import (
    Qt, QObject, QTimer, QUrl, QPoint, QPropertyAnimation, QParallelAnimationGroup,
    QSequentialAnimationGroup, QEasingCurve, pyqtSignal,
)
from PyQt6.QtGui import (
    QAction, QDesktopServices, QColor, QPainter, QLinearGradient, QRadialGradient,
    QPalette, QGuiApplication,
)
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QPushButton, QVBoxLayout,
    QHBoxLayout, QGridLayout, QLineEdit, QFileDialog, QDialog, QPlainTextEdit,
    QSystemTrayIcon, QMenu, QGraphicsOpacityEffect, QButtonGroup, QFrame, QMessageBox,
)

# Allow running this file directly as well as via main.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import (  # noqa: E402
    APP_NAME, APP_VERSION, APP_DIR, LOG_FILE,
    create_baseline, check_for_changes, create_honeypot, honeypot_path,
    start_real_time_monitor, monitor_processes_sustained, load_baseline,
    normalize_path, emit, INFO, SUCCESS, WARNING, CRITICAL,
)
from stream import LiveStreamServer  # noqa: E402
from scanner import Scanner, OnAccessScanner  # noqa: E402
from gui import theme  # noqa: E402
from gui.widgets import (  # noqa: E402
    Card, StatChip, ToggleSwitch, ToggleRow, FadeStack, StatusPill, StatusRing, Sparkline, ActionTile,
    ActivityFeed, ToastManager, ShieldLogo, SoundManager, make_app_icon, add_shadow,
)
from gui.splash import SplashScreen  # noqa: E402
from gui.antivirus import AntivirusPage, QuarantinePage  # noqa: E402


class Bridge(QObject):
    """Carries results from worker threads back to the GUI thread."""
    event = pyqtSignal(object)
    task_done = pyqtSignal(str, int, object)
    task_failed = pyqtSignal(str, int, str)
    progress = pyqtSignal(int, int, str)


class Backdrop(QWidget):
    """Soft blue gradient background with two blurred colour blobs."""
    def paintEvent(self, event):
        painter = QPainter(self)
        w, h = self.width(), self.height()
        base = QLinearGradient(0, 0, w * 0.4, h)
        base.setColorAt(0, QColor(theme.BG))
        base.setColorAt(1, QColor(theme.BG_DEEP))
        painter.fillRect(self.rect(), base)
        for cx, cy, radius, color, alpha in ((w * 0.92, -h * 0.1, w * 0.45, theme.ACCENT_2, 70),
                                             (-w * 0.05, h * 1.05, w * 0.40, theme.SUCCESS, 30)):
            blob = QRadialGradient(cx, cy, radius)
            c = QColor(color)
            c.setAlpha(alpha)
            blob.setColorAt(0, c)
            c.setAlpha(0)
            blob.setColorAt(1, c)
            painter.fillRect(self.rect(), blob)


class LogViewerWindow(QDialog):
    MAX_LINES = 5000

    def __init__(self, log_path, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"{APP_NAME} - Activity Log")
        self.resize(840, 580)
        self.log_path = log_path
        self.full_log = ""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(14)

        header = QHBoxLayout()
        titles = QVBoxLayout()
        titles.setSpacing(1)
        title = QLabel("Activity log")
        title.setObjectName("Headline")
        self.summary = QLabel()
        self.summary.setObjectName("Muted")
        titles.addWidget(title)
        titles.addWidget(self.summary)
        header.addLayout(titles, 1)
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("🔍  Filter lines")
        self.search_bar.setClearButtonEnabled(True)
        self.search_bar.setFixedWidth(240)
        self.search_bar.textChanged.connect(self.search_logs)
        header.addWidget(self.search_bar)
        layout.addLayout(header)

        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        layout.addWidget(self.log_text, 1)

        buttons = QHBoxLayout()
        buttons.addStretch()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.load_logs)
        folder = QPushButton("Open folder")
        folder.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(log_path))))
        save = QPushButton("Save a copy")
        save.setProperty("variant", "primary")
        save.clicked.connect(self.save_logs)
        for b in (refresh, folder, save):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            buttons.addWidget(b)
        layout.addLayout(buttons)
        self.load_logs()

    def load_logs(self):
        try:
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except OSError:
            lines = []
        total = len(lines)
        self.full_log = "\n".join(lines[-self.MAX_LINES:])
        if total > self.MAX_LINES:
            self.summary.setText(f"Showing the last {self.MAX_LINES:,} of {total:,} entries")
        else:
            self.summary.setText(f"{total:,} entries recorded" if total else "Nothing logged yet")
        self.search_logs(self.search_bar.text())

    def search_logs(self, text):
        if text:
            needle = text.lower()
            self.log_text.setPlainText("\n".join(l for l in self.full_log.splitlines() if needle in l.lower()))
        else:
            self.log_text.setPlainText(self.full_log)
        self.log_text.moveCursor(self.log_text.textCursor().MoveOperation.End)

    def save_logs(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Log Copy", "securevault_logs.txt", "Text Files (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.full_log)


class StreamDialog(QDialog):
    """Start/stop the live web stream and share its link."""
    def __init__(self, window):
        super().__init__(window)
        self.window_ = window
        self.stream = window.stream
        self.setWindowTitle(f"{APP_NAME} Live")
        self.setFixedWidth(500)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 24, 26, 24)
        layout.setSpacing(16)

        top = QHBoxLayout()
        top.setSpacing(14)
        badge = QLabel("📡")
        badge.setFixedSize(52, 52)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setStyleSheet(f"background: {theme.ACCENT_SOFT}; border-radius: 16px; font-size: 24px;")
        titles = QVBoxLayout()
        titles.setSpacing(2)
        title = QLabel("Live stream")
        title.setObjectName("Headline")
        sub = QLabel("Watch SecureVault in real time from any browser: status, alerts and system load.")
        sub.setObjectName("Muted")
        sub.setWordWrap(True)
        titles.addWidget(title)
        titles.addWidget(sub)
        top.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)
        top.addLayout(titles, 1)
        layout.addLayout(top)

        privacy_card = QFrame()
        privacy_card.setObjectName("Card")
        privacy_layout = QHBoxLayout(privacy_card)
        privacy_layout.setContentsMargins(16, 12, 16, 12)
        privacy_text = QVBoxLayout()
        privacy_text.setSpacing(1)
        privacy_title = QLabel("Hide folder paths (recommended)")
        privacy_title.setStyleSheet("font-weight: 600;")
        privacy_sub = QLabel("Viewers see file names only, never your folders or user name")
        privacy_sub.setObjectName("Muted")
        privacy_sub.setStyleSheet("font-size: 11px;")
        privacy_text.addWidget(privacy_title)
        privacy_text.addWidget(privacy_sub)
        self.privacy_switch = ToggleSwitch()
        self.privacy_switch.set_checked_silently(self.stream.private)
        self.privacy_switch.toggled.connect(self._privacy_changed)
        privacy_layout.addLayout(privacy_text, 1)
        privacy_layout.addWidget(self.privacy_switch)
        layout.addWidget(privacy_card)

        lan_card = QFrame()
        lan_card.setObjectName("Card")
        lan_layout = QHBoxLayout(lan_card)
        lan_layout.setContentsMargins(16, 12, 16, 12)
        lan_text = QVBoxLayout()
        lan_text.setSpacing(1)
        lan_title = QLabel("Allow devices on my network")
        lan_title.setStyleSheet("font-weight: 600;")
        lan_sub = QLabel("Your phone or another PC on the same Wi-Fi. Use on trusted networks only")
        lan_sub.setObjectName("Muted")
        lan_sub.setStyleSheet("font-size: 11px;")
        lan_sub.setWordWrap(True)
        lan_text.addWidget(lan_title)
        lan_text.addWidget(lan_sub)
        self.lan_switch = ToggleSwitch()
        self.lan_switch.set_checked_silently(self.stream.lan)
        self.lan_switch.toggled.connect(self._lan_changed)
        lan_layout.addLayout(lan_text, 1)
        lan_layout.addWidget(self.lan_switch)
        layout.addWidget(lan_card)

        net_card = QFrame()
        net_card.setObjectName("Card")
        net_layout = QHBoxLayout(net_card)
        net_layout.setContentsMargins(16, 12, 16, 12)
        net_text = QVBoxLayout()
        net_text.setSpacing(1)
        net_title = QLabel("Share over the internet")
        net_title.setStyleSheet("font-weight: 600;")
        available = self.stream.tunnel_available()
        net_sub = QLabel("Watch from anywhere through a secure Cloudflare tunnel (no account needed)" if available
                         else "Needs Cloudflare's free tool: winget install Cloudflare.cloudflared")
        net_sub.setObjectName("Muted")
        net_sub.setStyleSheet("font-size: 11px;")
        net_sub.setWordWrap(True)
        net_text.addWidget(net_title)
        net_text.addWidget(net_sub)
        self.net_switch = ToggleSwitch()
        self.net_switch.setEnabled(available)
        self.net_switch.set_checked_silently(bool(self.stream.public_base) or window.tunnel_starting)
        self.net_switch.toggled.connect(self._net_changed)
        net_layout.addLayout(net_text, 1)
        net_layout.addWidget(self.net_switch)
        layout.addWidget(net_card)

        self.url = QLineEdit()
        self.url.setReadOnly(True)
        self.url.setPlaceholderText("Start streaming to get a private link")
        url_row = QHBoxLayout()
        url_row.setSpacing(8)
        self.copy_btn = QPushButton("Copy")
        self.copy_btn.clicked.connect(self._copy)
        self.open_btn = QPushButton("Open")
        self.open_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(self._current_url())))
        url_row.addWidget(self.url, 1)
        url_row.addWidget(self.copy_btn)
        url_row.addWidget(self.open_btn)
        layout.addLayout(url_row)

        self.info = QLabel()
        self.info.setObjectName("Muted")
        self.info.setWordWrap(True)
        self.info.setStyleSheet("font-size: 12px;")
        layout.addWidget(self.info)

        self.toggle_btn = QPushButton()
        self.toggle_btn.setMinimumHeight(44)
        self.toggle_btn.clicked.connect(self._toggle)
        layout.addWidget(self.toggle_btn)
        for b in (self.copy_btn, self.open_btn, self.toggle_btn):
            b.setCursor(Qt.CursorShape.PointingHandCursor)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(1000)
        self.refresh()

    def _current_url(self):
        return self.stream.public_url or self.stream.url or ""

    def _start(self):
        self.window_.start_stream(self.lan_switch.isChecked())
        if self.net_switch.isChecked() and self.stream.running:
            self.window_.start_tunnel()

    def _toggle(self):
        if self.stream.running:
            self.window_.stop_stream()
            self.net_switch.set_checked_silently(False)
        else:
            self._start()
        self.refresh()

    def _confirm(self, title, text):
        return QMessageBox.question(self, title, text) == QMessageBox.StandardButton.Yes

    def _privacy_changed(self, checked):
        if not checked and not self._confirm(
                "Show folder paths?", "Viewers will see full file paths, which include your Windows user name "
                                      "and folder names.\n\nShow them anyway?"):
            self.privacy_switch.set_checked_silently(True)
            return
        self.stream.private = checked
        self.stream.seed(self.window_.events[-300:])  # re-share history with the new setting
        self.window_.push_stream_state()

    def _lan_changed(self, checked):
        if checked and not self._confirm(
                "Allow devices on your network?", "Anyone on this network who has the link will be able to watch.\n\n"
                                                  "Only do this on a network you trust, like your home Wi-Fi, "
                                                  "never on public Wi-Fi."):
            self.lan_switch.set_checked_silently(False)
            return
        if self.stream.running:  # The bind address changes, so restart with a new link
            self._start()
        self.refresh()

    def _net_changed(self, checked):
        if checked and not self._confirm(
                "Share over the internet?", "Anyone in the world who has the link will be able to watch "
                                            "until you stop streaming. The link also closes by itself after 2 hours.\n\n"
                                            "Only send it to people you trust. Share it now?"):
            self.net_switch.set_checked_silently(False)
            return
        if checked:
            if self.stream.running:
                self.window_.start_tunnel()
            else:
                self._start()
        else:
            self.window_.stop_tunnel()
        self.refresh()

    def _copy(self):
        QGuiApplication.clipboard().setText(self._current_url())
        self.copy_btn.setText("Copied ✓")
        QTimer.singleShot(1500, lambda: self.copy_btn.setText("Copy"))

    def refresh(self):
        running = self.stream.running
        if self.net_switch.isChecked() and not (self.stream.public_base or self.window_.tunnel_starting):
            self.net_switch.set_checked_silently(False)  # the tunnel failed or stopped
        if self.url.text() != self._current_url():
            self.url.setText(self._current_url())
            self.url.setCursorPosition(0)
        self.copy_btn.setEnabled(running)
        self.open_btn.setEnabled(running)
        self.toggle_btn.setText("Stop streaming" if running else "Start streaming")
        self.toggle_btn.setProperty("variant", "" if running else "primary")
        self.toggle_btn.style().unpolish(self.toggle_btn)
        self.toggle_btn.style().polish(self.toggle_btn)
        if running:
            n = self.stream.viewers
            if self.stream.public_base:
                expires = datetime.datetime.fromtimestamp(self.stream.public_expires_at).strftime("%H:%M") \
                    if self.stream.public_expires_at else "when you stop"
                where = f"anyone on the internet who has the link (closes at {expires})"
            elif self.window_.tunnel_starting:
                where = "this computer for now. Opening the internet tunnel…"
            else:
                where = "devices on your network" if self.stream.lan else "this computer only"
            self.info.setText(f"🔴  Live · {n} watching · visible to {where}\n"
                              "Anyone with the link can watch. Stopping the stream revokes it.")
        else:
            self.info.setText("The viewer is read-only. Each time you start streaming, a new private link is created.")


class SecureVaultGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} - Ransomware Detection & Prevention")
        self.setWindowIcon(make_app_icon())
        self.resize(1320, 850)
        self.setMinimumSize(1100, 720)

        self.folder_to_monitor = normalize_path(os.path.expanduser("~"))
        self.events = []
        self.counts = {INFO: 0, SUCCESS: 0, WARNING: 0, CRITICAL: 0}
        self.threat_active = False
        self.baseline_meta = None
        self._last_toast = 0.0
        self._last_beep = 0.0
        self._tray_hint_shown = False
        self._quitting = False
        self._entered = False
        self._tokens = itertools.count(1)
        self._running = {}       # task key -> token of the run currently owning it
        self._stop_events = {}   # task key -> threading.Event for long-running monitors
        self.stream = LiveStreamServer()
        self.tunnel_starting = False
        self.scanner = Scanner()
        self.on_access_enabled = True

        self.bridge = Bridge()
        self.bridge.event.connect(self.on_event)
        self.bridge.task_done.connect(self.on_task_done)
        self.bridge.task_failed.connect(self.on_task_failed)
        self.on_access = OnAccessScanner(self.scanner, self.sink)
        self.stream.on_notice = lambda message: emit(
            self.sink, WARNING if message.startswith("Blocked") else INFO, message, "stream")

        self.init_ui()
        self.bridge.progress.connect(self.av_page.on_progress)
        self.setup_tray_icon()
        self.toasts = ToastManager(self.centralWidget())

        self._stream_timer = QTimer(self)
        self._stream_timer.timeout.connect(self.refresh_stream_pill)
        self._stream_timer.start(2000)

        self.refresh_all()
        self.reload_baseline_meta()
        self.feed.add(emit(self._silent, INFO, f"{APP_NAME} v{APP_VERSION} is ready", log=False))

    # ------------------------------------------------------------------ UI

    def init_ui(self):
        root = Backdrop()
        page = QVBoxLayout(root)
        page.setContentsMargins(28, 22, 28, 24)
        page.setSpacing(20)
        page.addLayout(self.build_header())

        body = QHBoxLayout()
        body.setSpacing(20)
        left = QVBoxLayout()
        left.setSpacing(20)
        left.addWidget(self.build_hero())
        left.addWidget(self.build_protection())
        left.addStretch()
        left_widget = QWidget()
        left_widget.setLayout(left)
        left_widget.setFixedWidth(360)
        left.setContentsMargins(0, 0, 0, 0)

        right = QVBoxLayout()
        right.setSpacing(20)
        right.setContentsMargins(0, 0, 0, 0)
        right.addLayout(self.build_stats())
        right.addLayout(self.build_actions())
        right.addWidget(self.build_activity(), 1)

        body.addWidget(left_widget)
        body.addLayout(right, 1)
        protection_page = QWidget()
        protection_page.setLayout(body)
        body.setContentsMargins(0, 0, 0, 0)

        self.pages = FadeStack()
        self.pages.add(protection_page)
        self.av_page = AntivirusPage(self)
        self.pages.add(self.av_page)
        self.quarantine_page = QuarantinePage(self)
        self.pages.add(self.quarantine_page)
        page.addWidget(self.pages, 1)
        self.setCentralWidget(root)

    def build_header(self):
        header = QHBoxLayout()
        header.setSpacing(12)
        logo = ShieldLogo(40)
        titles = QVBoxLayout()
        titles.setSpacing(0)
        title = QLabel(APP_NAME)
        title.setObjectName("BrandTitle")
        subtitle = QLabel("Ransomware detection & prevention")
        subtitle.setObjectName("BrandSubtitle")
        titles.addWidget(title)
        titles.addWidget(subtitle)
        header.addWidget(logo)
        header.addLayout(titles)
        header.addStretch()

        nav = QFrame()
        nav.setObjectName("Segment")
        nav_layout = QHBoxLayout(nav)
        nav_layout.setContentsMargins(4, 4, 4, 4)
        nav_layout.setSpacing(2)
        self.nav_group = QButtonGroup(self)
        self.nav_buttons = []
        for i, label in enumerate(("🛡  Protection", "🔍  Antivirus", "🔒  Quarantine")):
            b = QPushButton(label)
            b.setProperty("variant", "chip")
            b.setCheckable(True)
            b.setChecked(i == 0)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setStyleSheet("padding: 7px 16px;")
            self.nav_group.addButton(b, i)
            self.nav_buttons.append(b)
            nav_layout.addWidget(b)
        self.nav_group.idClicked.connect(self.show_page)
        header.addWidget(nav)
        header.addStretch()

        self.live_pill = StatusPill()
        self.live_pill.clicked.connect(self.open_stream_dialog)
        header.addWidget(self.live_pill)

        self.sound_btn = QPushButton()
        self.sound_btn.setProperty("variant", "ghost")
        self.sound_btn.setFixedSize(38, 38)
        self.sound_btn.setStyleSheet("padding: 0; border-radius: 19px; font-size: 16px;")
        self.sound_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.sound_btn.clicked.connect(self.toggle_sound)
        self._update_sound_btn()
        header.addWidget(self.sound_btn)

        self.status_pill = StatusPill()
        self.status_pill.clicked.connect(self.acknowledge_threat)
        header.addWidget(self.status_pill)
        return header

    def build_hero(self):
        card = Card(padding=(22, 26, 22, 22))
        card.body.setSpacing(6)
        self.ring = StatusRing()
        self.ring.setCursor(Qt.CursorShape.PointingHandCursor)
        self.ring.mousePressEvent = lambda e: self.acknowledge_threat()
        card.body.addWidget(self.ring, 0, Qt.AlignmentFlag.AlignHCenter)
        card.body.addSpacing(8)
        self.headline = QLabel()
        self.headline.setObjectName("Headline")
        self.headline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.subline = QLabel()
        self.subline.setObjectName("Muted")
        self.subline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.subline.setWordWrap(True)
        card.body.addWidget(self.headline)
        card.body.addWidget(self.subline)
        card.body.addSpacing(10)

        self.folder_btn = QPushButton()
        self.folder_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.folder_btn.setStyleSheet(f"""
            QPushButton {{ background: {theme.SURFACE_2}; border: 1px solid {theme.BORDER};
                           border-radius: 12px; padding: 9px 14px; font-weight: 600; }}
            QPushButton:hover {{ border-color: {theme.ACCENT_2}; background: {theme.ACCENT_SOFT}; }}
            QPushButton::menu-indicator {{ width: 0; }}
        """)
        menu = QMenu(self)
        menu.addAction("Change protected folder…", self.change_folder)
        menu.addAction("Open in file explorer", lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(self.folder_to_monitor)))
        self.folder_btn.setMenu(menu)
        card.body.addWidget(self.folder_btn, 0, Qt.AlignmentFlag.AlignHCenter)
        self._update_folder_btn()
        self.hero = card
        return card

    def build_protection(self):
        card = Card("Live protection", "Choose what SecureVault watches")
        self.file_row = ToggleRow("👁", "Real-time file monitor")
        self.cpu_row = ToggleRow("⚙", "Process monitor")
        self.file_row.switch.toggled.connect(self.set_file_monitor)
        self.cpu_row.switch.toggled.connect(self.set_cpu_monitor)
        card.body.addWidget(self.file_row)
        card.body.addWidget(self.cpu_row)
        self.protection_card = card
        return card

    def build_stats(self):
        row = QHBoxLayout()
        row.setSpacing(16)
        self.stat_baseline = StatChip("🗂", "Baseline")
        self.stat_honeypot = StatChip("🧲", "Honeypot")
        self.stat_alerts = StatChip("🔔", "Alerts")
        self.stat_cpu = StatChip("⚡", "CPU")
        self.sparkline = Sparkline()
        self.sparkline.setFixedWidth(84)
        self.stat_cpu.extra.addWidget(self.sparkline, 0, Qt.AlignmentFlag.AlignBottom)
        self.stat_cpu.set("0%", "RAM -")
        self.stats = (self.stat_baseline, self.stat_honeypot, self.stat_alerts, self.stat_cpu)
        for chip in self.stats:
            row.addWidget(chip)
        self._cpu_timer = QTimer(self)
        self._cpu_timer.timeout.connect(self.sample_load)
        self._cpu_timer.start(1000)
        return row

    def build_actions(self):
        row = QHBoxLayout()
        row.setSpacing(14)
        self.buttons = {
            "baseline": ActionTile("🛡", "Create baseline", "Record a known-good state", primary=True),
            "scan": ActionTile("🔍", "Integrity scan", "Compare files to the baseline"),
            "honeypot": ActionTile("🧲", "Deploy honeypot", "Plant a decoy file"),
            "logs": ActionTile("📄", "Activity log", "Everything ever recorded"),
        }
        self.buttons["baseline"].clicked.connect(self.create_baseline)
        self.buttons["scan"].clicked.connect(self.check_changes)
        self.buttons["honeypot"].clicked.connect(self.create_honeypot)
        self.buttons["logs"].clicked.connect(self.view_logs)
        for btn in self.buttons.values():
            row.addWidget(btn)
        return row

    def build_activity(self):
        card = Card("Activity", "Live feed of what SecureVault sees")
        segment = QFrame()
        segment.setObjectName("Segment")
        seg_layout = QHBoxLayout(segment)
        seg_layout.setContentsMargins(3, 3, 3, 3)
        seg_layout.setSpacing(2)
        self.filter_group = QButtonGroup(self)
        for i, label in enumerate(("All", "Alerts", "Info")):
            b = QPushButton(label)
            b.setProperty("variant", "chip")
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setChecked(i == 0)
            self.filter_group.addButton(b, i)
            seg_layout.addWidget(b)
        self.filter_group.idClicked.connect(self.apply_filter)

        self.search = QLineEdit()
        self.search.setPlaceholderText("🔍  Search")
        self.search.setClearButtonEnabled(True)
        self.search.setFixedWidth(190)
        self.search.textChanged.connect(lambda: self.apply_filter())

        more = QPushButton("⋯")
        more.setProperty("variant", "ghost")
        more.setFixedSize(36, 34)
        more.setStyleSheet("padding: 0; font-size: 18px; font-weight: 800;")
        more.setCursor(Qt.CursorShape.PointingHandCursor)
        more_menu = QMenu(self)
        more_menu.addAction("Export evidence report…", self.export_report)
        more_menu.addAction("Clear feed", lambda: self.feed.clear())
        more.clicked.connect(lambda: more_menu.exec(more.mapToGlobal(QPoint(more.width() - more_menu.sizeHint().width(), more.height() + 4))))

        card.header.addWidget(segment)
        card.header.addWidget(self.search)
        card.header.addWidget(more)

        self.feed = ActivityFeed(self._short)
        self.feed.event_activated.connect(self.open_event_path)
        card.body.addWidget(self.feed, 1)
        self.activity_card = card
        return card

    def setup_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(make_app_icon(), self)
        self.tray_icon.setToolTip(APP_NAME)
        menu = QMenu(self)
        show_action = QAction(f"Open {APP_NAME}", self)
        show_action.triggered.connect(self.restore_window)
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.quit_app)
        menu.addAction(show_action)
        menu.addSeparator()
        menu.addAction(quit_action)
        self.tray_icon.setContextMenu(menu)
        self.tray_icon.activated.connect(self._on_tray_activated)
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray_icon.show()

    # ----------------------------------------------------------- entrance

    def showEvent(self, event):
        super().showEvent(event)
        if not self._entered:
            self._entered = True
            QTimer.singleShot(0, self.play_entrance)

    def play_entrance(self):
        """Cards fade in and float up one after another."""
        widgets = [self.hero, self.protection_card, *self.stats, *self.buttons.values(), self.activity_card]
        self._entrance = QParallelAnimationGroup(self)
        for i, w in enumerate(widgets):
            had_shadow = w.graphicsEffect() is not None
            effect = QGraphicsOpacityEffect(w)
            effect.setOpacity(0.0)
            w.setGraphicsEffect(effect)
            fade = QPropertyAnimation(effect, b"opacity")
            fade.setDuration(650)
            fade.setStartValue(0.0)
            fade.setEndValue(1.0)
            fade.setEasingCurve(QEasingCurve.Type.OutCubic)
            end = w.pos()
            slide = QPropertyAnimation(w, b"pos")
            slide.setDuration(650)
            slide.setStartValue(end + QPoint(0, 22))
            slide.setEndValue(end)
            slide.setEasingCurve(QEasingCurve.Type.OutCubic)
            both = QParallelAnimationGroup()
            both.addAnimation(fade)
            both.addAnimation(slide)
            seq = QSequentialAnimationGroup()
            seq.addPause(i * 55)
            seq.addAnimation(both)
            seq.finished.connect(lambda w=w, s=had_shadow: self._finish_entrance(w, s))
            self._entrance.addAnimation(seq)
        self._entrance.start()

    def _finish_entrance(self, widget, shadow):
        if shadow:
            add_shadow(widget, 28 if isinstance(widget, StatChip) else 36, 8 if isinstance(widget, StatChip) else 10)
        else:
            widget.setGraphicsEffect(None)

    # ------------------------------------------------------------ workers

    @staticmethod
    def _silent(event):
        return event

    def sink(self, event):
        """Backend event sink; safe to call from any thread."""
        try:
            self.bridge.event.emit(event)
        except RuntimeError:  # the window is already gone (app quitting)
            pass

    def run_task(self, key, fn, *args, **kwargs):
        token = next(self._tokens)
        self._running[key] = token

        def target():
            try:
                result = fn(*args, **kwargs)
            except Exception as e:  # Surface unexpected backend failures instead of dying silently
                signal, payload = self.bridge.task_failed, str(e)
            else:
                signal, payload = self.bridge.task_done, result
            try:
                signal.emit(key, token, payload)
            except RuntimeError:  # the window is already gone (app quitting)
                pass

        threading.Thread(target=target, name=f"securevault-{key}", daemon=True).start()
        return token

    def on_task_done(self, key, token, result):
        if self._running.get(key) != token:
            return  # A newer run of this task has already taken over
        del self._running[key]
        if key == "baseline":
            self.buttons["baseline"].set_busy(False)
            if result:
                self.baseline_meta = self._meta_from(result)
                self.refresh_baseline()
        elif key == "scan":
            self.buttons["scan"].set_busy(False)
            if result is not None:
                issues = len(result["modified"]) + len(result["deleted"])
                self.buttons["scan"].set_description(
                    f"Last run {datetime.datetime.now():%H:%M} · " + (f"{issues} change(s)" if issues else "all clear"))
        elif key == "honeypot":
            self.buttons["honeypot"].set_busy(False)
            self.refresh_honeypot()
        elif key == "tunnel":
            self.tunnel_starting = False
            if result:
                self.on_event(emit(self._silent, SUCCESS, "Public live link is ready (Cloudflare tunnel)"))
            self.refresh_stream_pill()
        elif key == "av_scan":
            self.av_page.on_scan_done(result)
        elif key == "load_baseline":
            self.baseline_meta = result
            self.refresh_baseline()
        elif key in ("file_monitor", "cpu_monitor"):
            # The monitor ended (stopped by the user, or failed to start)
            self._stop_events.pop(key, None)
            row = self.file_row if key == "file_monitor" else self.cpu_row
            row.switch.set_checked_silently(False)
            self.refresh_protection()

    def on_task_failed(self, key, token, error):
        self.on_task_done(key, token, None)
        self.on_event(emit(self._silent, WARNING, f"{key.replace('_', ' ').capitalize()} failed: {error}"))

    # ------------------------------------------------------------- events

    def on_event(self, event):
        self.events.append(event)
        self.counts[event.level] = self.counts.get(event.level, 0) + 1
        self.feed.add(event)
        if self.stream.running:
            self.stream.publish(event)
        if event.category == "scanner" and event.data:
            self.av_page.add_finding(event.data)

        now = time.time()
        per_file_scan = event.category in ("scan", "scanner") and event.path
        if event.level == CRITICAL:
            self.threat_active = True
            if not (per_file_scan and now - self._last_toast < 1.5):  # one toast per burst of findings
                self.toasts.show("Threat detected", self._short(event), CRITICAL)
                self._last_toast = now
            SoundManager.play_alert()
            QApplication.alert(self)
            if not self.isVisible() and self.tray_icon.isVisible():
                self.tray_icon.showMessage(f"{APP_NAME}: threat detected", event.message,
                                           QSystemTrayIcon.MessageIcon.Critical, 8000)
        elif event.level in (WARNING, SUCCESS):
            # Individual scan findings go to the feed only; the scan summary gets the toast
            if not per_file_scan and now - self._last_toast > 1.2:
                self.toasts.show({"warning": "Heads up", "success": "Done"}[event.level], self._short(event), event.level)
                self._last_toast = now
            if event.level == WARNING and not per_file_scan and now - self._last_beep > 3:
                SoundManager.play_warning()
                self._last_beep = now

        if event.category == "honeypot":
            self.refresh_honeypot()
        self.refresh_alerts()
        self.refresh_protection()

    def _short(self, event):
        """Compact message: full paths are reduced to file names."""
        message = event.message
        if event.path:
            for part in event.path.split(" -> "):
                message = message.replace(part, os.path.basename(part) or part)
        message = message.replace(self.folder_to_monitor + os.sep, "")
        return message if len(message) <= 160 else message[:157] + "..."

    def apply_filter(self, *_):
        levels = {0: None, 1: {WARNING, CRITICAL}, 2: {INFO, SUCCESS}}[self.filter_group.checkedId()]
        self.feed.set_filter(levels or set(), self.search.text())

    def open_event_path(self, event):
        if not (event and event.path):
            return
        target = event.path if os.path.isdir(event.path) else os.path.dirname(event.path)
        if os.path.isdir(target):
            QDesktopServices.openUrl(QUrl.fromLocalFile(target))

    def sample_load(self):
        import psutil
        cpu = psutil.cpu_percent(None)
        mem = psutil.virtual_memory().percent
        color = theme.CRITICAL if cpu >= 85 else theme.WARNING if cpu >= 60 else theme.ACCENT
        self.stat_cpu.set(f"{cpu:.0f}%", f"RAM {mem:.0f}%", color)
        self.sparkline.add(cpu, color)

    # ------------------------------------------------------------- status

    def refresh_all(self):
        self.refresh_protection()
        self.refresh_honeypot()
        self.refresh_alerts()
        self.refresh_baseline()
        self.refresh_stream_pill()

    def _status(self):
        if self.threat_active:
            return "threat"
        return "protected" if "file_monitor" in self._stop_events else "idle"

    def refresh_protection(self):
        file_on = "file_monitor" in self._stop_events
        cpu_on = "cpu_monitor" in self._stop_events
        name = os.path.basename(self.folder_to_monitor) or self.folder_to_monitor
        self.file_row.state.setText(f"Watching {name}" if file_on else "Off")
        self.cpu_row.state.setText("Watching for sustained high CPU" if cpu_on else "Off")

        status = self._status()
        self.ring.set_state(status)
        if status == "threat":
            self.headline.setText("Threat detected")
            self.subline.setText("Review the activity feed, then click the shield to acknowledge")
            self.status_pill.set_state("Threat", theme.CRITICAL, pulse=True, tooltip="Click to acknowledge")
        elif status == "protected":
            self.headline.setText("You're protected")
            self.subline.setText(f"Watching {name} in real time")
            self.status_pill.set_state("Protected", theme.SUCCESS, pulse=True, tooltip="Real-time protection is on")
        else:
            self.headline.setText("Protection is off")
            self.subline.setText("Turn on the real-time monitor to stay protected")
            self.status_pill.set_state("Unprotected", theme.WARNING, tooltip="Real-time file monitoring is off")
        self.push_stream_state()

    def acknowledge_threat(self):
        if self.threat_active:
            self.threat_active = False
            self.on_event(emit(self._silent, INFO, "Threat alert acknowledged"))

    def refresh_alerts(self):
        crit, warn = self.counts.get(CRITICAL, 0), self.counts.get(WARNING, 0)
        color = theme.CRITICAL if crit else theme.WARNING if warn else theme.SUCCESS
        caption = f"{crit} critical · {warn} warnings" if crit or warn else "Nothing suspicious"
        self.stat_alerts.set(crit + warn, caption, color)

    def refresh_honeypot(self):
        if os.path.exists(honeypot_path(self.folder_to_monitor)):
            self.stat_honeypot.set("Deployed", "Decoy is in place", theme.SUCCESS)
        else:
            self.stat_honeypot.set("Off", "Deploy a decoy file", theme.SUBTLE)
        self.push_stream_state()

    @staticmethod
    def _meta_from(baseline):
        if not baseline:
            return None
        return {"count": len(baseline["files"]), "created": baseline.get("created"), "folder": baseline.get("folder")}

    def reload_baseline_meta(self):
        self.run_task("load_baseline", lambda: self._meta_from(load_baseline()))

    def refresh_baseline(self):
        meta = self.baseline_meta
        if not meta:
            self.stat_baseline.set("None", "Create one to enable scans", theme.WARNING)
        else:
            created = meta.get("created")
            when = created.replace("T", " ")[5:16] if created else "unknown date"
            folder = meta.get("folder")
            if folder and os.path.normcase(folder) != os.path.normcase(self.folder_to_monitor):
                self.stat_baseline.set(meta["count"], "Made for another folder", theme.WARNING, fmt="{:,} files")
            else:
                self.stat_baseline.set(meta["count"], f"Created {when}", theme.ACCENT, fmt="{:,} files")
        self.push_stream_state()

    # -------------------------------------------------------- live stream

    def open_stream_dialog(self):
        StreamDialog(self).exec()
        self.refresh_stream_pill()

    def start_stream(self, lan=False):
        try:
            self.stream.seed(self.events[-300:])
            url = self.stream.start(lan)
        except OSError as e:
            self.on_event(emit(self._silent, WARNING, f"Live stream could not start: {e}"))
            return
        self.push_stream_state()
        self.refresh_stream_pill()
        self.on_event(emit(self._silent, SUCCESS, f"Live stream started ({'local network' if lan else 'this computer'})"))
        return url

    def stop_stream(self):
        self._running.pop("tunnel", None)
        self.tunnel_starting = False
        self.stream.stop()
        self.refresh_stream_pill()
        self.on_event(emit(self._silent, INFO, "Live stream stopped"))

    def start_tunnel(self):
        if self.tunnel_starting or not self.stream.running:
            return
        self.tunnel_starting = True
        self.run_task("tunnel", self.stream.start_public)

    def stop_tunnel(self):
        if self.stream.public_base:
            self.stream.stop_public()
            self.on_event(emit(self._silent, INFO, "Public live link closed"))
        self._running.pop("tunnel", None)
        self.tunnel_starting = False
        self.refresh_stream_pill()

    def refresh_stream_pill(self):
        if self.stream.running:
            n = self.stream.viewers
            scope = "public · " if self.stream.public_base else ""
            self.live_pill.set_state(f"Live · {scope}{n} watching", theme.ACCENT_DEEP, pulse=True,
                                     tooltip="Streaming to the web. Click to manage.")
        else:
            self.live_pill.set_state("Go live", theme.MUTED, tooltip="Stream SecureVault to a browser")

    def push_stream_state(self):
        if not getattr(self, "stream", None) or not self.stream.running:
            return
        meta = self.baseline_meta
        crit, warn = self.counts.get(CRITICAL, 0), self.counts.get(WARNING, 0)
        self.stream.update_state(
            status=self._status(),
            headline=self.headline.text(),
            subline=self.subline.text(),
            folder=os.path.basename(self.folder_to_monitor) or self.folder_to_monitor,
            file_monitor="file_monitor" in self._stop_events,
            cpu_monitor="cpu_monitor" in self._stop_events,
            alerts=crit + warn, critical=crit, warnings=warn,
            baseline=f"{meta['count']:,} files" if meta else "None",
            baseline_sub=self.stat_baseline.caption.text(),
            honeypot=self.stat_honeypot.value.text(),
            honeypot_sub=self.stat_honeypot.caption.text(),
        )

    # ------------------------------------------------------------ actions

    def _update_folder_btn(self):
        name = os.path.basename(self.folder_to_monitor) or self.folder_to_monitor
        self.folder_btn.setText(f"📁   {name}   ▾")
        self.folder_btn.setToolTip(self.folder_to_monitor)

    def change_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Protect", self.folder_to_monitor)
        if not folder:
            return
        folder = normalize_path(folder)
        if folder == self.folder_to_monitor:
            return
        self.folder_to_monitor = folder
        self._update_folder_btn()
        restart = "file_monitor" in self._stop_events
        self.on_event(emit(self._silent, INFO, f"Protected folder changed to {folder}"))
        if restart:
            self.set_file_monitor(False)
            self.file_row.switch.set_checked_silently(True)
            self.set_file_monitor(True)
        self.refresh_honeypot()
        self.refresh_baseline()

    def create_baseline(self):
        self.buttons["baseline"].set_busy(True, "Indexing files…")
        self.run_task("baseline", create_baseline, self.folder_to_monitor, self.sink)

    def check_changes(self):
        self.buttons["scan"].set_busy(True, "Scanning…")
        self.run_task("scan", check_for_changes, self.folder_to_monitor, self.sink)

    def create_honeypot(self):
        self.buttons["honeypot"].set_busy(True, "Deploying…")
        self.run_task("honeypot", create_honeypot, self.folder_to_monitor, self.sink)

    def set_file_monitor(self, enabled):
        self._set_monitor("file_monitor", enabled, start_real_time_monitor,
                          lambda stop: ((self.folder_to_monitor, self.sink, stop), {"on_file": self._on_access}))

    def _on_access(self, path):
        """Called on the monitor thread for new or changed files."""
        if self.on_access_enabled:
            self.on_access.submit(path)

    def show_page(self, index):
        self.nav_buttons[index].setChecked(True)
        self.pages.show_page(index)
        if index == 2:
            self.quarantine_page.refresh()

    def update_nav_badges(self, quarantined=None):
        if not hasattr(self, "nav_buttons"):
            return
        threats = len(self.av_page.rows) if hasattr(self, "av_page") else 0
        self.nav_buttons[1].setText(f"🔍  Antivirus · {threats}" if threats else "🔍  Antivirus")
        if quarantined is not None:
            self.nav_buttons[2].setText(f"🔒  Quarantine · {quarantined}" if quarantined else "🔒  Quarantine")

    def set_cpu_monitor(self, enabled):
        self._set_monitor("cpu_monitor", enabled, monitor_processes_sustained,
                          lambda stop: ((), {"alert_queue": self.sink, "stop_event": stop}))

    def _set_monitor(self, key, enabled, fn, args_for):
        if enabled:
            if key in self._stop_events:
                return
            stop = threading.Event()
            self._stop_events[key] = stop
            args, kwargs = args_for(stop)
            self.run_task(key, fn, *args, **kwargs)
        else:
            stop = self._stop_events.pop(key, None)
            if stop:
                stop.set()
            # Detach the old run so its late "finished" signal can't flip a restarted switch
            self._running.pop(key, None)
        self.refresh_protection()

    def view_logs(self):
        self.log_window = LogViewerWindow(LOG_FILE, self)
        self.log_window.show()

    def toggle_sound(self):
        SoundManager.enabled = not SoundManager.enabled
        self._update_sound_btn()

    def _update_sound_btn(self):
        self.sound_btn.setText("🔔" if SoundManager.enabled else "🔕")
        self.sound_btn.setToolTip("Sound alerts on" if SoundManager.enabled else "Sound alerts off")

    def export_report(self):
        stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        default = os.path.join(os.path.expanduser("~"), "Documents", f"SecureVault_Report_{stamp}.html")
        if not os.path.isdir(os.path.dirname(default)):
            default = os.path.join(APP_DIR, os.path.basename(default))
        path, _ = QFileDialog.getSaveFileName(self, "Export Evidence Report", default, "HTML Report (*.html)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.build_report_html())
        except OSError as e:
            self.on_event(emit(self._silent, WARNING, f"Report export failed: {e}"))
            return
        self.on_event(emit(self._silent, SUCCESS, f"Evidence report saved: {path}", path=path))
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def build_report_html(self):
        rows = []
        for ev in reversed(self.events):
            color = theme.LEVEL_COLORS.get(ev.level, theme.INFO)
            rows.append(
                f"<tr><td class='t'>{html.escape(ev.time_str)}</td>"
                f"<td><span class='badge' style='color:{color};background:{theme.soft(color, 0.12)}'>"
                f"{html.escape(theme.LEVEL_LABELS.get(ev.level, ev.level))}</span></td>"
                f"<td>{html.escape(ev.category)}</td><td class='m'>{html.escape(ev.message)}</td></tr>"
            )
        crit, warn = self.counts.get(CRITICAL, 0), self.counts.get(WARNING, 0)
        generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{APP_NAME} Evidence Report</title>
<style>
body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: {theme.BG}; color: {theme.TEXT}; margin: 0; padding: 36px; }}
h1 {{ margin: 0 0 4px; font-size: 26px; }}
.sub {{ color: {theme.MUTED}; margin-bottom: 26px; }}
.cards {{ display: flex; gap: 16px; margin-bottom: 26px; flex-wrap: wrap; }}
.card {{ background: #fff; border: 1px solid {theme.BORDER}; border-radius: 16px; padding: 16px 20px; min-width: 170px;
         box-shadow: 0 10px 28px rgba(76,141,246,.10); }}
.card b {{ display: block; font-size: 24px; }}
.card span {{ color: {theme.MUTED}; font-size: 12px; font-weight: 600; }}
table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 16px; overflow: hidden;
         box-shadow: 0 10px 28px rgba(76,141,246,.10); }}
th {{ text-align: left; color: {theme.MUTED}; font-size: 12px; padding: 12px 14px; border-bottom: 1px solid {theme.BORDER}; }}
td {{ padding: 10px 14px; border-bottom: 1px solid {theme.SURFACE_3}; font-size: 13px; vertical-align: top; }}
td.t {{ color: {theme.MUTED}; white-space: nowrap; }}
td.m {{ word-break: break-all; }}
.badge {{ border-radius: 999px; padding: 3px 10px; font-size: 11px; font-weight: 700; }}
</style></head><body>
<h1>{APP_NAME} Evidence Report</h1>
<div class="sub">Generated {generated} · Protected folder: {html.escape(self.folder_to_monitor)}</div>
<div class="cards">
<div class="card"><span>Events</span><b>{len(self.events)}</b></div>
<div class="card"><span>Critical</span><b style="color:{theme.CRITICAL}">{crit}</b></div>
<div class="card"><span>Warnings</span><b style="color:{theme.WARNING}">{warn}</b></div>
</div>
<table><thead><tr><th>Time</th><th>Level</th><th>Source</th><th>Event</th></tr></thead>
<tbody>{''.join(rows) or "<tr><td colspan='4'>No events recorded this session.</td></tr>"}</tbody></table>
</body></html>"""

    # -------------------------------------------------------------- window

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "toasts"):
            self.toasts.reposition()

    def _on_tray_activated(self, reason):
        if reason in (QSystemTrayIcon.ActivationReason.DoubleClick, QSystemTrayIcon.ActivationReason.Trigger):
            self.restore_window()

    def restore_window(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, event):
        """Keep protecting from the tray while a monitor or the stream is running."""
        busy = self._stop_events or self.stream.running or self.av_page.scanning
        if not self._quitting and busy and self.tray_icon.isVisible():
            self.hide()
            if not self._tray_hint_shown:
                self._tray_hint_shown = True
                self.tray_icon.showMessage(APP_NAME, "Still protecting in the background. "
                                           "Right-click the tray icon to quit.",
                                           QSystemTrayIcon.MessageIcon.Information, 3000)
            event.ignore()
            return
        self.quit_app()
        event.accept()

    def quit_app(self):
        self._quitting = True
        for stop in self._stop_events.values():
            stop.set()
        self._stop_events.clear()
        if self.av_page.stop_event:
            self.av_page.stop_event.set()
        self.on_access.stop()
        self.stream.stop()
        self.tray_icon.hide()
        QApplication.instance().quit()


def apply_light_palette(app):
    """Force a light palette so native widgets match the theme in OS dark mode."""
    palette = QPalette()
    roles = {
        QPalette.ColorRole.Window: theme.BG,
        QPalette.ColorRole.WindowText: theme.TEXT,
        QPalette.ColorRole.Base: theme.SURFACE,
        QPalette.ColorRole.AlternateBase: theme.SURFACE_2,
        QPalette.ColorRole.Text: theme.TEXT,
        QPalette.ColorRole.Button: theme.SURFACE,
        QPalette.ColorRole.ButtonText: theme.TEXT,
        QPalette.ColorRole.Highlight: theme.ACCENT,
        QPalette.ColorRole.HighlightedText: "#ffffff",
        QPalette.ColorRole.ToolTipBase: theme.TEXT,
        QPalette.ColorRole.ToolTipText: "#ffffff",
        QPalette.ColorRole.PlaceholderText: theme.SUBTLE,
    }
    for role, color in roles.items():
        palette.setColor(role, QColor(color))
    app.setPalette(palette)


def run_gui(show_splash=True):
    if sys.platform == "win32":
        try:  # Use our own taskbar icon instead of Python's
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SecureVault.Dashboard")
        except Exception:
            pass

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setStyle("Fusion")
    apply_light_palette(app)
    app.setStyleSheet(theme.STYLESHEET)
    app.setWindowIcon(make_app_icon())
    app.setQuitOnLastWindowClosed(False)

    window = SecureVaultGUI()
    if show_splash:
        splash = SplashScreen()
        splash.finished.connect(window.show)
        splash.start()
        app._splash = splash  # keep a reference until it finishes
    else:
        window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    import signal
    signal.signal(signal.SIGINT, signal.SIG_DFL)  # Allow Ctrl+C to kill the app
    run_gui()
