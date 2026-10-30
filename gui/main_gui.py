# gui/main_gui.py
"""SecureVault desktop dashboard (PyQt6)."""
import os
import sys
import html
import time
import datetime
import threading
import itertools

from PyQt6.QtCore import Qt, QObject, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import QAction, QDesktopServices, QFontMetrics, QColor, QFont
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QPushButton, QVBoxLayout,
    QHBoxLayout, QGridLayout, QLineEdit, QComboBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView, QFileDialog, QDialog,
    QPlainTextEdit, QSystemTrayIcon, QMenu, QStatusBar, QSizePolicy,
)

# Allow running this file directly as well as via main.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import (  # noqa: E402
    APP_NAME, APP_VERSION, APP_DIR, LOG_FILE, HASH_DB_FILE,
    create_baseline, check_for_changes, create_honeypot, honeypot_path,
    start_real_time_monitor, monitor_processes_sustained, load_baseline,
    normalize_path, emit, INFO, SUCCESS, WARNING, CRITICAL,
)
from gui import theme  # noqa: E402
from gui.widgets import (  # noqa: E402
    Card, StatCard, ToggleSwitch, StatusPill, SystemLoadGraph, ToastManager,
    ShieldLogo, SoundManager, make_app_icon,
)
from gui.splash import SplashScreen  # noqa: E402

MAX_FEED_ROWS = 2000


class Bridge(QObject):
    """Carries results from worker threads back to the GUI thread."""
    event = pyqtSignal(object)
    task_done = pyqtSignal(str, int, object)
    task_failed = pyqtSignal(str, int, str)


class ElidedLabel(QLabel):
    """A label that shortens long text with an ellipsis in the middle."""
    def __init__(self, text="", parent=None):
        super().__init__(parent)
        self._full = text
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.setText(text)

    def setText(self, text):
        self._full = text
        self.setToolTip(text)
        self._refresh()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._refresh()

    def _refresh(self):
        elided = QFontMetrics(self.font()).elidedText(self._full, Qt.TextElideMode.ElideMiddle, max(40, self.width()))
        super().setText(elided)


class ActionTile(QPushButton):
    """Large button with an icon badge, title and description."""
    def __init__(self, glyph, title, description, primary=False, parent=None):
        super().__init__(parent)
        self.setProperty("variant", "primary" if primary else "action")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(62)
        self._title_text = title
        self._desc_text = description
        self._primary = primary

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(12)
        self.glyph = QLabel(glyph)
        self.glyph.setFixedSize(34, 34)
        self.glyph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge_bg = "rgba(4, 19, 31, 0.18)" if primary else theme.SURFACE_3
        self.glyph.setStyleSheet(f"background: {badge_bg}; border-radius: 8px; font-size: 16px;")
        text = QVBoxLayout()
        text.setSpacing(1)
        fg = "#04131f" if primary else theme.TEXT
        sub = "rgba(4, 19, 31, 0.7)" if primary else theme.MUTED
        self.title = QLabel(title)
        self.title.setStyleSheet(f"color: {fg}; font-weight: 700; font-size: 13px;")
        self.desc = QLabel(description)
        self.desc.setStyleSheet(f"color: {sub}; font-size: 11px; font-weight: 400;")
        text.addWidget(self.title)
        text.addWidget(self.desc)
        layout.addWidget(self.glyph)
        layout.addLayout(text, 1)
        for w in (self.glyph, self.title, self.desc):
            w.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    def set_busy(self, busy, text="Working..."):
        self.setEnabled(not busy)
        self.setCursor(Qt.CursorShape.BusyCursor if busy else Qt.CursorShape.PointingHandCursor)
        self.title.setText(text if busy else self._title_text)


class ToggleRow(QWidget):
    def __init__(self, title, description, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(12)
        text = QVBoxLayout()
        text.setSpacing(2)
        t = QLabel(title)
        t.setStyleSheet("font-weight: 600;")
        self.state = QLabel(description)
        self.state.setObjectName("Muted")
        self.state.setStyleSheet("font-size: 11px;")
        self.state.setWordWrap(True)
        text.addWidget(t)
        text.addWidget(self.state)
        self.switch = ToggleSwitch()
        layout.addLayout(text, 1)
        layout.addWidget(self.switch, 0, Qt.AlignmentFlag.AlignVCenter)


class LogViewerWindow(QDialog):
    MAX_LINES = 5000

    def __init__(self, log_path, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"{APP_NAME} - Activity Log")
        self.resize(820, 560)
        self.log_path = log_path
        self.full_log = ""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        header = QHBoxLayout()
        title = QLabel("Activity log")
        title.setObjectName("CardTitle")
        path = ElidedLabel(log_path)
        path.setObjectName("Muted")
        header.addWidget(title)
        header.addSpacing(10)
        header.addWidget(path, 1)
        layout.addLayout(header)

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Filter lines...")
        self.search_bar.setClearButtonEnabled(True)
        self.search_bar.textChanged.connect(self.search_logs)
        layout.addWidget(self.search_bar)

        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self.log_text, 1)

        buttons = QHBoxLayout()
        self.summary = QLabel()
        self.summary.setObjectName("Muted")
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.load_logs)
        folder = QPushButton("Open folder")
        folder.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(log_path))))
        save = QPushButton("Save copy...")
        save.setProperty("variant", "primary")
        save.clicked.connect(self.save_logs)
        buttons.addWidget(self.summary, 1)
        buttons.addWidget(refresh)
        buttons.addWidget(folder)
        buttons.addWidget(save)
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
            self.summary.setText(f"Showing last {self.MAX_LINES:,} of {total:,} entries")
        else:
            self.summary.setText(f"{total:,} entries" if total else "No activity logged yet")
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


class SecureVaultGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} - Ransomware Detection & Prevention")
        self.setWindowIcon(make_app_icon())
        self.resize(1320, 840)
        self.setMinimumSize(1080, 700)

        self.folder_to_monitor = normalize_path(os.path.expanduser("~"))
        self.events = []
        self.counts = {INFO: 0, SUCCESS: 0, WARNING: 0, CRITICAL: 0}
        self.threat_active = False
        self.baseline_meta = None
        self.last_scan = None
        self._last_toast = 0.0
        self._last_beep = 0.0
        self._tray_hint_shown = False
        self._quitting = False
        self._tokens = itertools.count(1)
        self._running = {}       # task key -> token of the run currently owning it
        self._stop_events = {}   # task key -> threading.Event for long-running monitors

        self.bridge = Bridge()
        self.bridge.event.connect(self.on_event)
        self.bridge.task_done.connect(self.on_task_done)
        self.bridge.task_failed.connect(self.on_task_failed)

        self.init_ui()
        self.setup_tray_icon()
        self.toasts = ToastManager(self.centralWidget())

        self.refresh_protection()
        self.refresh_honeypot()
        self.refresh_threats()
        self.reload_baseline_meta()
        self.add_event_row(emit(self._silent, INFO, f"{APP_NAME} v{APP_VERSION} ready", log=False))

    # ------------------------------------------------------------------ UI

    def init_ui(self):
        root = QWidget()
        root.setObjectName("Root")
        page = QVBoxLayout(root)
        page.setContentsMargins(24, 20, 24, 16)
        page.setSpacing(16)

        page.addLayout(self.build_header())
        page.addWidget(self.build_scope_card())
        page.addLayout(self.build_stats())

        body = QHBoxLayout()
        body.setSpacing(16)
        left = QVBoxLayout()
        left.setSpacing(16)
        left.addWidget(self.build_protection_card())
        left.addWidget(self.build_actions_card())
        left.addStretch()
        left_widget = QWidget()
        left_widget.setLayout(left)
        left_widget.setFixedWidth(380)
        left.setContentsMargins(0, 0, 0, 0)

        right = QVBoxLayout()
        right.setSpacing(16)
        right.setContentsMargins(0, 0, 0, 0)
        right.addWidget(self.build_load_card())
        right.addWidget(self.build_activity_card(), 1)

        body.addWidget(left_widget)
        body.addLayout(right, 1)
        page.addLayout(body, 1)
        self.setCentralWidget(root)

        status = QStatusBar()
        status.setSizeGripEnabled(False)
        self.status_text = QLabel("Ready")
        self.scan_text = QLabel("No scan run this session")
        version = QLabel(f"{APP_NAME} v{APP_VERSION}")
        status.addWidget(self.status_text, 1)
        status.addPermanentWidget(self.scan_text)
        status.addPermanentWidget(version)
        self.setStatusBar(status)

    def build_header(self):
        header = QHBoxLayout()
        header.setSpacing(12)
        self.logo = ShieldLogo(42)
        titles = QVBoxLayout()
        titles.setSpacing(0)
        title = QLabel(APP_NAME)
        title.setObjectName("BrandTitle")
        subtitle = QLabel("Ransomware detection & prevention")
        subtitle.setObjectName("BrandSubtitle")
        titles.addWidget(title)
        titles.addWidget(subtitle)
        header.addWidget(self.logo)
        header.addLayout(titles)
        header.addStretch()

        self.sound_btn = QPushButton()
        self.sound_btn.setProperty("variant", "ghost")
        self.sound_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.sound_btn.clicked.connect(self.toggle_sound)
        self._update_sound_btn()
        header.addWidget(self.sound_btn)

        self.status_pill = StatusPill()
        self.status_pill.clicked.connect(self.acknowledge_threat)
        header.addWidget(self.status_pill)
        return header

    def build_scope_card(self):
        card = Card()
        card.body.setContentsMargins(18, 12, 12, 12)
        row = QHBoxLayout()
        row.setSpacing(12)
        icon = QLabel("📁")
        icon.setStyleSheet("font-size: 20px;")
        text = QVBoxLayout()
        text.setSpacing(0)
        label = QLabel("PROTECTED FOLDER")
        label.setObjectName("StatLabel")
        self.scope_label = ElidedLabel(self.folder_to_monitor)
        self.scope_label.setStyleSheet("font-size: 14px; font-weight: 600;")
        text.addWidget(label)
        text.addWidget(self.scope_label)
        open_btn = QPushButton("Open")
        open_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        open_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(self.folder_to_monitor)))
        change_btn = QPushButton("Change folder...")
        change_btn.setProperty("variant", "primary")
        change_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        change_btn.clicked.connect(self.change_folder)
        row.addWidget(icon)
        row.addLayout(text, 1)
        row.addWidget(open_btn)
        row.addWidget(change_btn)
        card.body.addLayout(row)
        return card

    def build_stats(self):
        grid = QHBoxLayout()
        grid.setSpacing(16)
        self.stat_protection = StatCard("Protection", "Off", "Real-time monitor is off", theme.MUTED)
        self.stat_baseline = StatCard("Baseline", "Loading...", "")
        self.stat_honeypot = StatCard("Honeypot", "-", "")
        self.stat_threats = StatCard("Alerts this session", "0", "")
        for card in (self.stat_protection, self.stat_baseline, self.stat_honeypot, self.stat_threats):
            grid.addWidget(card)
        return grid

    def build_protection_card(self):
        card = Card("Live protection", "Watch the folder and running processes")
        self.file_row = ToggleRow("Real-time file monitor", "Off")
        self.cpu_row = ToggleRow("Process monitor", "Off")
        self.file_row.switch.toggled.connect(self.set_file_monitor)
        self.cpu_row.switch.toggled.connect(self.set_cpu_monitor)
        card.body.addWidget(self.file_row)
        divider = QWidget()
        divider.setFixedHeight(1)
        divider.setStyleSheet(f"background: {theme.BORDER};")
        card.body.addWidget(divider)
        card.body.addWidget(self.cpu_row)
        return card

    def build_actions_card(self):
        card = Card("Actions")
        grid = QVBoxLayout()
        grid.setSpacing(8)
        self.buttons = {
            "baseline": ActionTile("🛡", "Create baseline", "Hash every file to record a known-good state", primary=True),
            "scan": ActionTile("🔍", "Run integrity scan", "Compare files against the baseline"),
            "honeypot": ActionTile("🧲", "Deploy honeypot", "Place a decoy file that triggers alerts"),
            "logs": ActionTile("📄", "View activity log", "Browse everything SecureVault recorded"),
        }
        self.buttons["baseline"].clicked.connect(self.create_baseline)
        self.buttons["scan"].clicked.connect(self.check_changes)
        self.buttons["honeypot"].clicked.connect(self.create_honeypot)
        self.buttons["logs"].clicked.connect(self.view_logs)
        for btn in self.buttons.values():
            grid.addWidget(btn)
        card.body.addLayout(grid)
        return card

    def build_load_card(self):
        card = Card("System load", "CPU usage over the last minute")
        self.load_label = QLabel("CPU --  ·  RAM --")
        self.load_label.setObjectName("Muted")
        self.load_label.setStyleSheet("font-weight: 600;")
        card.header.addWidget(self.load_label)
        self.graph = SystemLoadGraph()
        self.graph.sampled.connect(self.on_load_sample)
        card.body.addWidget(self.graph)
        return card

    def build_activity_card(self):
        card = Card("Activity", "Live feed of events detected this session")
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search events...")
        self.search.setClearButtonEnabled(True)
        self.search.setFixedWidth(200)
        self.search.textChanged.connect(self.apply_filter)
        self.level_filter = QComboBox()
        self.level_filter.addItems(["All events", "Alerts only", "Critical", "Warnings", "Info"])
        self.level_filter.currentIndexChanged.connect(self.apply_filter)
        clear = QPushButton("Clear")
        clear.setProperty("variant", "ghost")
        clear.clicked.connect(self.clear_feed)
        export = QPushButton("Export report")
        export.clicked.connect(self.export_report)
        for w in (self.search, self.level_filter, clear, export):
            card.header.addWidget(w)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["TIME", "LEVEL", "EVENT"])
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.table.verticalHeader().setDefaultSectionSize(34)
        header = self.table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(0, 86)
        self.table.setColumnWidth(1, 96)
        self.table.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self.table.cellDoubleClicked.connect(self.open_event_path)
        card.body.addWidget(self.table, 1)

        self.empty_hint = QLabel("No events match the current filter")
        self.empty_hint.setObjectName("Muted")
        self.empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_hint.hide()
        card.body.addWidget(self.empty_hint)
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

    # ------------------------------------------------------------ workers

    def _silent(self, event):
        return event

    def sink(self, event):
        """Backend event sink; safe to call from any thread."""
        self.bridge.event.emit(event)

    def run_task(self, key, fn, *args, **kwargs):
        token = next(self._tokens)
        self._running[key] = token

        def target():
            try:
                result = fn(*args, **kwargs)
            except Exception as e:  # Surface unexpected backend failures instead of dying silently
                self.bridge.task_failed.emit(key, token, str(e))
            else:
                self.bridge.task_done.emit(key, token, result)

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
                self.last_scan = datetime.datetime.now()
                issues = len(result["modified"]) + len(result["deleted"])
                self.scan_text.setText(f"Last scan {self.last_scan:%H:%M:%S}: "
                                       + (f"{issues} change(s) found" if issues else "no changes"))
        elif key == "honeypot":
            self.buttons["honeypot"].set_busy(False)
            self.refresh_honeypot()
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
        self.add_event_row(event)
        self.status_text.setText(event.message)

        now = time.time()
        if event.level == CRITICAL:
            self.threat_active = True
            self.toasts.show("Threat detected", self._short(event), CRITICAL)
            self._last_toast = now
            SoundManager.play_alert()
            QApplication.alert(self)
            if not self.isVisible() and self.tray_icon.isVisible():
                self.tray_icon.showMessage(f"{APP_NAME}: threat detected", event.message,
                                           QSystemTrayIcon.MessageIcon.Critical, 8000)
        elif event.level in (WARNING, SUCCESS):
            # Individual scan findings go to the feed only; the scan summary gets the toast
            per_file_scan = event.category == "scan" and event.path
            if not per_file_scan and now - self._last_toast > 1.2:
                title = {"warning": "Warning", "success": "Done"}[event.level]
                self.toasts.show(title, self._short(event), event.level)
                self._last_toast = now
            if event.level == WARNING and not per_file_scan and now - self._last_beep > 3:
                SoundManager.play_warning()
                self._last_beep = now

        if event.category == "honeypot":
            self.refresh_honeypot()
        self.refresh_threats()
        self.refresh_protection()

    def _short(self, event):
        """Toast-sized message: full paths are reduced to file names."""
        message = event.message
        if event.path:
            for part in event.path.split(" -> "):
                message = message.replace(part, os.path.basename(part) or part)
        message = message.replace(self.folder_to_monitor + os.sep, "")
        return message if len(message) <= 160 else message[:157] + "..."

    def add_event_row(self, event):
        self.table.insertRow(0)
        time_item = QTableWidgetItem(time.strftime("%H:%M:%S", time.localtime(event.timestamp)))
        time_item.setForeground(QColor(theme.MUTED))
        time_item.setToolTip(event.time_str)
        color = QColor(theme.LEVEL_COLORS.get(event.level, theme.INFO))
        level_item = QTableWidgetItem(f"●  {theme.LEVEL_LABELS.get(event.level, event.level.upper())}")
        level_item.setForeground(color)
        font = QFont(theme.FONT_FAMILY, 8)
        font.setBold(True)
        level_item.setFont(font)
        message_item = QTableWidgetItem(event.message)
        message_item.setToolTip(event.message + ("\n\nDouble-click to show in folder" if event.path else ""))
        if event.level == CRITICAL:
            message_item.setForeground(QColor("#fecaca"))
        message_item.setData(Qt.ItemDataRole.UserRole, event)
        self.table.setItem(0, 0, time_item)
        self.table.setItem(0, 1, level_item)
        self.table.setItem(0, 2, message_item)
        if self.table.rowCount() > MAX_FEED_ROWS:
            self.table.removeRow(self.table.rowCount() - 1)
        self._apply_filter_to_row(0)
        self._update_empty_hint()

    def _row_matches(self, event):
        needle = self.search.text().strip().lower()
        if needle and needle not in event.message.lower():
            return False
        allowed = {
            0: None,
            1: {WARNING, CRITICAL},
            2: {CRITICAL},
            3: {WARNING},
            4: {INFO, SUCCESS},
        }[self.level_filter.currentIndex()]
        return allowed is None or event.level in allowed

    def _apply_filter_to_row(self, row):
        item = self.table.item(row, 2)
        event = item.data(Qt.ItemDataRole.UserRole) if item else None
        self.table.setRowHidden(row, bool(event) and not self._row_matches(event))

    def apply_filter(self, *_):
        for row in range(self.table.rowCount()):
            self._apply_filter_to_row(row)
        self._update_empty_hint()

    def _update_empty_hint(self):
        visible = any(not self.table.isRowHidden(r) for r in range(self.table.rowCount()))
        self.empty_hint.setVisible(not visible)

    def clear_feed(self):
        self.table.setRowCount(0)
        self._update_empty_hint()

    def open_event_path(self, row, _column):
        item = self.table.item(row, 2)
        event = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not (event and event.path):
            return
        target = event.path if os.path.isdir(event.path) else os.path.dirname(event.path)
        if os.path.isdir(target):
            QDesktopServices.openUrl(QUrl.fromLocalFile(target))

    def on_load_sample(self, cpu, mem):
        self.load_label.setText(f"CPU {cpu:.0f}%  ·  RAM {mem:.0f}%")

    # ------------------------------------------------------------- status

    def refresh_protection(self):
        file_on = "file_monitor" in self._stop_events
        cpu_on = "cpu_monitor" in self._stop_events
        self.file_row.state.setText(f"Watching {os.path.basename(self.folder_to_monitor) or self.folder_to_monitor}"
                                    if file_on else "Off - changes are not being watched")
        self.cpu_row.state.setText("Watching for sustained high CPU usage" if cpu_on else "Off")
        if file_on and cpu_on:
            self.stat_protection.set("Full", "File and process monitors running", theme.SUCCESS)
        elif file_on:
            self.stat_protection.set("Active", "File monitor running", theme.SUCCESS)
        elif cpu_on:
            self.stat_protection.set("Partial", "Only the process monitor is running", theme.WARNING)
        else:
            self.stat_protection.set("Off", "Turn on the real-time monitor", theme.MUTED)

        if self.threat_active:
            self.status_pill.set_state("THREAT DETECTED", theme.CRITICAL, pulse=True,
                                       tooltip="A critical alert was raised. Click to acknowledge.")
            self.logo.set_color(theme.CRITICAL)
        elif file_on:
            self.status_pill.set_state("PROTECTED", theme.SUCCESS, pulse=True, tooltip="Real-time protection is on")
            self.logo.set_color(theme.ACCENT)
        else:
            self.status_pill.set_state("UNPROTECTED", theme.WARNING, tooltip="Real-time file monitoring is off")
            self.logo.set_color(theme.ACCENT)

    def acknowledge_threat(self):
        if self.threat_active:
            self.threat_active = False
            self.refresh_protection()
            self.on_event(emit(self._silent, INFO, "Threat alert acknowledged"))

    def refresh_threats(self):
        crit, warn = self.counts.get(CRITICAL, 0), self.counts.get(WARNING, 0)
        accent = theme.CRITICAL if crit else theme.WARNING if warn else theme.SUCCESS
        caption = f"{crit} critical · {warn} warnings" if crit or warn else "Nothing suspicious so far"
        self.stat_threats.set(crit + warn, caption, accent)

    def refresh_honeypot(self):
        path = honeypot_path(self.folder_to_monitor)
        if os.path.exists(path):
            self.stat_honeypot.set("Deployed", os.path.basename(path), theme.SUCCESS)
        else:
            self.stat_honeypot.set("Not deployed", "Deploy a decoy to catch intruders", theme.MUTED)

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
            self.stat_baseline.set("None", "Create a baseline to enable scans", theme.WARNING)
            return
        created = meta.get("created")
        when = created.replace("T", " ")[:16] if created else "unknown date"
        folder = meta.get("folder")
        if folder and os.path.normcase(folder) != os.path.normcase(self.folder_to_monitor):
            self.stat_baseline.set(f"{meta['count']:,} files", f"Made for another folder: {folder}", theme.WARNING)
        else:
            self.stat_baseline.set(f"{meta['count']:,} files", f"Created {when}", theme.SUCCESS)

    # ------------------------------------------------------------ actions

    def change_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Protect", self.folder_to_monitor)
        if not folder:
            return
        folder = normalize_path(folder)
        if folder == self.folder_to_monitor:
            return
        self.folder_to_monitor = folder
        self.scope_label.setText(folder)
        restart = "file_monitor" in self._stop_events
        self.on_event(emit(self._silent, INFO, f"Protected folder changed to {folder}"))
        if restart:
            self.set_file_monitor(False)
            self.file_row.switch.set_checked_silently(True)
            self.set_file_monitor(True)
        self.refresh_honeypot()
        self.refresh_baseline()

    def create_baseline(self):
        self.buttons["baseline"].set_busy(True, "Indexing files...")
        self.run_task("baseline", create_baseline, self.folder_to_monitor, self.sink)

    def check_changes(self):
        self.buttons["scan"].set_busy(True, "Scanning...")
        self.run_task("scan", check_for_changes, self.folder_to_monitor, self.sink)

    def create_honeypot(self):
        self.buttons["honeypot"].set_busy(True, "Deploying...")
        self.run_task("honeypot", create_honeypot, self.folder_to_monitor, self.sink)

    def set_file_monitor(self, enabled):
        self._set_monitor("file_monitor", enabled, start_real_time_monitor,
                          lambda stop: (self.folder_to_monitor, self.sink, stop))

    def set_cpu_monitor(self, enabled):
        self._set_monitor("cpu_monitor", enabled, monitor_processes_sustained, None)

    def _set_monitor(self, key, enabled, fn, args_for):
        if enabled:
            if key in self._stop_events:
                return
            stop = threading.Event()
            self._stop_events[key] = stop
            if args_for:
                self.run_task(key, fn, *args_for(stop))
            else:
                self.run_task(key, fn, alert_queue=self.sink, stop_event=stop)
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
        self.sound_btn.setText("🔔  Sound on" if SoundManager.enabled else "🔕  Sound off")
        self.sound_btn.setToolTip("Toggle audible alerts")

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
                f"<td><span class='badge' style='color:{color};border-color:{color}'>"
                f"{html.escape(theme.LEVEL_LABELS.get(ev.level, ev.level))}</span></td>"
                f"<td>{html.escape(ev.category)}</td><td class='m'>{html.escape(ev.message)}</td></tr>"
            )
        crit, warn = self.counts.get(CRITICAL, 0), self.counts.get(WARNING, 0)
        generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{APP_NAME} Evidence Report</title>
<style>
body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: {theme.BG}; color: {theme.TEXT}; margin: 0; padding: 32px; }}
h1 {{ margin: 0 0 4px; font-size: 24px; }}
.sub {{ color: {theme.MUTED}; margin-bottom: 24px; }}
.cards {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
.card {{ background: {theme.SURFACE}; border: 1px solid {theme.BORDER}; border-radius: 12px; padding: 14px 18px; min-width: 160px; }}
.card b {{ display: block; font-size: 22px; }}
.card span {{ color: {theme.MUTED}; font-size: 12px; text-transform: uppercase; letter-spacing: .5px; }}
table {{ width: 100%; border-collapse: collapse; background: {theme.SURFACE}; border: 1px solid {theme.BORDER}; border-radius: 12px; overflow: hidden; }}
th {{ text-align: left; color: {theme.MUTED}; font-size: 11px; text-transform: uppercase; padding: 10px 12px; border-bottom: 1px solid {theme.BORDER}; }}
td {{ padding: 8px 12px; border-bottom: 1px solid {theme.SURFACE_2}; font-size: 13px; vertical-align: top; }}
td.t {{ color: {theme.MUTED}; white-space: nowrap; }}
td.m {{ word-break: break-all; }}
.badge {{ border: 1px solid; border-radius: 10px; padding: 1px 8px; font-size: 11px; font-weight: 700; }}
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
        """Keep protecting from the tray while a monitor is running."""
        if not self._quitting and self._stop_events and self.tray_icon.isVisible():
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
        self.tray_icon.hide()
        QApplication.instance().quit()


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
