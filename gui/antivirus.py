# gui/antivirus.py
"""Antivirus and Quarantine pages of the SecureVault dashboard."""
import os
import time
import datetime
import threading

from PyQt6.QtCore import Qt, QUrl, QPropertyAnimation, QEasingCurve, QRectF, QPointF
from PyQt6.QtGui import QDesktopServices, QFontMetrics, QPainter, QColor
from PyQt6.QtWidgets import (
    QWidget, QFrame, QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QScrollArea,
    QFileDialog, QMenu, QMessageBox, QGraphicsOpacityEffect, QSizePolicy,
)

from main import emit, INFO, SUCCESS, WARNING
from scanner import (
    Finding, MALICIOUS, quick_scan_targets, full_scan_targets, quarantine_file,
    list_quarantine, restore_quarantined, delete_quarantined, import_signatures,
    USER_SIGNATURE_DIR, USER_YARA_DIR,
)
from gui import theme
from gui.widgets import Card, StatChip, ToggleRow, ScanRing, paint_shield

VERDICT_COLORS = {"malicious": theme.CRITICAL, "suspicious": theme.WARNING}


def elide(text, label, width=None, mode=Qt.TextElideMode.ElideMiddle):
    return QFontMetrics(label.font()).elidedText(text, mode, width or max(80, label.width()))


def pill(text, color):
    label = QLabel(text)
    label.setStyleSheet(f"background: {theme.soft(color, 0.13)}; color: {color}; border-radius: 9px;"
                        f" padding: 2px 9px; font-size: 11px; font-weight: 700;")
    return label


def fade_in(widget, duration=320):
    effect = QGraphicsOpacityEffect(widget)
    widget.setGraphicsEffect(effect)
    anim = QPropertyAnimation(effect, b"opacity", widget)
    anim.setDuration(duration)
    anim.setStartValue(0.0)
    anim.setEndValue(1.0)
    anim.setEasingCurve(QEasingCurve.Type.OutCubic)
    anim.finished.connect(lambda: widget.setGraphicsEffect(None))
    anim.start()


class EmptyState(QWidget):
    """Friendly illustration shown when a list has nothing in it."""
    def __init__(self, title, subtitle, parent=None):
        super().__init__(parent)
        self.title, self.subtitle = title, subtitle
        self.setMinimumHeight(220)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = QPointF(self.width() / 2, self.height() / 2 - 30)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(theme.ACCENT_SOFT))
        painter.drawEllipse(c, 38, 38)
        paint_shield(painter, QRectF(c.x() - 19, c.y() - 21, 38, 41), theme.SUCCESS)
        painter.setPen(QColor(theme.TEXT))
        f = painter.font()
        f.setPointSize(11)
        f.setBold(True)
        painter.setFont(f)
        painter.drawText(QRectF(0, c.y() + 48, self.width(), 24), Qt.AlignmentFlag.AlignCenter, self.title)
        f.setBold(False)
        f.setPointSize(9)
        painter.setFont(f)
        painter.setPen(QColor(theme.MUTED))
        painter.drawText(QRectF(0, c.y() + 74, self.width(), 20), Qt.AlignmentFlag.AlignCenter, self.subtitle)


class ScrollList(QScrollArea):
    """Vertical list of row widgets with an empty state."""
    def __init__(self, empty_title, empty_subtitle, parent=None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setStyleSheet("QScrollArea { background: transparent; } QScrollArea > QWidget > QWidget { background: transparent; }")
        host = QWidget()
        self.rows = QVBoxLayout(host)
        self.rows.setContentsMargins(0, 0, 6, 0)
        self.rows.setSpacing(10)
        self.empty = EmptyState(empty_title, empty_subtitle)
        self.rows.addWidget(self.empty)
        self.rows.addStretch()
        self.setWidget(host)

    def add_row(self, row, top=True):
        self.rows.insertWidget(1 if top else self.rows.count() - 1, row)
        self.empty.hide()
        fade_in(row)

    def remove_row(self, row):
        self.rows.removeWidget(row)
        row.deleteLater()
        self.empty.setVisible(self.count() == 0)

    def count(self):
        return self.rows.count() - 2

    def clear(self):
        while self.count():
            item = self.rows.takeAt(1)
            item.widget().deleteLater()
        self.empty.show()


class FindingRow(QFrame):
    def __init__(self, finding, on_quarantine, on_ignore, parent=None):
        super().__init__(parent)
        self.finding = finding
        color = VERDICT_COLORS.get(finding.verdict, theme.WARNING)
        self.setObjectName("Row")
        self.setStyleSheet(f"#Row {{ background: {theme.SURFACE_2}; border: 1px solid {theme.BORDER}; border-radius: 16px; }}"
                           f"#Row:hover {{ border-color: {theme.soft(color, 0.45)}; }}")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(14)

        bubble = QLabel("!" if finding.verdict == MALICIOUS else "?")
        bubble.setFixedSize(40, 40)
        bubble.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bubble.setStyleSheet(f"background: {theme.soft(color, 0.14)}; color: {color}; border-radius: 20px;"
                             f" font-size: 17px; font-weight: 800;")
        layout.addWidget(bubble, 0, Qt.AlignmentFlag.AlignTop)

        text = QVBoxLayout()
        text.setSpacing(3)
        top = QHBoxLayout()
        top.setSpacing(8)
        name = QLabel(finding.name)
        name.setStyleSheet("font-weight: 700; font-size: 13px;")
        name.setToolTip(finding.path)
        top.addWidget(name)
        top.addWidget(pill(finding.threat, color))
        top.addWidget(pill(f"{finding.verdict.capitalize()} · {finding.score}", color))
        top.addStretch()
        text.addLayout(top)
        reasons = QLabel(" · ".join(finding.reasons))
        reasons.setObjectName("Muted")
        reasons.setWordWrap(True)
        reasons.setStyleSheet("font-size: 12px;")
        text.addWidget(reasons)
        where = QLabel(f"{finding.engine}  ·  {os.path.dirname(finding.path)}")
        where.setStyleSheet(f"color: {theme.SUBTLE}; font-size: 11px;")
        where.setToolTip(finding.path)
        where.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        text.addWidget(where)
        layout.addLayout(text, 1)

        buttons = QVBoxLayout()
        buttons.setSpacing(6)
        self.quarantine_btn = QPushButton("Quarantine")
        self.quarantine_btn.setProperty("variant", "primary")
        self.quarantine_btn.clicked.connect(lambda: on_quarantine(self))
        ignore = QPushButton("Ignore")
        ignore.setProperty("variant", "ghost")
        ignore.clicked.connect(lambda: on_ignore(self))
        for b in (self.quarantine_btn, ignore):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setFixedWidth(112)
            buttons.addWidget(b)
        layout.addLayout(buttons)


class AntivirusPage(QWidget):
    def __init__(self, window):
        super().__init__()
        self.w = window
        self.scanner = window.scanner
        self.rows = {}
        self.stop_event = None
        self.scanning = False
        self._last_progress = 0.0

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(20)
        left = QVBoxLayout()
        left.setSpacing(20)
        left.addWidget(self.build_scan_card())
        left.addWidget(self.build_engines_card())
        left.addStretch()
        left_widget = QWidget()
        left_widget.setLayout(left)
        left_widget.setFixedWidth(360)
        left.setContentsMargins(0, 0, 0, 0)

        right = QVBoxLayout()
        right.setSpacing(20)
        right.setContentsMargins(0, 0, 0, 0)
        stats = QHBoxLayout()
        stats.setSpacing(16)
        self.stat_scanned = StatChip("🗂", "Files scanned")
        self.stat_threats = StatChip("🚨", "Threats")
        self.stat_suspicious = StatChip("🔎", "Suspicious")
        self.stat_last = StatChip("🕒", "Last scan")
        for chip in (self.stat_scanned, self.stat_threats, self.stat_suspicious, self.stat_last):
            stats.addWidget(chip)
        self.stat_scanned.set(0, "This session")
        self.stat_threats.set(0, "Malicious files", theme.CRITICAL)
        self.stat_suspicious.set(0, "Worth a look", theme.WARNING)
        self.stat_last.set("Never", "Run a quick scan")
        right.addLayout(stats)
        right.addWidget(self.build_results_card(), 1)

        layout.addWidget(left_widget)
        layout.addLayout(right, 1)
        self.refresh_engines()

    # ---------------------------------------------------------------- UI

    def build_scan_card(self):
        card = Card(padding=(22, 24, 22, 22))
        card.body.setSpacing(8)
        self.ring = ScanRing()
        card.body.addWidget(self.ring, 0, Qt.AlignmentFlag.AlignHCenter)
        card.body.addSpacing(6)
        self.headline = QLabel("Scan your PC")
        self.headline.setObjectName("Headline")
        self.headline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.sub = QLabel("Find malware, disguised programs and ransomware tools")
        self.sub.setObjectName("Muted")
        self.sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.sub.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        card.body.addWidget(self.headline)
        card.body.addWidget(self.sub)
        card.body.addSpacing(8)

        self.quick_btn = QPushButton("⚡  Quick scan")
        self.quick_btn.setProperty("variant", "primary")
        self.quick_btn.setMinimumHeight(44)
        self.quick_btn.setToolTip("Downloads, Desktop, Temp and Startup: where malware usually lands")
        self.quick_btn.clicked.connect(lambda: self.start_scan("Quick scan", quick_scan_targets()))
        card.body.addWidget(self.quick_btn)

        row = QHBoxLayout()
        row.setSpacing(8)
        self.full_btn = QPushButton("Full scan")
        self.full_btn.setToolTip("Everything in your user folder")
        self.full_btn.clicked.connect(lambda: self.start_scan("Full scan", full_scan_targets()))
        self.custom_btn = QPushButton("Custom  ▾")
        menu = QMenu(self)
        menu.addAction("Scan a folder…", self.scan_folder)
        menu.addAction("Scan a file…", self.scan_file)
        self.custom_btn.setMenu(menu)
        self.custom_btn.setStyleSheet("QPushButton::menu-indicator { width: 0; }")
        row.addWidget(self.full_btn)
        row.addWidget(self.custom_btn)
        card.body.addLayout(row)

        self.stop_btn = QPushButton("Stop scan")
        self.stop_btn.setMinimumHeight(40)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.hide()
        card.body.addWidget(self.stop_btn)
        for b in (self.quick_btn, self.full_btn, self.custom_btn, self.stop_btn):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
        return card

    def build_engines_card(self):
        card = Card("Protection engines", "What SecureVault scans with")
        self.defender_row = ToggleRow("🛡", "Microsoft Defender engine")
        self.onaccess_row = ToggleRow("⚡", "Scan new files automatically")
        self.defender_row.switch.set_checked_silently(bool(self.scanner.defender))
        self.defender_row.switch.setEnabled(bool(self.scanner.defender))
        self.onaccess_row.switch.set_checked_silently(self.w.on_access_enabled)
        self.onaccess_row.switch.toggled.connect(self.set_on_access)
        self.defender_row.switch.toggled.connect(lambda _: self.refresh_engines())
        card.body.addWidget(self.defender_row)
        card.body.addWidget(self.onaccess_row)

        footer = QHBoxLayout()
        self.engine_info = QLabel()
        self.engine_info.setObjectName("Muted")
        self.engine_info.setStyleSheet("font-size: 11px;")
        more = QPushButton("Signatures  ▾")
        more.setProperty("variant", "ghost")
        more.setCursor(Qt.CursorShape.PointingHandCursor)
        more.setStyleSheet("QPushButton::menu-indicator { width: 0; }")
        menu = QMenu(self)
        menu.addAction("Import hash signatures…", self.import_signatures)
        menu.addAction("Reload signatures and rules", self.reload_signatures)
        menu.addAction("Open signatures folder", self.open_signature_folder)
        more.setMenu(menu)
        footer.addWidget(self.engine_info, 1)
        footer.addWidget(more)
        card.body.addLayout(footer)
        return card

    def build_results_card(self):
        card = Card("Scan results", "Threats and suspicious files appear here")
        self.quarantine_all_btn = QPushButton("Quarantine all threats")
        self.quarantine_all_btn.setProperty("variant", "primary")
        self.quarantine_all_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.quarantine_all_btn.clicked.connect(self.quarantine_all)
        self.quarantine_all_btn.hide()
        card.header.addWidget(self.quarantine_all_btn)
        self.list = ScrollList("You're all clear", "No threats found yet. Run a scan to check your files.")
        card.body.addWidget(self.list, 1)
        return card

    # ----------------------------------------------------------- engines

    def refresh_engines(self):
        s = self.scanner
        self.defender_row.state.setText(
            ("Deep scans also use Defender" if self.defender_row.switch.isChecked() else "Off")
            if s.defender else "Not available on this PC")
        self.onaccess_row.state.setText("Checks new files in the protected folder"
                                        if self.w.on_access_enabled else "Off")
        n = s.signature_count
        self.engine_info.setText(f"{n:,} signature{'s' if n != 1 else ''} · YARA {'on' if s.yara_rules else 'off'}")

    def set_on_access(self, enabled):
        self.w.on_access_enabled = enabled
        self.refresh_engines()

    def open_signature_folder(self):
        os.makedirs(USER_YARA_DIR, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(USER_SIGNATURE_DIR))

    def reload_signatures(self):
        self.scanner.reload()
        self.refresh_engines()
        self.w.on_event(emit(self.w._silent, INFO, f"Signatures reloaded: {self.scanner.signature_count:,} loaded"))

    def import_signatures(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import Hash Signatures", os.path.expanduser("~"),
                                              "Hash lists (*.txt *.csv);;All files (*)")
        if not path:
            return
        try:
            added = import_signatures(path)
        except OSError as e:
            self.w.on_event(emit(self.w._silent, WARNING, f"Signature import failed: {e}"))
            return
        self.scanner.reload()
        self.refresh_engines()
        self.w.on_event(emit(self.w._silent, SUCCESS, f"Imported {added:,} new signatures"))

    # ----------------------------------------------------------- scanning

    def scan_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Choose a Folder to Scan", os.path.expanduser("~"))
        if folder:
            self.start_scan("Custom scan", [folder])

    def scan_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a File to Scan", os.path.expanduser("~"))
        if path:
            self.start_scan("File scan", [path])

    def start_scan(self, label, targets):
        if self.scanning or not targets:
            return
        self.scanning = True
        self.stop_event = threading.Event()
        self.ring.reset()
        self.ring.set_color(theme.ACCENT)
        self.ring.set_progress(-1, "0%", "Finding files…")
        self.headline.setText(f"{label} running")
        self.sub.setText("Preparing…")
        for b in (self.quick_btn, self.full_btn, self.custom_btn):
            b.setEnabled(False)
        self.stop_btn.show()
        self._label = label
        self.w.run_task("av_scan", self.scanner.scan, targets, sink=self.w.sink, stop_event=self.stop_event,
                        progress=self._progress_from_worker, label=label,
                        use_defender=self.defender_row.switch.isChecked())

    def _progress_from_worker(self, done, total, path):
        """Called on the scan thread; forwards at most ~12 updates per second."""
        now = time.time()
        if now - self._last_progress > 0.08 or done == total:
            self._last_progress = now
            try:
                self.w.bridge.progress.emit(done, total, path)
            except RuntimeError:  # the window is already gone (app quitting)
                pass

    def on_progress(self, done, total, path):
        if not self.scanning:
            return
        fraction = done / total if total else 1.0
        self.ring.set_progress(fraction, f"{fraction * 100:.0f}%", f"{done:,} of {total:,} files")
        if path:
            self.sub.setText(elide(path, self.sub))

    def stop_scan(self):
        if self.stop_event:
            self.stop_event.set()
        self.sub.setText("Stopping…")

    def on_scan_done(self, result):
        self.scanning = False
        self.stop_btn.hide()
        for b in (self.quick_btn, self.full_btn, self.custom_btn):
            b.setEnabled(True)
        if not result:
            self.ring.set_progress(None, "Ready", "")
            self.headline.setText("Scan failed")
            self.sub.setText("See the activity feed for details")
            return
        threats, suspicious = result["malicious"], result["suspicious"]
        self.ring.set_progress(1.0, f"{result['scanned']:,}", "files scanned")
        if threats:
            self.ring.set_color(theme.CRITICAL)
            self.headline.setText(f"{threats} threat{'s' if threats != 1 else ''} found")
        elif suspicious:
            self.ring.set_color(theme.WARNING)
            self.headline.setText(f"{suspicious} suspicious file{'s' if suspicious != 1 else ''}")
        else:
            self.ring.set_color(theme.SUCCESS)
            self.headline.setText("No threats found")
        word = "Stopped" if result["cancelled"] else "Finished"
        self.sub.setText(f"{word} in {result['duration']:.0f}s · {self._label}")
        self.stat_scanned.set(self.stat_scanned.value._value + result["scanned"]
                              if isinstance(self.stat_scanned.value._value, int) else result["scanned"])
        self.stat_last.set(datetime.datetime.now().strftime("%H:%M"),
                           f"{self._label} · {'clean' if not (threats or suspicious) else 'issues found'}")
        self.refresh_counts()

    # ----------------------------------------------------------- findings

    def add_finding(self, data):
        finding = Finding(**data)
        key = os.path.normcase(finding.path)
        if key in self.rows:
            return
        row = FindingRow(finding, self.quarantine_row, self.ignore_row)
        self.rows[key] = row
        self.list.add_row(row)
        self.refresh_counts()

    def refresh_counts(self):
        findings = [r.finding for r in self.rows.values()]
        threats = sum(1 for f in findings if f.verdict == MALICIOUS)
        self.stat_threats.set(threats, "Malicious files", theme.CRITICAL if threats else theme.SUCCESS)
        self.stat_suspicious.set(len(findings) - threats, "Worth a look", theme.WARNING)
        self.quarantine_all_btn.setVisible(threats > 0)
        self.w.update_nav_badges()

    def _drop(self, row):
        self.rows.pop(os.path.normcase(row.finding.path), None)
        self.list.remove_row(row)
        self.refresh_counts()

    def quarantine_row(self, row, quiet=False):
        f = row.finding
        try:
            if not os.path.exists(f.path):
                raise FileNotFoundError("the file is already gone (another antivirus may have removed it)")
            quarantine_file(f.path, f)
        except OSError as e:
            if not quiet:
                self.w.on_event(emit(self.w._silent, WARNING, f"Could not quarantine {f.name}: {e}", "scanner"))
            if isinstance(e, FileNotFoundError):
                self._drop(row)
            return False
        self._drop(row)
        if not quiet:
            self.w.on_event(emit(self.w._silent, SUCCESS, f"Quarantined {f.name}", "scanner"))
        self.w.quarantine_page.refresh()
        return True

    def ignore_row(self, row):
        self._drop(row)

    def quarantine_all(self):
        rows = [r for r in self.rows.values() if r.finding.verdict == MALICIOUS]
        moved = sum(self.quarantine_row(r, quiet=True) for r in rows)
        self.w.on_event(emit(self.w._silent, SUCCESS if moved == len(rows) else WARNING,
                             f"Quarantined {moved} of {len(rows)} threats", "scanner"))


class QuarantineRow(QFrame):
    def __init__(self, entry, on_restore, on_delete, parent=None):
        super().__init__(parent)
        self.entry = entry
        color = VERDICT_COLORS.get(entry.get("verdict"), theme.WARNING)
        self.setObjectName("Row")
        self.setStyleSheet(f"#Row {{ background: {theme.SURFACE_2}; border: 1px solid {theme.BORDER}; border-radius: 16px; }}")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(14)
        bubble = QLabel("🔒")
        bubble.setFixedSize(40, 40)
        bubble.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bubble.setStyleSheet(f"background: {theme.ACCENT_SOFT}; border-radius: 20px; font-size: 16px;")
        layout.addWidget(bubble, 0, Qt.AlignmentFlag.AlignTop)

        text = QVBoxLayout()
        text.setSpacing(3)
        top = QHBoxLayout()
        top.setSpacing(8)
        name = QLabel(entry["name"])
        name.setStyleSheet("font-weight: 700; font-size: 13px;")
        top.addWidget(name)
        top.addWidget(pill(entry.get("threat", "Unknown"), color))
        top.addStretch()
        text.addLayout(top)
        origin = QLabel(f"From {entry['original_path']}")
        origin.setObjectName("Muted")
        origin.setStyleSheet("font-size: 12px;")
        origin.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        origin.setToolTip(entry["original_path"])
        when = entry.get("quarantined_at", "").replace("T", " ")
        meta = QLabel(f"Quarantined {when}  ·  {entry.get('size', 0) / 1024:,.1f} KB")
        meta.setStyleSheet(f"color: {theme.SUBTLE}; font-size: 11px;")
        text.addWidget(origin)
        text.addWidget(meta)
        layout.addLayout(text, 1)

        restore = QPushButton("Restore")
        restore.clicked.connect(lambda: on_restore(self))
        delete = QPushButton("Delete")
        delete.setStyleSheet(f"QPushButton {{ color: {theme.CRITICAL}; }} QPushButton:hover {{"
                             f" background: {theme.soft(theme.CRITICAL, 0.10)}; border-color: {theme.CRITICAL}; }}")
        delete.clicked.connect(lambda: on_delete(self))
        for b in (restore, delete):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setFixedWidth(96)
            layout.addWidget(b)


class QuarantinePage(QWidget):
    def __init__(self, window):
        super().__init__()
        self.w = window
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        card = Card("Quarantine", "Quarantined files are neutralized and cannot run. Restore anything you trust.")
        self.count_label = pill("0 items", theme.ACCENT)
        self.delete_all_btn = QPushButton("Delete all")
        self.delete_all_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.delete_all_btn.clicked.connect(self.delete_all)
        card.header.addWidget(self.count_label)
        card.header.addWidget(self.delete_all_btn)
        self.list = ScrollList("Quarantine is empty", "Threats you quarantine are kept here safely.")
        card.body.addWidget(self.list, 1)
        layout.addWidget(card)
        self.refresh()

    def refresh(self):
        self.list.clear()
        entries = list_quarantine()
        for entry in entries:
            self.list.add_row(QuarantineRow(entry, self.restore, self.delete), top=False)
        self.count_label.setText(f"{len(entries)} item{'s' if len(entries) != 1 else ''}")
        self.delete_all_btn.setEnabled(bool(entries))
        self.w.update_nav_badges(len(entries))

    def _confirm(self, title, text):
        return QMessageBox.question(self, title, text) == QMessageBox.StandardButton.Yes

    def restore(self, row):
        entry = row.entry
        if not self._confirm("Restore file?", f"Put “{entry['name']}” back in its original folder?\n\n"
                                              "Only restore files you are sure are safe."):
            return
        try:
            path = restore_quarantined(entry["id"])
        except OSError as e:
            self.w.on_event(emit(self.w._silent, WARNING, f"Restore failed: {e}", "scanner"))
            return
        self.w.on_event(emit(self.w._silent, INFO, f"Restored from quarantine: {path}", "scanner", path))
        self.refresh()

    def delete(self, row):
        if not self._confirm("Delete permanently?", f"Permanently delete “{row.entry['name']}”? This cannot be undone."):
            return
        delete_quarantined(row.entry["id"])
        self.w.on_event(emit(self.w._silent, INFO, f"Deleted from quarantine: {row.entry['name']}", "scanner"))
        self.refresh()

    def delete_all(self):
        entries = list_quarantine()
        if not entries or not self._confirm("Delete everything?",
                                            f"Permanently delete all {len(entries)} quarantined files?"):
            return
        for entry in entries:
            delete_quarantined(entry["id"])
        self.w.on_event(emit(self.w._silent, INFO, f"Deleted {len(entries)} files from quarantine", "scanner"))
        self.refresh()
