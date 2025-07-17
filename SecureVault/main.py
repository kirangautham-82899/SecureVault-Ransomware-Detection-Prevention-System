# main.py
import os
import hashlib
import json
import time
import psutil
from collections import defaultdict, deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import platform
import tkinter as tk
import queue
# At the top of main.py, import the GUI launcher
def launch_gui():
    import sys
    from PyQt6.QtWidgets import QApplication
    from gui.dashboard import SecureVaultGUI

    app = QApplication(sys.argv)
    window = SecureVaultGUI()
    window.show()
    sys.exit(app.exec())

HASH_DB_FILE = "hash_db.json"
LOG_FILE = "suspicious_activity.log"
HONEYPOT_FILE = "honeypot_fake_sensitive.txt"

def notify_user(message, title="Alert", duration=5000):
    def popup():
        root = tk.Tk()
        root.title(title)
        root.geometry("300x100+1000+50")
        root.attributes("-topmost", True)
        root.resizable(False, False)
        root.overrideredirect(True)
        label = tk.Label(root, text=message, font=("Segoe UI", 10), fg="white", bg="#333333", wraplength=280)
        label.pack(expand=True, fill="both")
        root.after(duration, root.destroy)
        root.mainloop()

    threading.Thread(target=popup, daemon=True).start()

def log_suspicious_activity(message):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def normalize_path(file_path):
    return os.path.normpath(file_path)

def create_baseline(folder_to_monitor):
    hash_data = {}
    for root, _, files in os.walk(folder_to_monitor):
        for file in files:
            if file in (HASH_DB_FILE, HONEYPOT_FILE):
                continue
            full_path = os.path.join(root, file)
            file_hash = calculate_hash(full_path)
            if file_hash:
                norm_path = normalize_path(full_path)
                hash_data[norm_path] = file_hash
    with open(HASH_DB_FILE, "w") as f:
        json.dump(hash_data, f, indent=4)
    print(f"✅ Baseline created at {HASH_DB_FILE}")
    notify_user("Hash baseline successfully created.")

def check_for_changes():
    try:
        with open(HASH_DB_FILE, "r") as f:
            saved_hashes = json.load(f)
    except FileNotFoundError:
        print("❌ Baseline file not found! Please run baseline first.")
        notify_user("Baseline not found. Please create one first.")
        return

    modified_files = []
    for file_path, old_hash in saved_hashes.items():
        if os.path.exists(file_path):
            current_hash = calculate_hash(file_path)
            if current_hash != old_hash:
                modified_files.append(file_path)
        else:
            modified_files.append(f"{file_path} (deleted)")

    if modified_files:
        print("⚠️ ALERT! Modified or deleted files:")
        for f in modified_files:
            print(" -", f)
        notify_user("Files modified or deleted! Check logs.")
    else:
        print("✅ No changes detected.")
        notify_user("No file changes detected. All files are intact.")

def create_honeypot():
    if not os.path.exists(HONEYPOT_FILE):
        try:
            with open(HONEYPOT_FILE, "w") as f:
                f.write("DO NOT TOUCH! This file is a honeypot.")
            print(f"📦 Honeypot created: {HONEYPOT_FILE}")
            notify_user("Honeypot file created.")
        except Exception as e:
            print(f"⚠️ Honeypot creation error: {e}")

class RealTimeMonitor(FileSystemEventHandler):
    def __init__(self, baseline_hashes, alert_queue=None):
        super().__init__()
        self.baseline_hashes = baseline_hashes
        self.change_times = []
        self.alert_queue = alert_queue

    def on_created(self, event):
        if not event.is_directory:
            log_suspicious_activity(f"New file created: {event.src_path}")
            notify_user(f"New file detected: {os.path.basename(event.src_path)}")
            if self.alert_queue:
                self.alert_queue.put("New file created")

    def on_modified(self, event):
        if event.is_directory:
            return
        file_path = normalize_path(event.src_path)
        if os.path.basename(file_path) in [HASH_DB_FILE, HONEYPOT_FILE]:
            return
        new_hash = calculate_hash(file_path)
        old_hash = self.baseline_hashes.get(file_path)

        if old_hash and new_hash != old_hash:
            print(f"⚠️ File changed: {file_path}")
            self.baseline_hashes[file_path] = new_hash
            log_suspicious_activity(f"Modified: {file_path}")
            notify_user(f"File modified: {os.path.basename(file_path)}")
            self.change_times.append(time.time())
            self.detect_mass_changes()
            if self.alert_queue:
                self.alert_queue.put("File modified")

    def on_deleted(self, event):
        if not event.is_directory:
            print(f"[Deleted] {event.src_path}")
            log_suspicious_activity(f"Deleted: {event.src_path}")
            notify_user(f"File deleted: {os.path.basename(event.src_path)}")
            if self.alert_queue:
                self.alert_queue.put("File deleted")

    def detect_mass_changes(self):
        now = time.time()
        self.change_times = [t for t in self.change_times if now - t < 10]
        if len(self.change_times) > 5:
            alert = "🚨 MASS FILE CHANGES DETECTED! Possible ransomware activity!"
            print(alert)
            log_suspicious_activity(alert)
            notify_user(alert)
            if self.alert_queue:
                self.alert_queue.put("Mass file changes detected")

def start_real_time_monitor(path, alert_queue=None):
    try:
        with open(HASH_DB_FILE, "r") as f:
            baseline_hashes = json.load(f)
    except FileNotFoundError:
        print("❌ Baseline not found. Please run option 1 first.")
        notify_user("Baseline missing. Please create one first.")
        return

    event_handler = RealTimeMonitor(baseline_hashes, alert_queue)
    observer = Observer()
    observer.schedule(event_handler, path=path, recursive=True)
    observer.start()
    print(f"\n👁️ Real-time monitoring started on: {path}")
    notify_user("Real-time monitoring started.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def monitor_processes_sustained(threshold=10, window_seconds=30, repeat_limit=3, check_interval=5, alert_queue=None):
    print(f"\n🔎 Monitoring for processes with sustained CPU > {threshold}%...")
    high_cpu_times = defaultdict(deque)
    last_status_time = 0
    status_interval = 10

    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    try:
        while True:
            now = time.time()
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    cpu = proc.cpu_percent(interval=0.1)

                    pid = proc.pid
                    name = proc.name()
                    if cpu > threshold and pid != 0 and name != "System Idle Process":
                        times = high_cpu_times[pid]
                        times.append(now)
                        while times and now - times[0] > window_seconds:
                            times.popleft()
                        if len(times) >= repeat_limit:
                            message = f"🚨 High sustained CPU: {name} (PID: {pid}) - {cpu:.2f}%"
                            print(message)
                            log_suspicious_activity(message)
                            notify_user(message)
                            if alert_queue:
                                alert_queue.put(message)
                            times.clear()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if now - last_status_time > status_interval:
                print("⏳ Monitoring... no threats yet.")
                last_status_time = now

            time.sleep(check_interval)

    except KeyboardInterrupt:
        print("\n⛔ Monitoring stopped by user.")

def main_menu(alert_queue=None):
    folder_to_monitor = os.getcwd()

    while True:
        print("\n===== 🔐 SecureVault: Ransomware Detection System =====")
        print("1. Create Baseline Hashes")
        print("2. Check for Changes (Manual Scan)")
        print("3. Create Honeypot File")
        print("4. Start Real-Time File Monitoring")
        print("5. Start Suspicious Process Monitoring (CPU)")
        print("6. Launch GUI Dashboard")
        print("0. Exit")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            create_baseline(folder_to_monitor)
        elif choice == "2":
            check_for_changes()
        elif choice == "3":
            create_honeypot()
        elif choice == "4":
            print("Starting real-time monitor (press Ctrl+C to stop)...")
            start_real_time_monitor(folder_to_monitor, alert_queue)
        elif choice == "5":
            print("Starting suspicious process monitor (press Ctrl+C to stop)...")
        elif choice =="6":
            print("Launching GUI Dashboard...")
            launch_gui()
            monitor_processes_sustained(alert_queue=alert_queue)
        elif choice == "0":
            print("Exiting SecureVault.")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    # For standalone run, no queue passed
    main_menu()
