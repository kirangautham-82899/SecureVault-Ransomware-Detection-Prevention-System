# 🔐 SecureVault - Ransomware Detection & Prevention System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![GUI](https://img.shields.io/badge/GUI-PyQt6-41cd52)
![Status](https://img.shields.io/badge/Status-Active-success)

*A lightweight, real-time file integrity monitoring and heuristic analysis tool designed to detect and alert on ransomware-like activity.*

</div>

---

## 📖 Overview

**SecureVault** protects a folder of your choice from unauthorized encryption and modification. It combines file integrity monitoring (FIM) with behavioral heuristics to give you an early warning of ransomware activity.

It records a "known-good" SHA-256 baseline of your files, watches them in real time, plants a decoy (honeypot) file that no legitimate program should touch, and flags processes with sustained high CPU usage.

## ✨ Key Features

- **🛡️ File Integrity Monitoring**: SHA-256 baseline of the protected folder. Integrity scans report modified, deleted and new files.
- **👁️ Real-Time Watcher**: Live file system events via `watchdog`, including renames.
- **🔒 Ransomware Heuristics**: Critical alerts for files renamed to known ransomware extensions (`.locked`, `.encrypted`, `.wncry`, ...) and for bursts of mass file changes.
- **🧲 Honeypot Deception**: A decoy file in the protected folder. Modifying, renaming or deleting it raises a critical alert.
- **⚙️ Process Heuristics**: Flags processes with sustained high CPU usage (normalized across cores).
- **🖥️ Modern Dashboard**: Dark PyQt6 dashboard with live status, stat cards, a CPU graph, a searchable and filterable activity feed, toast notifications and system tray support.
- **📊 Evidence Reports**: Exports a self-contained HTML report of every event in the session.

## 🚀 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/kirangautham-82899/SecureVault-Ransomware-Detection-Prevention-System.git
   cd SecureVault-Ransomware-Detection-Prevention-System
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the dashboard**
   ```bash
   python main.py --gui
   ```
   Or start the command-line menu with `python main.py`.

## 🛠️ Usage

### GUI Dashboard
1. **Change folder...**: pick the folder you want to protect (defaults to your home folder).
2. **Create baseline**: hash every file to record its known-good state.
3. **Deploy honeypot**: drop the decoy file into the protected folder.
4. **Live protection**: switch on the real-time file monitor and, if you like, the process monitor.
5. Use **Run integrity scan** at any time to compare the folder against the baseline.

Critical alerts turn the header status red. Click the status pill to acknowledge an alert. Double-click an event to open its folder, and use **Export report** to save an HTML evidence report. While a monitor is running, closing the window keeps SecureVault protecting from the system tray.

### CLI Mode
```
1. Create Baseline Hashes        5. Start Suspicious Process Monitoring (CPU)
2. Check for Changes             6. Launch GUI Dashboard
3. Create Honeypot File          7. Change Folder
4. Start Real-Time Monitoring    0. Exit
```
The CLI works on the current directory by default. Press `Ctrl+C` to stop a monitor.

### Tests
```bash
python -m pytest tests
```

## 📂 Project Structure

| Path | Purpose |
| --- | --- |
| `main.py` | Detection engine (baseline, scan, honeypot, real-time and process monitors) and CLI |
| `gui/main_gui.py` | Dashboard window, log viewer and report export |
| `gui/widgets.py` | Custom widgets: toggle switch, stat cards, CPU graph, toasts, icons |
| `gui/theme.py` | Colour palette and application stylesheet |
| `gui/splash.py` | Startup splash screen |
| `tests/` | Unit tests for the engine |
| `hash_db.json` | Baseline database, created next to `main.py` (not in repo) |
| `suspicious_activity.log` | Activity log, created next to `main.py` (not in repo) |

## ⚠️ Disclaimer

**SecureVault is a proof-of-concept security tool.** It is not a replacement for enterprise-grade antivirus or anti-ransomware solutions. Use it to augment your security posture and for educational purposes.

---
*Created by Kiran*
