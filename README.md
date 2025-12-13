# 🔐 SecureVault - Ransomware Detection & Prevention System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![Status](https://img.shields.io/badge/Status-Active-success)

*A lightweight, real-time file integrity monitoring and heuristic analysis tool designed to detect and alert on ransomware-like activity.*

</div>

---

## 📖 Overview

**SecureVault** is a cybersecurity utility built to protect personal folders from unauthorized encryption and modification. By combining file integrity monitoring (FIM) with behavioral heuristics, SecureVault provides an early warning system against potential ransomware threats.

The system establishes a "known-good" baseline of your files and monitors them for unexpected changes. It also uses decoy files (honeypots) and CPU usage analysis to detect malicious processes.

## ✨ Key Features

- **🛡️ File Integrity Monitoring (FIM)**: Creates a SHA-256 hash baseline of your files to detect unauthorized modifications or deletions.
- **👁️ Real-Time Watcher**: Actively monitors file system events in real-time using `watchdog`.
- **🧲 Honeypot Deception**: Deploys "honeypot" files that, when touched, trigger immediate high-priority alerts.
- **⚙️ Heuristic Analysis**: Monitors processes for high, sustained CPU usage patterns typical of encryption activities.
- **🖥️ Modern GUI Dashboard**: A sleek, dark-themed interface for easy management and visualization of threats.
- **🚨 Instant Alerts**: Pop-up notifications and synthesized system audio alerts for critical events.
- **📊 Reporting**: Exports detailed HTML evidence reports of all suspicious activities including timestamps and file paths.

## 🚀 Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/kirangautham-82899/SecureVault-Ransomware-Detection-Prevention-System.git
    cd SecureVault-Ransomware-Detection-Prevention-System
    ```

2.  **Install Dependencies**
    Ensure you have Python installed, then run:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the Application**
    ```bash
    python main.py
    ```

## 🛠️ Usage

### CLI Mode
The application starts with a command-line menu for quick actions:
1.  **Create Baseline**: Run this first to index your files.
2.  **Manual Scan**: Perform a one-time check against your baseline.
3.  **Deploy Honeypot**: Place a trap file in the directory.
4.  **Real-Time Monitor**: Start the background watcher.
5.  **GUI Dashboard**: Launch the visual interface.

### GUI Dashboard
For the full experience, select **Option 6** in the menu to launch the GUI.
- **Scope**: Select the folder you want to protect.
- **Buttons**: Toggle monitoring and honeypots with a single click.
- **Live Graph**: Watch system CPU load in real-time.
- **Activity Feed**: View a live stream of all file system events.
- **Export**: Click "Export Evidence" to generate an HTML report of the session.

## 📂 Project Structure

- `main.py`: Core logic for monitoring, hashing, and heuristics.
- `gui/main_gui.py`: PyQt6 based graphical user interface.
- `hash_db.json`: Local database storing file hash baselines (Not in repo).
- `suspicious_activity.log`: Log file for all detected events (Not in repo).

## ⚠️ Disclaimer

**SecureVault is a Proof of Concept (PoC) security tool.**
While it provides effective detection mechanisms, it is not a replacement for enterprise-grade antivirus or anti-ransomware solutions. Use this tool to augment your security posture and for educational purposes.

---
*Created by Kiran*
