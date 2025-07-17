Here's a strong README file for SecureVault, without emojis:

-----

# SecureVault – Real-Time Ransomware Detection System

SecureVault is a robust, real-time ransomware detection and monitoring system developed with Python and PyQt6. It actively identifies ransomware-like behavior through a combination of advanced file monitoring, honeypot deployment, and CPU behavior analysis, aiming to prevent data damage before it occurs.

-----

## Features

### Create Baseline

Establishes a secure snapshot of your file system to detect any unauthorized modifications.

### Manual Scan

Compares current file states against the saved baseline to identify suspicious alterations.

### Honeypot Creation

Deploys decoy files designed to attract and trap ransomware, triggering immediate alerts upon access.

### Real-Time Folder Monitoring

Continuously watches critical folders for unauthorized or rapid changes indicative of ransomware activity.

### CPU & Process Tracker

Monitors system-wide CPU usage to identify and flag potentially malicious processes exhibiting high resource consumption.

### Log Viewer

A dedicated window with advanced search, save functionalities, and a user-friendly interface for comprehensive activity log viewing.

### Modern PyQt6 GUI

Features an animated splash screen, intuitive sidebar navigation, visually appealing glowing buttons, and smooth UI transitions for an enhanced user experience.

-----

## Tech Stack

  * **Language**: Python 3.x
  * **GUI**: PyQt6
  * **Monitoring**: `watchdog`, `psutil`
  * **Logging**: Built-in `logging` module
  * **UX Enhancements**: Animated splash, real-time log viewer

-----

## Project Structure

```
SecureVault/
├── gui/
│   ├── main_gui.py
│   ├── splash_screen.py
│   └── assets/
├── honeypot.py
├── monitor.py
├── baseline.py
├── process_monitor.py
├── logger.py
├── utils.py
├── main.py
└── requirements.txt
```
