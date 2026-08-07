# 🛡️ USB-Sentry – Intelligent USB Security & Data Loss Prevention System

> A comprehensive cybersecurity tracking, monitoring, and data loss prevention suite for USB storage devices.

**USB-Sentry** is an advanced Python-based endpoint security and device tracking solution. It provides real-time monitoring of USB storage devices, forensic data collection upon insertion, public IP geolocation tracking, multi-channel alerting (Email & Telegram), and an interactive administrative dashboard.

---

## 🎯 Overview & Key Features

1. **Real-Time USB Hardware Monitoring**: Automatically detects removable USB storage device insertions and removals using Windows WMI APIs.
2. **Device Provisioning & Digital Fingerprinting**: Provision USB drives with cryptographically signed metadata signatures (`.usb_guardian.json`) and visible recovery instructions (`README_RECOVERY.txt`).
3. **Forensic Telemetry Gathering**: Collects detailed machine data upon USB connection:
   - System Hostname & Active Logged-in Username
   - Network Data: Local IP, MAC Address, Public IP Address
   - System Specs: OS Version, CPU Specifications, RAM Capacity, Timezone
4. **Geolocation Resolution**: Resolves public IP addresses to geographical coordinates (Latitude, Longitude, Country, City) and generates instant Google Maps links.
5. **Multi-Channel Alert Dispatch**: Sends automated real-time alerts via:
   - **SMTP Email**: Formatted HTML security reports with system & geolocation details.
   - **Telegram Bot API**: Direct push notifications to designated Telegram channels or users.
6. **Administrative Control Dashboard**: Built with PyQt6, featuring a modern dark theme, real-time analytics graphs, device inventory management, interactive geographical maps (Folium), and searchable log history.
7. **Forensic Reporting & Export**: Generates PDF reports complete with embedded charts (ReportLab) and CSV spreadsheet data exports.
8. **Hardware-Bound Configuration Security**: Encrypts sensitive configuration data (email credentials, Telegram bot tokens) using AES-256 (Fernet) tied to the host's motherboard BIOS UUID and Windows DPAPI.

---

## 📂 Repository Structure

```
USB-Sentry/
├── Agent/
│   ├── agent_service.py       # Background monitoring loop & trigger handler
│   ├── info_collector.py      # System forensics & IP geolocation retriever
│   └── startup_manager.py     # Windows Registry autostart installer
├── Config/
│   ├── config_manager.py      # Encrypted settings reader & writer
│   └── settings.enc           # AES-256 encrypted configuration file
├── Dashboard/
│   ├── app.py                 # Main PyQt6 graphical portal launcher
│   ├── styles.py              # Dark theme CSS/QSS styling definitions
│   └── views/
│       ├── dashboard_view.py  # System overview metrics & activity graphs
│       ├── devices_view.py    # USB drive detection, auto-fill & provisioning
│       ├── logs_view.py       # Filterable event log tables
│       ├── map_view.py        # Geolocation telemetry & interactive maps
│       ├── reports_view.py    # PDF & CSV forensic exporter UI
│       ├── unknown_devices.py # Unregistered USB detection & stats
│       └── settings_view.py   # Admin credentials, SMTP & Telegram config
├── Database/
│   ├── db_manager.py          # SQLite database schema & operations
│   └── guardian.db            # Local event & device database
├── Email/
│   ├── email_sender.py        # HTML email template generator & SMTP client
│   └── telegram_sender.py     # Telegram Bot API notification engine
├── Encryption/
│   └── crypto_helper.py       # Key derivation using motherboard UUID & DPAPI
├── Reports/
│   └── report_generator.py    # ReportLab PDF compilation & CSV export logic
├── USBMonitor/
│   └── monitor.py             # WMI removable storage event listener
├── Launch Guardian.bat        # Quick-start batch file launcher
├── main.py                    # Unified CLI & GUI entry point
└── requirements.txt           # Required Python packages
```

---

## 🛠️ Step-by-Step Installation Guide

### Prerequisites
- **Operating System**: Windows 10 or Windows 11
- **Python Version**: Python 3.8 to 3.12 installed (Make sure to check **"Add Python to PATH"** during installation)
- **Administrator Access**: Required for registry autostart configuration and WMI device monitoring.

### 1. Clone or Download the Repository
```bash
git clone https://github.com/Amangit4149/USB-Sentry.git
cd USB-Sentry
```

### 2. Set Up a Virtual Environment (Optional but Recommended)
```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies
Run the following command to install all required libraries:
```bash
pip install -r requirements.txt
```

---

## 🚀 How to Use USB-Sentry

USB-Sentry can be run in two primary modes: **Graphical Dashboard Mode** and **Background Agent Mode**.

### Mode 1: Graphical Dashboard (Admin Portal)
To launch the full interactive administration dashboard:

```bash
python main.py
```
*(Or double-click `Launch Guardian.bat`)*

**Default Admin Credentials**:
- **Username**: `admin`
- **Password**: `admin`

*(Note: You can change the password at any time in **System Settings** inside the dashboard.)*

---

### Mode 2: System Settings Setup (First-Time Setup)

Before deploying agents or provisioning USB drives:
1. Open the **Dashboard** (`python main.py`).
2. Navigate to **System Settings**.
3. Configure your notification channels:
   - **SMTP Email Config**: Enter SMTP Host (e.g. `smtp.gmail.com`), Port (`587`), Sender Email, and App Password.
   - **Telegram Config**: Enter your Telegram Bot Token and Chat ID.
4. Click **Send Test Email** and **Send Test Telegram** to confirm your settings are working.
5. Click **Save Settings Configurations**.

---

### Mode 3: Provisioning & Registering a USB Drive

To register and fingerprint a USB drive for tracking:
1. Plug the USB flash drive into your computer.
2. Open the **Dashboard** and go to **Registered Devices**.
3. Select your drive letter from the dropdown and click **Detect & Auto-Fill**.
4. Fill in the Owner Name, Owner Email, and contact details.
5. Click **Provision & Register**.
   - *USB-Sentry will register the device serial in the database, write a hidden cryptographic signature (`.usb_guardian.json`), and create a visible recovery notice (`README_RECOVERY.txt`) on the drive.*

---

### Mode 4: Running the Background Monitoring Agent

The background agent monitors all USB insertions, collects forensic data, and triggers alerts automatically.

#### A. Run Agent via Dashboard
Click the **Start Agent** button on the top-right header of the Dashboard.

#### B. Run Agent via Command Line
```bash
python main.py --agent
```

#### C. Register Agent as Windows Startup Program
To make the agent run automatically in the background every time Windows boots up:
```bash
# Register for automatic Windows startup
python main.py --register-startup

# Check current autostart status
python main.py --status

# Remove from Windows startup
python main.py --unregister-startup
```

---

## 📊 Reports & Data Export

- **PDF Reports**: Navigate to the **Reports** tab in the dashboard to generate comprehensive PDF security summaries with charts.
- **CSV Data Export**: Export logs and event records directly to CSV files for further analysis.

---

## 🔒 Security & Privacy

All sensitive credentials stored by USB-Sentry are encrypted using **AES-256 encryption** with keys derived from the host computer's motherboard BIOS UUID and protected via the Windows **Data Protection API (DPAPI)**. Encrypted settings files cannot be decrypted on a different machine.

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more details.
