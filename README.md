# 🛡️ Smart USB Guardian

### Intelligent Lost Pendrive Tracking & Secure Recovery System

**Smart USB Guardian** is a comprehensive Python-based cybersecurity tracking and recovery suite. It consists of a Windows background monitoring agent, a secure SQLite database, automated email/Telegram alert systems, and a high-performance, dark-themed PyQt6 administrative dashboard.

The system allows you to **register** and **provision** USB flash drives. When a lost, registered USB drive is connected to any machine running the Smart USB Guardian Agent, it silently gathers system forensic data, resolves geographical coordinates based on the public IP address, logs connection history, and immediately dispatches alerts (with Google Maps location) to the device owner's email and Telegram channel.

---

## 🚀 Key Features

1. **Intelligent Hardware Monitoring**: Lightweight thread polling Windows WMI API for removable disk mount/unmount triggers.
2. **Dynamic Provisioning**: Embeds a hidden, cryptographically signed metadata signature file (`.usb_guardian.json`) and a visible text recovery notice (`README_RECOVERY.txt`) on the USB drives.
3. **Forensic Telemetry**: Collects Host Computer Name, Active Username, Local IP, MAC Address, OS release version, CPU Specifications, RAM Capacity, and Timezone.
4. **Geolocation Resolution**: Automatic geo-tracking via public IP, querying latitude, longitude, country, state, and city with direct Google Maps integration.
5. **Multi-Channel Alert Dispatch**: Async email (SMTP) and Telegram Bot API alert delivery.
6. **Vibrant Analytics Dashboard**: Built using PyQt6, featuring custom dark-mode styling, Matplotlib activity timelines, registered device lists, interactive location maps (Folium), and logs explorer.
7. **Confidential Reporting**: Generates forensic PDF reports with embedded graphs (using ReportLab) and CSV spreadsheet exports.
8. **Hardware-Bound Security**: Encrypts settings (such as mail credentials and Telegram tokens) using AES-256 (Fernet) bound to the machine's motherboard BIOS UUID, further wrapped in the Windows Data Protection API (DPAPI).

---

## 📂 Project Structure

```
SmartUSBGuardian/
├── Agent/
│   ├── agent_service.py       # Main background agent service loop
│   ├── info_collector.py      # System forensics & IP geolocation logic
│   └── startup_manager.py     # Registry key autostart manager
├── Config/
│   ├── config_manager.py      # Reads/writes encrypted settings
│   └── settings.enc           # Secure encrypted configurations file
├── Dashboard/
│   ├── app.py                 # PyQt6 main login & sidebar window UI
│   ├── styles.py              # CSS/QSS premium styling theme
│   └── views/
│       ├── dashboard_view.py  # Live metrics overview & canvas graph
│       ├── devices_view.py    # Auto-fill detection & provisioning
│       ├── logs_view.py       # Historical database event search tabs
│       ├── map_view.py        # Geolocation log tables & Folium map launch
│       ├── reports_view.py    # PDF report and CSV spreadsheet exporter UI
│       └── settings_view.py   # Secure SMTP/Telegram configurations
├── Database/
│   ├── db_manager.py          # SQLite connections, schemas, and queries
│   └── guardian.db            # Local security event database file
├── Email/
│   ├── email_sender.py        # SMTP client & premium HTML mail renderer
│   └── telegram_sender.py     # Telegram Bot API client wrapper
├── Encryption/
│   └── crypto_helper.py       # Motherboard UUID key derivation & DPAPI layer
├── Reports/
│   └── report_generator.py    # ReportLab PDF compilation & CSV writer
├── main.py                    # Unified entry point launcher
└── requirements.txt           # Python dependency specifications
```

---

## 🛠️ Setup & Installation

### 1. Prerequisites
- **Operating System**: Windows 10/11
- **Python**: version 3.8 to 3.12 (Ensure Python is added to your system `PATH`)

### 2. Install Dependencies
Run a Command Prompt or PowerShell as Administrator and run:
```bash
pip install -r requirements.txt
```
*Note: Dependecies include `PyQt6`, `psutil`, `pywin32`, `wmi`, `requests`, `geopy`, `cryptography`, `matplotlib`, `folium`, and `reportlab`.*

---

## 🏁 How to Run

The system is launched via the unified script entry point `main.py`.

### 1. Start the Graphical Dashboard
To launch the admin portal dashboard:
```bash
python main.py
```
- **Default Authentication**: Log in with:
  - **Username**: `admin`
  - **Password**: `admin`
- *You can update the administrator password in the **System Settings** tab inside the dashboard.*

### 2. Run the Background Agent (CLI Mode)
To run the background USB monitoring agent process without the GUI:
```bash
python main.py --agent
```

### 3. Register Startup Autostart
To make the background agent start automatically when Windows boots up (without showing terminal console popups):
```bash
python main.py --register-startup
```
To remove the registry startup key:
```bash
python main.py --unregister-startup
```
To query current registry registration state:
```bash
python main.py --status
```

---

## 🛡️ Usage Instructions

1. **Configure Notifications**: Go to **System Settings** in the dashboard and set up your SMTP email settings (e.g. Gmail App Password) and Telegram Bot token + Chat ID. Click **Send Test Email** / **Send Test Telegram** to verify, and then click **Save Settings Configurations**.
2. **Provision a USB Drive**:
   - Insert a USB flash drive.
   - Go to **Registered Devices** view.
   - Select the drive in the **Detect USB Drive** dropdown and click **Detect & Auto-Fill**.
   - Input the Owner Name, Owner Email, and emergency details.
   - Click **Provision & Register**. This registers the serial in the DB and places a hidden tracking configuration `.usb_guardian.json` and a visible `README_RECOVERY.txt` on the USB.
3. **Monitor Insertions**: Keep the agent running (either via the **Start Agent** button on the dashboard main view or by running `python main.py --agent`). When that USB is connected to any machine running the agent, forensic logs are written and instant notifications are sent!
