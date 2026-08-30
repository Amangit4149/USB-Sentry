import os
import time
from Database.db_manager import DBManager
from Config.config_manager import ConfigManager
from Email.email_sender import EmailSender
from Email.telegram_sender import TelegramSender
from USBMonitor.monitor import USBMonitor
from USBMonitor.file_watcher import USBFileWatcher
from Agent.info_collector import InfoCollector

class AgentService:
    def __init__(self, db_path=None, config_path=None):
        self.db = DBManager(db_path)
        self.config = ConfigManager(config_path)
        self.email_sender = EmailSender(self.config, self.db)
        self.telegram_sender = TelegramSender(self.config, self.db)
        self.file_watcher = USBFileWatcher(self.db)
        
        self.monitor = None
        self.active = False

    def on_usb_inserted(self, device_details: dict):
        """Callback triggered when any USB device is mounted on the system."""
        drive_letter = device_details.get("drive_letter")
        serial = device_details.get("serial_number")
        
        if not serial:
            print(f"USB drive detected at {drive_letter} but hardware serial number is unreadable.")
            return

        print(f"USB Device Inserted: {device_details['manufacturer']} on {drive_letter} (Serial: {serial})")
        
        # 1. Check if registered in local database
        usb_info = self.db.get_usb_by_serial(serial)
        
        # 2. If not registered locally, check if provisioned with metadata file on the USB root
        if not usb_info:
            print(f"USB {serial} not registered in local database. Scanning filesystem for tracking credentials...")
            metadata = self.monitor.check_usb_for_metadata(drive_letter)
            if metadata:
                print("Valid digitally signed tracking metadata found on drive! Auto-registering device...")
                success = self.db.register_usb(
                    serial_number=metadata["serial_number"],
                    label=metadata.get("label", "Restored USB"),
                    manufacturer=device_details.get("manufacturer", "Generic USB"),
                    pid=device_details.get("pid", "Unknown"),
                    vid=device_details.get("vid", "Unknown"),
                    owner_name=metadata.get("owner_name", "Unknown Owner"),
                    owner_email=metadata.get("owner_email", ""),
                    emergency_contact=metadata.get("emergency_contact", ""),
                    secret_key=""
                )
                if success:
                    usb_info = self.db.get_usb_by_serial(serial)
            else:
                # ── UNKNOWN DEVICE: detect, log, scan, and alert ──────────────
                print(f"⚠️  UNKNOWN USB DEVICE detected: {serial} — logging and alerting!")
                sys_info = InfoCollector.collect_system_info()
                geo_info = InfoCollector.collect_geolocation()
                suspicious_files = InfoCollector.scan_usb_for_suspicious_files(drive_letter) if drive_letter else []
                import json
                susp_json = json.dumps(suspicious_files) if suspicious_files else None
                self.db.log_unknown_device(
                    serial_number=serial,
                    manufacturer=device_details.get("manufacturer", "Unknown"),
                    vid=device_details.get("vid", "Unknown"),
                    pid=device_details.get("pid", "Unknown"),
                    drive_letter=drive_letter or "—",
                    computer_name=sys_info["computer_name"],
                    username=sys_info["username"],
                    local_ip=sys_info["local_ip"],
                    public_ip=geo_info["public_ip"],
                    mac_address=sys_info["mac_address"],
                    os_version=sys_info["os_version"],
                    suspicious_files=susp_json,
                )
                # Build a synthetic usb_info-like dict for alert dispatchers
                unknown_usb_info = {
                    "serial_number": serial,
                    "label": "⚠️ UNREGISTERED USB",
                    "manufacturer": device_details.get("manufacturer", "Unknown"),
                    "owner_name": "—",
                    "owner_email": self.config.get("email_receiver", ""),
                }
                sys_info["suspicious_files"] = suspicious_files
                # Dispatch email / telegram for unknown device
                self.email_sender.send_unknown_device_alert(unknown_usb_info, sys_info, geo_info, device_details)
                if self.config.get("telegram_token") and self.config.get("telegram_chat_id"):
                    self.telegram_sender.send_alert(unknown_usb_info, sys_info, geo_info)
                return

        # Double check we now have device profile details
        if not usb_info:
            return

        # 3. Collect Forensic Indicators
        print("Gathering host system forensic information...")
        sys_info = InfoCollector.collect_system_info()
        
        print("Resolving public IP Geolocation...")
        geo_info = InfoCollector.collect_geolocation()

        # 3b. Scan USB for suspicious files
        print(f"Scanning USB drive {drive_letter} for suspicious files...")
        suspicious_files = InfoCollector.scan_usb_for_suspicious_files(drive_letter)
        if suspicious_files:
            print(f"⚠️  {len(suspicious_files)} suspicious file(s) detected on USB!")
            for f in suspicious_files:
                print(f"   • {f['name']} — {f['reason']}")
        else:
            print("✅ No suspicious files detected on USB drive.")
        sys_info["suspicious_files"] = suspicious_files
        
        # 4. Save Logs locally in SQLite
        import json
        susp_json = json.dumps(suspicious_files) if suspicious_files else None
        log_id = self.db.log_device_event(
            usb_serial=serial,
            event_type="INSERTION",
            computer_name=sys_info["computer_name"],
            username=sys_info["username"],
            local_ip=sys_info["local_ip"],
            public_ip=geo_info["public_ip"],
            mac_address=sys_info["mac_address"],
            os_version=sys_info["os_version"],
            cpu_info=sys_info["cpu_info"],
            ram_info=sys_info["ram_info"],
            suspicious_files=susp_json
        )
        
        if log_id:
            print(f"Forensic event logged successfully (ID: {log_id}).")
            
        loc_id = self.db.log_location(
            usb_serial=serial,
            country=geo_info["country"],
            state=geo_info["state"],
            city=geo_info["city"],
            latitude=geo_info["latitude"],
            longitude=geo_info["longitude"],
            maps_link=geo_info["maps_link"]
        )
        if loc_id:
            print(f"Location tracking coordinate logged successfully (ID: {loc_id}).")

        # Start real-time file activity watcher on inserted USB drive
        if drive_letter:
            self.file_watcher.start_watching(drive_letter, serial)

        # 5. Dispatch Notifications
        # SMTPLib Email Dispatcher
        print("Dispatching security email alert...")
        self.email_sender.send_alert(usb_info, sys_info, geo_info)
        
        # Telegram Channel Alert Dispatcher
        if self.config.get("telegram_token") and self.config.get("telegram_chat_id"):
            print("Dispatching Telegram channel alert...")
            self.telegram_sender.send_alert(usb_info, sys_info, geo_info)

    def on_usb_removed(self, device_details: dict):
        """Callback triggered when any USB device is unmounted from the system."""
        serial = device_details.get("serial_number")
        drive_letter = device_details.get("drive_letter")
        if drive_letter:
            self.file_watcher.stop_watching(drive_letter)
        if not serial:
            return
            
        # Log event if the USB was registered
        usb_info = self.db.get_usb_by_serial(serial)
        if usb_info:
            print(f"Registered USB Device Removed: {usb_info.get('label')} (Serial: {serial})")
            sys_info = InfoCollector.collect_system_info()
            geo_info = InfoCollector.collect_geolocation() # Get IP just in case
            
            self.db.log_device_event(
                usb_serial=serial,
                event_type="REMOVAL",
                computer_name=sys_info["computer_name"],
                username=sys_info["username"],
                local_ip=sys_info["local_ip"],
                public_ip=geo_info["public_ip"],
                mac_address=sys_info["mac_address"],
                os_version=sys_info["os_version"],
                cpu_info=sys_info["cpu_info"],
                ram_info=sys_info["ram_info"]
            )

    def start(self):
        """Starts the background USB monitoring thread."""
        if not self.active:
            self.active = True
            self.monitor = USBMonitor(
                insertion_callback=self.on_usb_inserted,
                removal_callback=self.on_usb_removed
            )
            self.monitor.start()

    def stop(self):
        """Halts the background USB monitoring thread."""
        if self.active:
            self.active = False
            if self.monitor:
                self.monitor.stop()
            if hasattr(self, 'file_watcher'):
                self.file_watcher.stop_all()
            print("USB-Sentry monitoring agent stopped.")

if __name__ == "__main__":
    # Test execution
    service = AgentService()
    service.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        service.stop()
