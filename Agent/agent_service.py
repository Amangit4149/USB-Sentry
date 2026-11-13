import os
import time
import json
import traceback
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
        print(f"✅ AgentService initialized (DB: {self.db.db_path})")

    def on_usb_inserted(self, device_details: dict):
        """Callback triggered when any USB device is mounted on the system."""
        try:
            self._handle_usb_insertion(device_details)
        except Exception as e:
            print(f"❌ CRITICAL ERROR in USB insertion handler: {e}")
            traceback.print_exc()

    def _handle_usb_insertion(self, device_details: dict):
        """Internal handler for USB insertion — wrapped by on_usb_inserted for safety."""
        drive_letter = device_details.get("drive_letter")
        serial = device_details.get("serial_number")
        if drive_letter:
            self.file_watcher.start_watching(drive_letter, serial or "Unreadable serial")
        
        if not serial:
            serial = f"UNREADABLE-{drive_letter or 'UNKNOWN'}"
            print(f"USB drive detected at {drive_letter} but hardware serial number is unreadable; logging as {serial}.")

        print(f"\n{'='*50}")
        print(f"USB Device Inserted: {device_details.get('manufacturer', 'Unknown')} on {drive_letter} (Serial: {serial})")
        print(f"{'='*50}")
        
        # 1. Check if registered in local database
        usb_info = self.db.get_usb_by_serial(serial)
        
        # 2. If not registered locally, check if provisioned with metadata file on the USB root
        if not usb_info:
            print(f"USB {serial} not registered in local database. Scanning filesystem for tracking credentials...")
            metadata = (
                self.monitor.check_usb_for_metadata(drive_letter)
                if device_details.get("serial_number")
                else None
            )
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
                self._handle_unknown_device(serial, drive_letter, device_details)
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
            print(f"✅ Forensic event logged successfully (ID: {log_id}).")
        else:
            print("❌ Failed to log forensic event!")
            
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
            print(f"✅ Location tracking logged successfully (ID: {loc_id}).")

        # 5. Dispatch Notifications
        # SMTPLib Email Dispatcher
        print("Dispatching security email alert...")
        self.email_sender.send_alert(usb_info, sys_info, geo_info)
        
        # Telegram Channel Alert Dispatcher
        if self.config.get("telegram_token") and self.config.get("telegram_chat_id"):
            print("Dispatching Telegram channel alert...")
            self.telegram_sender.send_alert(usb_info, sys_info, geo_info)
        
        print(f"✅ USB insertion processing complete for {serial}.")

    def _handle_unknown_device(self, serial: str, drive_letter: str, device_details: dict):
        """Handles an unregistered/unknown USB device — logs ALL forensic data including location and file activity."""
        print(f"⚠️  UNKNOWN USB DEVICE detected: {serial} — logging and alerting!")
        
        # Collect forensic info
        sys_info = InfoCollector.collect_system_info()
        geo_info = InfoCollector.collect_geolocation()
        suspicious_files = InfoCollector.scan_usb_for_suspicious_files(drive_letter) if drive_letter else []
        
        if suspicious_files:
            print(f"⚠️  {len(suspicious_files)} suspicious file(s) detected on unknown USB!")
            for f in suspicious_files:
                print(f"   • {f['name']} — {f['reason']}")
        
        susp_json = json.dumps(suspicious_files) if suspicious_files else None
        
        # 1. Log to unknown_device_logs table
        unknown_id = self.db.log_unknown_device(
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
        if unknown_id:
            print(f"✅ Unknown device logged (ID: {unknown_id}).")
        else:
            print("❌ Failed to log unknown device event!")
        
        # 2. Also log to device_logs for the Historical Logs > Device Connection Events tab
        log_id = self.db.log_device_event(
            usb_serial=serial,
            event_type="UNKNOWN DEVICE",
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
            print(f"✅ Device event logged (ID: {log_id}).")
        
        # 3. Log geographical location for the Historical Logs > Geographical Logs tab
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
            print(f"✅ Location logged for unknown device (ID: {loc_id}).")

        # 5. Build synthetic usb_info-like dict for alert dispatchers
        unknown_usb_info = {
            "serial_number": serial,
            "label": "⚠️ UNREGISTERED USB",
            "manufacturer": device_details.get("manufacturer", "Unknown"),
            "owner_name": "—",
            "owner_email": self.config.get("email_receiver", ""),
        }
        sys_info["suspicious_files"] = suspicious_files
        
        # 6. Dispatch email / telegram alerts for unknown device
        try:
            self.email_sender.send_unknown_device_alert(unknown_usb_info, sys_info, geo_info, device_details)
        except Exception as e:
            print(f"⚠️  Email alert dispatch failed: {e}")
            
        if self.config.get("telegram_token") and self.config.get("telegram_chat_id"):
            try:
                self.telegram_sender.send_alert(unknown_usb_info, sys_info, geo_info)
            except Exception as e:
                print(f"⚠️  Telegram alert dispatch failed: {e}")
        
        print(f"✅ Unknown USB processing complete for {serial}.")

    def on_usb_removed(self, device_details: dict):
        """Callback triggered when any USB device is unmounted from the system."""
        try:
            serial = device_details.get("serial_number")
            drive_letter = device_details.get("drive_letter")
            
            # Always stop file watcher for removed drive
            if drive_letter:
                self.file_watcher.stop_watching(drive_letter)
            if not serial:
                return
                
            print(f"\n⏏️  USB Device Removed: {serial} from {drive_letter}")
            
            # Log removal event
            sys_info = InfoCollector.collect_system_info()
            geo_info = InfoCollector.collect_geolocation()
            
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
            print(f"✅ Removal event logged for {serial}.")
        except Exception as e:
            print(f"❌ Error handling USB removal: {e}")
            traceback.print_exc()

    def start(self):
        """Starts the background USB monitoring thread."""
        if not self.active:
            self.active = True
            self.monitor = USBMonitor(
                insertion_callback=self.on_usb_inserted,
                removal_callback=self.on_usb_removed
            )
            self.monitor.start()
            print("✅ USB monitoring agent started.")

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
