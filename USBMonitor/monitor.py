import os
import re
import json
import hmac
import hashlib
import threading
import time
import secrets
import sys

# WMI import with diagnostic feedback
try:
    import wmi
    _WMI_AVAILABLE = True
except ImportError:
    wmi = None
    _WMI_AVAILABLE = False
    print("⚠️  WARNING: 'wmi' Python module not installed. USB monitoring requires it.")
    print("   Install with: pip install wmi pywin32")
except Exception as e:
    wmi = None
    _WMI_AVAILABLE = False
    print(f"⚠️  WARNING: 'wmi' module failed to load: {e}")

# pythoncom import check (required for WMI in non-main threads)
try:
    import pythoncom
    _PYTHONCOM_AVAILABLE = True
except ImportError:
    pythoncom = None
    _PYTHONCOM_AVAILABLE = False
    print("⚠️  WARNING: 'pythoncom' (pywin32) not installed. WMI thread support requires it.")
    print("   Install with: pip install pywin32")
except Exception:
    pythoncom = None
    _PYTHONCOM_AVAILABLE = False

from Config.paths import get_signing_key_path

def get_signing_key() -> bytes:
    """
    Retrieves or generates an independent per-user, per-installation 32-byte signing key.
    Stored securely in the user's isolated data directory (%LOCALAPPDATA%\\\\USB-Sentry\\\\signing.key).
    """
    key_file = get_signing_key_path()
    try:
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                key = f.read().strip()
                if len(key) >= 16:
                    return key
        # Generate new cryptographically secure 32-byte key
        new_key = secrets.token_bytes(32)
        os.makedirs(os.path.dirname(os.path.abspath(key_file)), exist_ok=True)
        with open(key_file, "wb") as f:
            f.write(new_key)
        return new_key
    except Exception:
        import getpass
        fingerprint = f"USBSentry-SigningKey::{getpass.getuser()}::{os.environ.get('COMPUTERNAME', '')}"
        return hashlib.sha256(fingerprint.encode("utf-8")).digest()

# Module-level variable for backwards compatibility
SIGNING_KEY = get_signing_key()

class USBMonitor(threading.Thread):
    def __init__(self, insertion_callback=None, removal_callback=None):
        super().__init__()
        self.daemon = True
        self.insertion_callback = insertion_callback
        self.removal_callback = removal_callback
        self.running = False
        self._wmi_conn = None

    @staticmethod
    def clean_serial(serial: str) -> str:
        """Cleans and standardizes the hardware serial number from WMI."""
        if not serial:
            return ""
        # Remove trailing/leading spaces and common suffix/prefix garbage
        serial = serial.strip()
        # Some WMI queries return serials in hex format or with trailing '&0'
        if '&' in serial:
            serial = serial.split('&')[0]
        # Remove non-alphanumeric chars
        serial = re.sub(r'[^A-Za-z0-9]', '', serial)
        return serial.upper()

    @staticmethod
    def get_vid_pid_from_pnp(pnp_id: str) -> tuple:
        """Parses vendor and product ID from WMI PNPDeviceID string."""
        if not pnp_id:
            return "Unknown", "Unknown"
        
        vid_match = re.search(r'VID_([0-9A-Fa-f]{4})', pnp_id, re.IGNORECASE)
        pid_match = re.search(r'PID_([0-9A-Fa-f]{4})', pnp_id, re.IGNORECASE)
        
        if vid_match and pid_match:
            return vid_match.group(1).upper(), pid_match.group(1).upper()
            
        # Standard USBSTOR PNP format: USBSTOR\DISK&VEN_SANDISK&PROD_CRUZER_GLIDE&REV_1.00\4C53000...
        # We can try to look up parent USB device using WMI to find real VID/PID
        if not _WMI_AVAILABLE or wmi is None:
            return "Unknown", "Unknown"
        try:
            c = wmi.WMI()
            parts = pnp_id.split('\\')
            if len(parts) >= 3:
                serial_part = parts[-1].split('&')[0]
                # Query USB entities
                for device in c.Win32_PnPEntity():
                    dev_id = device.DeviceID or ""
                    if serial_part in dev_id and "USB" in dev_id:
                        vid_m = re.search(r'VID_([0-9A-Fa-f]{4})', dev_id, re.IGNORECASE)
                        pid_m = re.search(r'PID_([0-9A-Fa-f]{4})', dev_id, re.IGNORECASE)
                        if vid_m and pid_m:
                            return vid_m.group(1).upper(), pid_m.group(1).upper()
        except Exception:
            pass
            
        return "Unknown", "Unknown"

    def _ensure_wmi_connection(self) -> bool:
        """Ensures a valid WMI connection exists. Returns True if successful."""
        if self._wmi_conn is not None:
            return True
        if not _WMI_AVAILABLE or wmi is None:
            return False
        try:
            self._wmi_conn = wmi.WMI()
            return True
        except Exception as e:
            print(f"❌ Failed to create WMI connection: {e}")
            self._wmi_conn = None
            return False

    def get_drive_details(self, drive_letter: str) -> dict:
        """Gets detailed USB device hardware info mapped from a drive letter."""
        details = {
            "drive_letter": drive_letter,
            "serial_number": "",
            "label": "Unknown",
            "manufacturer": "Generic USB Drive",
            "pid": "Unknown",
            "vid": "Unknown",
            "is_usb": False
        }
        
        if not self._ensure_wmi_connection():
            return details
        
        try:
            # Get LogicalDisk details
            logical_disks = self._wmi_conn.Win32_LogicalDisk(DeviceID=drive_letter)
            if not logical_disks:
                return details
                
            disk = logical_disks[0]
            # Check if removable drive (DriveType 2)
            if disk.DriveType != 2:
                return details
                
            details["is_usb"] = True
            details["label"] = disk.VolumeName or "Unnamed USB"
            
            # Map LogicalDisk -> Partition -> DiskDrive using associators
            partitions = self._wmi_conn.query(
                f"ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{drive_letter}'}} "
                f"WHERE AssocClass = Win32_LogicalDiskToPartition"
            )
            
            for part in partitions:
                drives = self._wmi_conn.query(
                    f"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{part.DeviceID}'}} "
                    f"WHERE AssocClass = Win32_DiskDriveToDiskPartition"
                )
                for drive in drives:
                    raw_serial = drive.SerialNumber or ""
                    details["serial_number"] = self.clean_serial(raw_serial)
                    details["manufacturer"] = drive.Model or drive.Manufacturer or "Generic"
                    
                    pnp_id = drive.PNPDeviceID or ""
                    vid, pid = self.get_vid_pid_from_pnp(pnp_id)
                    details["vid"] = vid
                    details["pid"] = pid
                    break
        except Exception as e:
            print(f"Error fetching USB details for {drive_letter}: {e}")
            # Reset WMI connection on error so it reconnects next time
            self._wmi_conn = None
            
        return details

    @staticmethod
    def verify_usb_metadata_signature(metadata: dict) -> bool:
        """Verifies if the metadata configuration on the USB drive is digitally signed and valid."""
        try:
            signature = metadata.get("signature")
            serial = metadata.get("serial_number")
            email = metadata.get("owner_email")
            
            if not signature or not serial or not email:
                return False
                
            # Recreate digest
            message = f"{serial}:{email}".encode('utf-8')
            expected_sig = hmac.new(get_signing_key(), message, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected_sig, signature)
        except Exception:
            return False

    @classmethod
    def generate_usb_metadata_signature(cls, serial: str, email: str) -> str:
        """Generates HMAC-SHA256 signature for USB configuration verification."""
        message = f"{serial}:{email}".encode('utf-8')
        return hmac.new(get_signing_key(), message, hashlib.sha256).hexdigest()

    def check_usb_for_metadata(self, drive_letter: str) -> dict:
        """Checks if a plugged USB drive contains a valid .usb_guardian.json metadata file."""
        meta_path = os.path.join(drive_letter + "\\", ".usb_guardian.json")
        if not os.path.exists(meta_path):
            return None
            
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)
                
            if self.verify_usb_metadata_signature(metadata):
                return metadata
        except Exception as e:
            print(f"Error reading USB metadata signature: {e}")
            
        return None

    def run(self):
        """Thread main loop: uses polling to detect USB mount/unmount events."""
        self.running = True
        print("=" * 60)
        print("  USB-Sentry Monitoring Engine Starting...")
        print(f"  WMI module available: {_WMI_AVAILABLE}")
        print(f"  pythoncom available:  {_PYTHONCOM_AVAILABLE}")
        print(f"  Platform:             {sys.platform}")
        print("=" * 60)
        
        # Critical check: WMI is required for USB detection on Windows
        if not _WMI_AVAILABLE or wmi is None:
            print("❌ CRITICAL: Cannot start USB monitoring without 'wmi' module!")
            print("   Install required packages: pip install wmi pywin32")
            self.running = False
            return

        # Initialize COM for this thread (required for WMI in non-main threads)
        com_initialized = False
        if _PYTHONCOM_AVAILABLE and pythoncom is not None:
            try:
                pythoncom.CoInitialize()
                com_initialized = True
                print("✅ COM initialized successfully for monitor thread.")
            except Exception as e:
                print(f"⚠️  COM initialization failed: {e}")
                print("   WMI may not work correctly in this thread.")
        else:
            print("⚠️  pythoncom not available — attempting WMI without explicit COM init.")

        try:
            # Test WMI connection before entering polling loop
            try:
                self._wmi_conn = wmi.WMI()
                print("✅ WMI connection established successfully.")
            except Exception as e:
                print(f"❌ Initial WMI connection failed: {e}")
                print("   Will retry in polling loop...")
                self._wmi_conn = None

            # Run the polling-based USB detection loop
            self._run_polling()
        except Exception as e:
            print(f"❌ USB monitoring engine crashed: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.running = False
            if com_initialized:
                try:
                    pythoncom.CoUninitialize()
                except Exception:
                    pass
            print("USB-Sentry monitoring engine stopped.")

    def _run_polling(self):
        """Poller: compares active drive letters every 2 seconds to detect insertions/removals."""
        # Build initial snapshot of currently connected removable drives
        active_drives = {}
        if self._ensure_wmi_connection():
            try:
                for disk in self._wmi_conn.Win32_LogicalDisk(DriveType=2):
                    details = self.get_drive_details(disk.DeviceID)
                    if details["is_usb"]:
                        active_drives[disk.DeviceID] = details
                        print(f"   Pre-existing USB drive: {disk.DeviceID} (Serial: {details.get('serial_number', 'N/A')})")
                if not active_drives:
                    print("   No pre-existing USB drives found.")
            except Exception as e:
                print(f"⚠️  Initial USB scan failed: {e}")
                self._wmi_conn = None
        else:
            print("⚠️  WMI not available for initial scan — will retry...")

        print("🔄 USB polling loop started (checking every 2 seconds)...")
        poll_count = 0

        while self.running:
            time.sleep(2.0)
            poll_count += 1
            
            # Ensure WMI connection is alive
            if not self._ensure_wmi_connection():
                if poll_count % 15 == 0:  # Log every 30 seconds
                    print("⚠️  WMI connection unavailable — retrying...")
                continue
            
            try:
                current_disks = self._wmi_conn.Win32_LogicalDisk(DriveType=2)
                current_drive_ids = [disk.DeviceID for disk in current_disks]
                
                # Check for insertions
                for disk in current_disks:
                    drive_id = disk.DeviceID
                    if drive_id not in active_drives:
                        # New drive detected!
                        print(f"\n🔌 New removable drive detected: {drive_id}")
                        # Wait a moment for the drive to stabilize
                        time.sleep(0.8)
                        details = self.get_drive_details(drive_id)
                        if details["is_usb"]:
                            active_drives[drive_id] = details
                            print(f"   Serial: {details.get('serial_number', 'N/A')}")
                            print(f"   Label:  {details.get('label', 'Unknown')}")
                            print(f"   Model:  {details.get('manufacturer', 'Unknown')}")
                            if self.insertion_callback:
                                try:
                                    self.insertion_callback(details)
                                except Exception as cb_err:
                                    print(f"❌ Insertion callback error: {cb_err}")
                                    import traceback
                                    traceback.print_exc()
                        else:
                            print(f"   Drive {drive_id} is not a USB removable drive (DriveType mismatch).")
                                
                # Check for removals
                removed_drives = []
                for drive_id in active_drives:
                    if drive_id not in current_drive_ids:
                        removed_drives.append(drive_id)
                        
                for drive_id in removed_drives:
                    print(f"\n⏏️  Removable drive removed: {drive_id}")
                    details = active_drives.pop(drive_id)
                    if self.removal_callback:
                        try:
                            self.removal_callback(details)
                        except Exception as cb_err:
                            print(f"❌ Removal callback error: {cb_err}")
                            import traceback
                            traceback.print_exc()
                        
            except Exception as e:
                # WMI can raise errors during system standby/resume, reset connection
                if poll_count % 15 == 0:
                    print(f"⚠️  WMI polling error: {e} — reconnecting...")
                self._wmi_conn = None
                time.sleep(2)

    def stop(self):
        self.running = False
