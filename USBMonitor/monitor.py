import os
import re
import json
import hmac
import hashlib
import threading
import time
import secrets
try:
    import wmi
except Exception:
    wmi = None
from Config.paths import get_signing_key_path

def get_signing_key() -> bytes:
    """
    Retrieves or generates an independent per-user, per-installation 32-byte signing key.
    Stored securely in the user's isolated data directory (%LOCALAPPDATA%\\USB-Sentry\\signing.key).
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
        try:
            c = wmi.WMI()
            parts = pnp_id.split('\\')
            if len(parts) >= 3:
                serial_part = parts[-1].split('&')[0]
                # Query USB entities
                for device in c.Win32_PnPEntity(InterfaceClass="{a5fe4bf2-2801-11d0-ef88-00c04fd7d062}"):
                    dev_id = device.DeviceID or ""
                    if serial_part in dev_id:
                        vid_m = re.search(r'VID_([0-9A-Fa-f]{4})', dev_id, re.IGNORECASE)
                        pid_m = re.search(r'PID_([0-9A-Fa-f]{4})', dev_id, re.IGNORECASE)
                        if vid_m and pid_m:
                            return vid_m.group(1).upper(), pid_m.group(1).upper()
        except Exception:
            pass
            
        return "Unknown", "Unknown"

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
        
        try:
            if not self._wmi_conn:
                self._wmi_conn = wmi.WMI()
                
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
        """Thread main loop: polls or watches WMI events for USB mount/unmount."""
        self.running = True
        print("USB-Sentry monitoring engine started...")
        
        # Initialize WMI in this thread context (required for COM threads)
        pythoncom_initialized = False
        try:
            import pythoncom
            pythoncom.CoInitialize()
            pythoncom_initialized = True
        except Exception:
            pass

        try:
            self._wmi_conn = wmi.WMI()
            
            # WMI event watcher for logical disk creation (DriveType = 2 is removable)
            creation_watcher = self._wmi_conn.watch_for(
                notification_type="Creation",
                wmi_class="Win32_LogicalDisk",
                DriveType=2
            )
            
            deletion_watcher = self._wmi_conn.watch_for(
                notification_type="Deletion",
                wmi_class="Win32_LogicalDisk",
                DriveType=2
            )
            
        except Exception as e:
            print(f"Failed to start WMI event watchers: {e}. Falling back to active polling.")
            self._run_polling()
            if pythoncom_initialized:
                pythoncom.CoUninitialize()
            return

        # Event loop using WMI watcher
        while self.running:
            try:
                # We do a short timeout watch using time-sliced checks to keep thread interruptible
                # WMI watcher() blocks, so to make it interruptible we poll disk lists or run with small delays.
                # Since watcher blocks, we can check for logical drive changes using custom query matching.
                # To prevent thread lock when shutting down, we use a timeout mechanism on watcher.
                # WMI watch_for doesn't support timeout in python-wmi easily, so we can poll every 2 seconds
                # which is extremely reliable and lightweight.
                self._run_polling()
                break
            except Exception as e:
                print(f"WMI Watcher exception: {e}")
                time.sleep(2)

        if pythoncom_initialized:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass

    def _run_polling(self):
        """Poller fallback/primary: compares active drive letters to detect insertions/removals."""
        # Get initial list
        active_drives = {}
        try:
            self._wmi_conn = wmi.WMI()
            for disk in self._wmi_conn.Win32_LogicalDisk(DriveType=2):
                active_drives[disk.DeviceID] = self.get_drive_details(disk.DeviceID)
        except Exception as e:
            print(f"Initial polling scan failed: {e}")

        while self.running:
            time.sleep(2.0)
            try:
                current_disks = self._wmi_conn.Win32_LogicalDisk(DriveType=2)
                current_drive_ids = [disk.DeviceID for disk in current_disks]
                
                # Check for insertions
                for disk in current_disks:
                    drive_id = disk.DeviceID
                    if drive_id not in active_drives:
                        # Drive inserted!
                        print(f"New logical drive detected: {drive_id}")
                        # Wait a split second for mounting to stabilize
                        time.sleep(0.5)
                        details = self.get_drive_details(drive_id)
                        if details["is_usb"]:
                            active_drives[drive_id] = details
                            if self.insertion_callback:
                                self.insertion_callback(details)
                                
                # Check for removals
                removed_drives = []
                for drive_id in active_drives:
                    if drive_id not in current_drive_ids:
                        removed_drives.append(drive_id)
                        
                for drive_id in removed_drives:
                    # Drive removed!
                    print(f"Logical drive removed: {drive_id}")
                    details = active_drives.pop(drive_id)
                    if self.removal_callback:
                        self.removal_callback(details)
                        
            except Exception as e:
                # WMI can raise errors during system standby/resume, reset connection
                try:
                    self._wmi_conn = wmi.WMI()
                except Exception:
                    pass
                time.sleep(2)

    def stop(self):
        self.running = False
