import os
import socket
import uuid
import platform
import psutil
import requests
from datetime import datetime
import time

class InfoCollector:
    @staticmethod
    def get_local_ip() -> str:
        """Finds the primary local IP address by attempting an outbound connection."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # doesn't even have to be reachable, this is just to select the interface
            s.connect(('8.8.8.8', 1))
            local_ip = s.getsockname()[0]
        except Exception:
            try:
                local_ip = socket.gethostbyname(socket.gethostname())
            except Exception:
                local_ip = "127.0.0.1"
        finally:
            s.close()
        return local_ip

    @staticmethod
    def get_mac_address() -> str:
        """Gets the MAC address of the system formatted properly."""
        try:
            mac_num = uuid.getnode()
            mac_hex = f'{mac_num:012x}'
            mac_address = ':'.join(mac_hex[i:i+2] for i in range(0, 11, 2))
            return mac_address.upper()
        except Exception:
            return "00:00:00:00:00:00"

    @staticmethod
    def get_cpu_info() -> str:
        """Attempts to read a clean CPU processor name."""
        try:
            # platform.processor() can sometimes return generic values on Windows, 
            # let's try reading registry or WMI via platform if possible.
            cpu = platform.processor()
            if not cpu:
                cpu = platform.machine()
            return cpu
        except Exception:
            return "Unknown Processor"

    @staticmethod
    def get_ram_info() -> str:
        """Gets total installed physical memory in Gigabytes."""
        try:
            total_bytes = psutil.virtual_memory().total
            total_gb = total_bytes / (1024 ** 3)
            return f"{total_gb:.2f} GB"
        except Exception:
            return "Unknown RAM"

    @classmethod
    def collect_system_info(cls) -> dict:
        """Collects all local system hardware and OS forensic specifications."""
        now = datetime.now()
        
        # Determine username safely
        try:
            username = os.getlogin()
        except Exception:
            try:
                import getpass
                username = getpass.getuser()
            except Exception:
                username = os.environ.get("USERNAME", "System / Unknown User")

        info = {
            "computer_name": socket.gethostname(),
            "username": username,
            "local_ip": cls.get_local_ip(),
            "mac_address": cls.get_mac_address(),
            "os_version": f"{platform.system()} {platform.release()} (v{platform.version()})",
            "cpu_info": cls.get_cpu_info(),
            "ram_info": cls.get_ram_info(),
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
            "timezone": now.astimezone().tzname() or "UTC"
        }
        return info

    @staticmethod
    def collect_geolocation() -> dict:
        """
        Queries IP Geolocation API based on public IP.
        Uses ip-api.com as primary and ipapi.co as fallback.
        """
        geo_data = {
            "public_ip": "0.0.0.0",
            "country": "Unknown",
            "state": "Unknown",
            "city": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0,
            "maps_link": ""
        }

        # Try ip-api.com first
        try:
            response = requests.get("http://ip-api.com/json/", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    geo_data["public_ip"] = data.get("query", "0.0.0.0")
                    geo_data["country"] = data.get("country", "Unknown")
                    geo_data["state"] = data.get("regionName", "Unknown")
                    geo_data["city"] = data.get("city", "Unknown")
                    geo_data["latitude"] = data.get("lat", 0.0)
                    geo_data["longitude"] = data.get("lon", 0.0)
                    geo_data["maps_link"] = f"https://www.google.com/maps?q={geo_data['latitude']},{geo_data['longitude']}"
                    return geo_data
        except Exception as e:
            print(f"Primary Geolocation API failed: {e}")

        # Fallback to ipapi.co
        try:
            response = requests.get("https://ipapi.co/json/", timeout=5)
            if response.status_code == 200:
                data = response.json()
                geo_data["public_ip"] = data.get("ip", "0.0.0.0")
                geo_data["country"] = data.get("country_name", "Unknown")
                geo_data["state"] = data.get("region", "Unknown")
                geo_data["city"] = data.get("city", "Unknown")
                geo_data["latitude"] = data.get("latitude", 0.0)
                geo_data["longitude"] = data.get("longitude", 0.0)
                geo_data["maps_link"] = f"https://www.google.com/maps?q={geo_data['latitude']},{geo_data['longitude']}"
                return geo_data
        except Exception as e:
            print(f"Fallback Geolocation API failed: {e}")

        # If both fail, try just getting the public IP
        try:
            response = requests.get("https://api.ipify.org?format=json", timeout=3)
            if response.status_code == 200:
                geo_data["public_ip"] = response.json().get("ip", "0.0.0.0")
        except Exception:
            pass

        return geo_data

    @staticmethod
    def scan_usb_for_suspicious_files(drive_letter: str) -> list:
        """
        Scans the USB drive root and 1 level deep for suspicious files:
        - Executable scripts/binaries (.exe, .bat, .cmd, .vbs, .js, .scr, .lnk, .ps1, .inf)
        - Double extensions (e.g. document.pdf.exe)
        - Hidden files (excluding standard config files like .usb_guardian.json)
        """
        suspicious = []
        usb_path = drive_letter + "\\"
        if not os.path.exists(usb_path):
            return suspicious

        suspicious_exts = {
            '.exe', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse',
            '.wsf', '.wsh', '.msc', '.scr', '.msi', '.lnk', '.pif',
            '.ps1', '.inf'
        }

        try:
            # We scan the root and 1 level deep
            for root, dirs, files in os.walk(usb_path):
                # Calculate depth
                rel_path = os.path.relpath(root, usb_path)
                depth = 0 if rel_path == "." else len(rel_path.split(os.sep))
                if depth > 1:
                    # Prune recursion beyond 1 level deep for speed/safety
                    dirs.clear()
                    continue

                for file in files:
                    file_path = os.path.join(root, file)
                    name_lower = file.lower()
                    
                    # Ignore our own configuration and readme
                    if file in (".usb_guardian.json", "README_RECOVERY.txt"):
                        continue
                        
                    reason = None
                    _, ext = os.path.splitext(name_lower)
                    
                    # 1. Check for suspicious extension
                    if ext in suspicious_exts:
                        reason = f"Suspicious extension ({ext})"
                        
                    # 2. Check for double extension (e.g., invoice.pdf.exe)
                    elif len(name_lower.split('.')) > 2:
                        second_ext = '.' + name_lower.split('.')[-1]
                        if second_ext in suspicious_exts:
                            reason = f"Double extension ({file})"
                            
                    # 3. Check if hidden (excluding system files)
                    else:
                        try:
                            # On Windows, check hidden attribute
                            import ctypes
                            attrs = ctypes.windll.kernel32.GetFileAttributesW(file_path)
                            # FILE_ATTRIBUTE_HIDDEN = 2, FILE_ATTRIBUTE_SYSTEM = 4
                            if attrs != -1 and (attrs & 2) and not (attrs & 4):
                                reason = "Hidden file"
                        except Exception:
                            # Non-windows fallback or permission issue
                            if file.startswith('.'):
                                reason = "Hidden file"

                    if reason:
                        suspicious.append({
                            "name": file,
                            "path": file_path,
                            "reason": reason
                        })
        except Exception as e:
            print(f"Error scanning USB for suspicious files: {e}")
            
        return suspicious
