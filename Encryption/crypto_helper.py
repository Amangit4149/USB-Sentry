import os
import base64
import platform
import subprocess
import hashlib
import getpass
from cryptography.fernet import Fernet

# Try to import win32crypt for Windows DPAPI
try:
    import win32crypt
    HAS_DPAPI = True
except ImportError:
    HAS_DPAPI = False

class CryptoHelper:
    @staticmethod
    def get_machine_uuid() -> str:
        """Get a unique machine fingerprint on Windows or fallback platforms."""
        try:
            if platform.system() == "Windows":
                # 1. Try reading the Cryptography MachineGuid registry key (fast and reliable)
                try:
                    import winreg
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
                    guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                    if guid:
                        return guid.strip()
                except Exception:
                    pass

                # 2. Try PowerShell CimInstance query as fallback
                try:
                    output = subprocess.check_output(
                        'powershell -Command "(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID"',
                        shell=True,
                        stderr=subprocess.DEVNULL
                    )
                    uuid_str = output.decode().strip()
                    if uuid_str and "UUID" not in uuid_str:
                        return uuid_str
                except Exception:
                    pass
        except Exception:
            pass
        
        # Fallback to combining node name, processor, and architecture
        return f"{platform.node()}-{platform.processor()}-{platform.machine()}"

    @classmethod
    def get_user_fingerprint(cls) -> str:
        """
        Derives a unique, per-user, per-system fingerprint.
        Combines machine UUID, current Windows username, and user profile directory.
        """
        machine_uuid = cls.get_machine_uuid()
        try:
            username = getpass.getuser()
        except Exception:
            username = os.environ.get("USERNAME", "default_user")
            
        user_profile = os.environ.get("USERPROFILE", "")
        return f"{machine_uuid}::{username}::{user_profile}"

    @classmethod
    def get_derived_key(cls) -> bytes:
        """Derive a secure 32-byte key from the user-specific machine fingerprint for Fernet."""
        fingerprint = cls.get_user_fingerprint()
        key_bytes = hashlib.sha256(fingerprint.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(key_bytes)

    @classmethod
    def encrypt_data(cls, plaintext: str) -> str:
        """
        Encrypt data securely.
        Uses DPAPI (if available) to bind encryption directly to the Windows User account,
        wrapped with Fernet keyed by the machine and user-specific fingerprint.
        """
        if not plaintext:
            return ""
        
        try:
            # 1. First encrypt using Fernet with machine+user bound key
            key = cls.get_derived_key()
            fernet = Fernet(key)
            fernet_encrypted = fernet.encrypt(plaintext.encode("utf-8"))
            
            # 2. Then encrypt with Windows DPAPI if available (binds to current Windows logon)
            if HAS_DPAPI:
                dpapi_encrypted = win32crypt.CryptProtectData(
                    fernet_encrypted, 
                    "USBSentryConfig", 
                    None, 
                    None, 
                    None, 
                    0
                )
                return base64.b64encode(dpapi_encrypted).decode("utf-8")
            else:
                return base64.b64encode(fernet_encrypted).decode("utf-8")
        except Exception as e:
            raise RuntimeError(f"Encryption failed: {e}") from e

    @classmethod
    def decrypt_data(cls, ciphertext: str) -> str:
        """
        Decrypt data securely.
        Undoes DPAPI protection, then decrypts with the user-bound Fernet key.
        """
        if not ciphertext:
            return ""
        
        try:
            raw_data = base64.b64decode(ciphertext.encode("utf-8"))
            
            # 1. Decrypt using Windows DPAPI if available
            if HAS_DPAPI:
                try:
                    fernet_encrypted = win32crypt.CryptUnprotectData(raw_data, None, None, None, 0)[1]
                except Exception as dpapi_err:
                    raise ValueError(
                        "DPAPI decryption failed: This configuration belongs to another system or Windows account."
                    ) from dpapi_err
            else:
                fernet_encrypted = raw_data
            
            # 2. Decrypt with Fernet user-bound key
            key = cls.get_derived_key()
            fernet = Fernet(key)
            decrypted_bytes = fernet.decrypt(fernet_encrypted)
            return decrypted_bytes.decode("utf-8")
        except Exception as e:
            raise ValueError("Failed to decrypt configuration: Key or user environment mismatch.") from e
