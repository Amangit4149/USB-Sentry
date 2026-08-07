import os
import base64
import platform
import subprocess
import hashlib
from cryptography.fernet import Fernet

# Try to import win32crypt for DPAPI
try:
    import win32crypt
    HAS_DPAPI = True
except ImportError:
    HAS_DPAPI = False

class CryptoHelper:
    @staticmethod
    def get_machine_uuid():
        """Get a unique machine fingerprint on Windows or platforms."""
        try:
            if platform.system() == "Windows":
                # 1. Try reading the Cryptography MachineGuid registry key (highly reliable & fast)
                try:
                    import winreg
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
                    guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                    if guid:
                        return guid.strip()
                except Exception:
                    pass

                # 2. Try modern PowerShell query as fallback
                try:
                    output = subprocess.check_output(
                        "powershell -Command \"(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID\"",
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
        
        # Fallback to combining node name, processor, and system details
        fallback = f"{platform.node()}-{platform.processor()}-{platform.machine()}"
        return fallback

    @classmethod
    def get_derived_key(cls):
        """Derive a secure 32-byte key from the machine UUID for Fernet."""
        fingerprint = cls.get_machine_uuid()
        # Use SHA-256 to hash the fingerprint to a standard 32-byte key
        key_bytes = hashlib.sha256(fingerprint.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(key_bytes)

    @classmethod
    def encrypt_data(cls, plaintext: str) -> str:
        """
        Encrypt data securely.
        Uses DPAPI (if available) to tie encryption to the Windows User account,
        then wraps it in Fernet (AES-128 in CBC mode with HMAC-SHA256) keyed by the machine fingerprint.
        """
        if not plaintext:
            return ""
        
        try:
            # 1. First encrypt using Fernet with machine-bound key
            key = cls.get_derived_key()
            fernet = Fernet(key)
            fernet_encrypted = fernet.encrypt(plaintext.encode("utf-8"))
            
            # 2. Then encrypt with Windows DPAPI if available
            if HAS_DPAPI:
                dpapi_encrypted = win32crypt.CryptProtectData(
                    fernet_encrypted, 
                    "SmartUSBGuardianConfig", 
                    None, 
                    None, 
                    None, 
                    0
                )
                return base64.b64encode(dpapi_encrypted).decode("utf-8")
            else:
                return base64.b64encode(fernet_encrypted).decode("utf-8")
        except Exception as e:
            print(f"Encryption error: {e}")
            raise

    @classmethod
    def decrypt_data(cls, ciphertext: str) -> str:
        """
        Decrypt data securely.
        Undoes DPAPI protection, then decrypts with the machine-bound Fernet key.
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
                    # If DPAPI fails (e.g., config copied to another machine/user),
                    # we do not want to fallback silently to just Fernet, we raise the error.
                    raise ValueError("DPAPI decryption failed. This configuration belongs to another system or user account.") from dpapi_err
            else:
                fernet_encrypted = raw_data
            
            # 2. Decrypt with Fernet machine-bound key
            key = cls.get_derived_key()
            fernet = Fernet(key)
            decrypted_bytes = fernet.decrypt(fernet_encrypted)
            return decrypted_bytes.decode("utf-8")
        except Exception as e:
            print(f"Decryption error: {e}")
            raise ValueError("Failed to decrypt settings. The key or environment is incorrect.") from e
