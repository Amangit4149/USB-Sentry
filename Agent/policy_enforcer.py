import os
import sys
import subprocess

class PolicyEnforcer:
    """
    Enterprise Device Control & Security Policy Enforcement Engine.
    Enforces device authorization modes:
    1. MONITOR (Audit Only - Full Read/Write with telemetry logging)
    2. READ_ONLY (Enforces system-wide USB Write Protection to prevent data theft)
    3. BLOCK_UNREGISTERED (Strict Enterprise Whitelist - blocks/alerts on unapproved drives)
    """

    POLICY_MONITOR = "MONITOR"
    POLICY_READ_ONLY = "READ_ONLY"
    POLICY_BLOCK_UNREGISTERED = "BLOCK_UNREGISTERED"

    REG_KEY = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"

    @classmethod
    def apply_system_policy(cls, mode: str) -> bool:
        """
        Applies system-level storage device access policies on Windows.
        Sets WriteProtect registry value when in READ_ONLY mode.
        """
        if sys.platform != "win32":
            return False

        try:
            import winreg
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, cls.REG_KEY, 0, winreg.KEY_SET_VALUE)
            except FileNotFoundError:
                try:
                    key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, cls.REG_KEY)
                except PermissionError:
                    # Non-admin execution
                    return False

            with key:
                if mode == cls.POLICY_READ_ONLY:
                    # Enable USB Write Protection (1 = Read Only)
                    winreg.SetValueEx(key, "WriteProtect", 0, winreg.REG_DWORD, 1)
                    print("🔒 Policy Enforcer: USB Storage Write-Protection ENABLED (Read-Only Mode).")
                else:
                    # Disable USB Write Protection (0 = Full Access)
                    try:
                        winreg.SetValueEx(key, "WriteProtect", 0, winreg.REG_DWORD, 0)
                        print("🔓 Policy Enforcer: USB Storage Full Access Restored.")
                    except Exception:
                        pass
            return True
        except Exception as e:
            # Requires elevation for HKLM write protection
            return False

    @classmethod
    def should_allow_device(cls, serial_number: str, is_registered: bool, policy_mode: str) -> tuple:
        """
        Evaluates whether a connected USB device is permitted under current policy.
        Returns: (allowed: bool, reason: str, action: str)
        """
        if policy_mode == cls.POLICY_BLOCK_UNREGISTERED and not is_registered:
            return (
                False,
                f"Unauthorized USB Device ({serial_number}) blocked under STRICT_WHITELIST enterprise policy.",
                "BLOCK_ACCESS"
            )
        
        if policy_mode == cls.POLICY_READ_ONLY:
            return (
                True,
                "Device mounted in READ_ONLY mode. File writes to USB are restricted by DLP policy.",
                "ENFORCE_READ_ONLY"
            )

        return (True, "Device authorized under standard audit policy.", "ALLOW_ACCESS")

