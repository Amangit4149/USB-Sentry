import os
import sys
import tempfile

def get_app_data_dir() -> str:
    r"""
    Returns the user-specific local application data directory.
    - Windows: %LOCALAPPDATA%\USB-Sentry (e.g., C:\Users\<Username>\AppData\Local\USB-Sentry)
    - Linux/macOS: ~/.usb-sentry
    - Supports USB_SENTRY_DATA_DIR override for testing and custom environments.
    - Gracefully falls back to system temp or workspace data if permissions are restricted.
    """
    # 1. Explicit override (e.g. for testing)
    env_dir = os.environ.get("USB_SENTRY_DATA_DIR")
    if env_dir:
        os.makedirs(env_dir, exist_ok=True)
        return env_dir

    # 2. Standard Windows / OS Application Data
    if sys.platform == "win32":
        base_dir = os.environ.get("LOCALAPPDATA")
        if not base_dir:
            base_dir = os.path.expanduser(r"~\AppData\Local")
        data_dir = os.path.join(base_dir, "USB-Sentry")
    else:
        base_dir = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
        data_dir = os.path.join(base_dir, "USB-Sentry")
    
    try:
        os.makedirs(data_dir, exist_ok=True)
        return data_dir
    except (PermissionError, OSError):
        # Fallback to user temp directory if LocalAppData creation is restricted (e.g. sandbox/CI)
        fallback_dir = os.path.join(tempfile.gettempdir(), "USB-Sentry")
        try:
            os.makedirs(fallback_dir, exist_ok=True)
            return fallback_dir
        except (PermissionError, OSError):
            # Final fallback: workspace-isolated local data folder
            root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            local_fallback = os.path.join(root_dir, ".usb_sentry_data")
            os.makedirs(local_fallback, exist_ok=True)
            return local_fallback

def get_default_db_path() -> str:
    """Returns the default user-isolated database file path."""
    return os.path.join(get_app_data_dir(), "guardian.db")

def get_default_config_path() -> str:
    """Returns the default user-isolated configuration file path."""
    return os.path.join(get_app_data_dir(), "settings.enc")

def get_signing_key_path() -> str:
    """Returns the path for the per-user cryptographic signing key."""
    return os.path.join(get_app_data_dir(), "signing.key")
