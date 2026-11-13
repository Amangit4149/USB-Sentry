import os
import sys

def get_app_data_dir() -> str:
    r"""
    Returns the user-specific local application data directory.
    - Windows: %LOCALAPPDATA%\USB-Sentry (e.g., C:\Users\<Username>\AppData\Local\USB-Sentry)
    - Linux/macOS: ~/.local/share/USB-Sentry
    - Supports USB_SENTRY_DATA_DIR for testing and custom environments; using the
      same override for multiple accounts intentionally shares that data directory.
    - Uses a fallback under the user's home directory if the standard path is unavailable.
      It never falls back to shared system-temp or project-workspace storage.
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
    except OSError as primary_error:
        fallback_dir = os.path.join(os.path.expanduser("~"), ".usb-sentry")
        if os.path.normcase(os.path.abspath(fallback_dir)) == os.path.normcase(os.path.abspath(data_dir)):
            raise OSError(
                f"Cannot create USB-Sentry's per-user data directory: {data_dir}"
            ) from primary_error
        try:
            os.makedirs(fallback_dir, exist_ok=True)
            return fallback_dir
        except OSError as fallback_error:
            raise OSError(
                "Cannot create USB-Sentry's per-user data directory. "
                f"Tried {data_dir} and {fallback_dir}."
            ) from fallback_error

def get_default_db_path() -> str:
    """Returns the default user-isolated database file path."""
    return os.path.join(get_app_data_dir(), "guardian.db")

def get_default_config_path() -> str:
    """Returns the default user-isolated configuration file path."""
    return os.path.join(get_app_data_dir(), "settings.enc")

def get_signing_key_path() -> str:
    """Returns the path for the per-user cryptographic signing key."""
    return os.path.join(get_app_data_dir(), "signing.key")
