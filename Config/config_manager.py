import os
import json
from Config.paths import get_default_config_path
from Encryption.crypto_helper import CryptoHelper

class ConfigManager:
    DEFAULT_CONFIG = {
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "email_sender": "",
        "email_password": "",
        "email_receiver": "",
        "telegram_token": "",
        "telegram_chat_id": "",
        "location_api": "ip-api.com",
        "rate_limit_minutes": 15,
        "dashboard_password_hash": ""
    }

    def __init__(self, config_path=None):
        if config_path is None:
            self.config_file = get_default_config_path()
        else:
            self.config_file = config_path
            
        os.makedirs(os.path.dirname(os.path.abspath(self.config_file)), exist_ok=True)
        self.config = self.load_config()

    def load_config(self) -> dict:
        """
        Loads and decrypts configuration from the user's isolated encrypted config file.
        Safely returns default configuration if the file does not exist, is corrupted,
        or belongs to another Windows user/system.
        """
        if not os.path.exists(self.config_file):
            return self.DEFAULT_CONFIG.copy()

        try:
            with open(self.config_file, "r", encoding="utf-8") as f:
                encrypted_data = f.read().strip()
            
            if not encrypted_data:
                return self.DEFAULT_CONFIG.copy()

            decrypted_str = CryptoHelper.decrypt_data(encrypted_data)
            loaded_config = json.loads(decrypted_str)
            
            # Merge with default config to ensure all expected keys are present
            merged_config = self.DEFAULT_CONFIG.copy()
            merged_config.update(loaded_config)
            return merged_config
            
        except Exception:
            # Undecryptable (e.g. from another user or corrupted): safe fallback to defaults
            return self.DEFAULT_CONFIG.copy()

    def save_config(self) -> bool:
        """Encrypts and saves the current configuration to the user's isolated data file."""
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.config_file)), exist_ok=True)
            config_str = json.dumps(self.config)
            encrypted_str = CryptoHelper.encrypt_data(config_str)
            
            with open(self.config_file, "w", encoding="utf-8") as f:
                f.write(encrypted_str)
            return True
        except Exception as e:
            print(f"Error saving encrypted configuration: {e}")
            return False

    def get(self, key, default=None):
        return self.config.get(key, default)

    def set(self, key, value):
        self.config[key] = value
        self.save_config()
