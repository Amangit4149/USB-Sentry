import os
import json
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
        "dashboard_password_hash": ""  # SHA-256 hash of password
    }

    def __init__(self, config_path=None):
        if config_path is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            self.config_file = os.path.join(current_dir, "settings.enc")
        else:
            self.config_file = config_path
            
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        self.config = self.load_config()

    def load_config(self) -> dict:
        """Loads and decrypts the configuration from the encrypted file."""
        if not os.path.exists(self.config_file):
            # Save defaults if no config exists
            self.config = self.DEFAULT_CONFIG.copy()
            self.save_config()
            return self.config

        try:
            with open(self.config_file, "r", encoding="utf-8") as f:
                encrypted_data = f.read().strip()
            
            if not encrypted_data:
                self.config = self.DEFAULT_CONFIG.copy()
                self.save_config()
                return self.config

            decrypted_str = CryptoHelper.decrypt_data(encrypted_data)
            loaded_config = json.loads(decrypted_str)
            
            # Merge with default config to ensure all keys exist
            merged_config = self.DEFAULT_CONFIG.copy()
            merged_config.update(loaded_config)
            return merged_config
            
        except Exception as e:
            print(f"Error loading encrypted config, returning defaults: {e}")
            # In case of decryption error (e.g. file corrupted or machine environment changed), 
            # we return default configuration to prevent crash, but don't overwrite immediately.
            return self.DEFAULT_CONFIG.copy()

    def save_config(self) -> bool:
        """Encrypts and saves the current configuration to disk."""
        try:
            config_str = json.dumps(self.config)
            encrypted_str = CryptoHelper.encrypt_data(config_str)
            
            with open(self.config_file, "w", encoding="utf-8") as f:
                f.write(encrypted_str)
            return True
        except Exception as e:
            print(f"Error saving encrypted config: {e}")
            return False

    def get(self, key, default=None):
        return self.config.get(key, default)

    def set(self, key, value):
        self.config[key] = value
        self.save_config()
