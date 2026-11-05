import os
import sys
import shutil
import tempfile
import unittest

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from Config.paths import get_default_db_path, get_default_config_path
from Database.db_manager import DBManager
from Config.config_manager import ConfigManager
from Encryption.password_manager import PasswordManager
from Encryption.crypto_helper import CryptoHelper
from USBMonitor.monitor import get_signing_key


class TestUSBDataIsolationAndSecurity(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="usb_sentry_test_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_a_first_computer_lifecycle(self):
        """Test A: First computer - clean empty DB, logging events, persistence after restart."""
        db_path = os.path.join(self.test_dir, "pc1", "guardian.db")
        db = DBManager(db_path=db_path)

        # 1. Confirm the database starts completely empty
        self.assertFalse(db.check_user_exists(), "New DB should have 0 users.")
        self.assertEqual(len(db.get_registered_usbs()), 0, "New DB should have 0 registered USBs.")
        self.assertEqual(len(db.get_device_logs()), 0, "New DB should have 0 device logs.")
        self.assertEqual(len(db.get_file_activity_logs()), 0, "New DB should have 0 file activity logs.")

        # 2. Register first admin
        pwd_hash = PasswordManager.hash_password("MasterSecurePass123!")
        self.assertTrue(db.register_user("admin_pc1", pwd_hash))
        self.assertTrue(db.check_user_exists())
        self.assertTrue(db.verify_user("admin_pc1", "MasterSecurePass123!"))
        self.assertFalse(db.verify_user("admin_pc1", "WrongPassword"))

        # 3. Simulate USB event
        log_id = db.log_device_event(
            usb_serial="USB_PC1_ALPHA",
            event_type="INSERTION",
            computer_name="PC1-DESKTOP",
            username="alice",
            local_ip="192.168.1.50",
            public_ip="203.0.113.1",
            mac_address="AA:BB:CC:11:22:33",
            os_version="Windows 11",
            cpu_info="Intel Core i7",
            ram_info="16.00 GB"
        )
        self.assertIsNotNone(log_id)

        # 4. Restart application (re-instantiate DBManager on same path)
        db_restarted = DBManager(db_path=db_path)
        self.assertTrue(db_restarted.check_user_exists(), "User should still exist after restart.")
        logs = db_restarted.get_device_logs()
        self.assertEqual(len(logs), 1, "Logged event must persist after restart.")
        self.assertEqual(logs[0]["usb_serial"], "USB_PC1_ALPHA")
        self.assertEqual(logs[0]["computer_name"], "PC1-DESKTOP")

    def test_b_second_computer_isolation(self):
        """Test B: Second computer starts with independent empty DB and doesn't share data with PC1."""
        pc1_dir = os.path.join(self.test_dir, "pc1")
        pc2_dir = os.path.join(self.test_dir, "pc2")

        db1 = DBManager(db_path=os.path.join(pc1_dir, "guardian.db"))
        db1.register_user("admin_pc1", PasswordManager.hash_password("Pass1!"))
        db1.log_device_event("USB_PC1_ONLY", "INSERTION", "PC1", "user1", "10.0.0.1", "1.1.1.1", "AA", "Win11", "CPU1", "8GB")

        # Second computer gets clean installation
        db2 = DBManager(db_path=os.path.join(pc2_dir, "guardian.db"))

        # PC2 must start completely empty
        self.assertFalse(db2.check_user_exists(), "PC2 should have no users initially.")
        self.assertEqual(len(db2.get_device_logs()), 0, "PC2 must not see PC1 device logs.")
        self.assertEqual(len(db2.get_registered_usbs()), 0, "PC2 must not see PC1 registered USBs.")

        # Log event on PC2
        db2.log_device_event("USB_PC2_ONLY", "INSERTION", "PC2", "user2", "10.0.0.2", "2.2.2.2", "BB", "Win11", "CPU2", "16GB")

        # Verify strict separation
        pc1_serials = [log["usb_serial"] for log in db1.get_device_logs()]
        pc2_serials = [log["usb_serial"] for log in db2.get_device_logs()]

        self.assertIn("USB_PC1_ONLY", pc1_serials)
        self.assertNotIn("USB_PC2_ONLY", pc1_serials)
        self.assertIn("USB_PC2_ONLY", pc2_serials)
        self.assertNotIn("USB_PC1_ONLY", pc2_serials)

    def test_c_application_code_update(self):
        """Test C: Updating application code must never overwrite existing user records."""
        pc2_db_path = os.path.join(self.test_dir, "pc2", "guardian.db")
        db = DBManager(db_path=pc2_db_path)
        db.register_user("pc2_user", PasswordManager.hash_password("Secret123!"))
        db.log_device_event("PERSISTENT_USB", "INSERTION", "PC2", "u2", "10.0.0.5", "5.5.5.5", "CC", "Win11", "CPU", "16GB")

        # Simulate update: app restarted after git pull
        db_after_update = DBManager(db_path=pc2_db_path)
        self.assertTrue(db_after_update.check_user_exists())
        self.assertTrue(db_after_update.verify_user("pc2_user", "Secret123!"))
        logs = db_after_update.get_device_logs()
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["usb_serial"], "PERSISTENT_USB")

    def test_d_configuration_isolation(self):
        """Test D: Configuration files are independent and use per-user encryption."""
        cfg1_path = os.path.join(self.test_dir, "user1", "settings.enc")
        cfg2_path = os.path.join(self.test_dir, "user2", "settings.enc")

        cfg1 = ConfigManager(config_path=cfg1_path)
        cfg1.set("email_sender", "alice@enterprise.corp")
        cfg1.set("telegram_chat_id", "123456789")

        self.assertTrue(os.path.exists(cfg1_path))

        # Config 2 starts empty with default values
        cfg2 = ConfigManager(config_path=cfg2_path)
        self.assertEqual(cfg2.get("email_sender"), "")
        self.assertEqual(cfg2.get("telegram_chat_id"), "")

        # Verify file contents are encrypted
        with open(cfg1_path, "r", encoding="utf-8") as f:
            raw_data = f.read()
        self.assertNotIn("alice@enterprise.corp", raw_data, "Plaintext email must never appear in raw settings.enc file.")

    def test_e_security_and_authentication(self):
        """Test E: Verification of salted hashing, rejection of hardcoded admin/admin, dynamic signing key."""
        db = DBManager(db_path=os.path.join(self.test_dir, "sec_test.db"))

        # Rejection of uninitialized login
        self.assertFalse(db.verify_user("admin", "admin"), "Must NOT accept default admin/admin if user does not exist.")

        # Test salted password hashing
        pwd = "ComplexUserPassword99$"
        pwd_hash = PasswordManager.hash_password(pwd)
        self.assertNotEqual(pwd, pwd_hash)
        self.assertTrue(pwd_hash.startswith(("$scrypt$", "$pbkdf2$", "$argon2", "$2b$")))
        self.assertTrue(PasswordManager.verify_password(pwd, pwd_hash))
        self.assertFalse(PasswordManager.verify_password("wrong", pwd_hash))

        # Dynamic per-user signing key
        key1 = get_signing_key()
        self.assertIsInstance(key1, bytes)
        self.assertGreaterEqual(len(key1), 16)
        self.assertNotEqual(key1, b"SmartUSBGuardianMasterSigningKeySecret123", "Hardcoded signing key must be eliminated.")


if __name__ == "__main__":
    unittest.main()

