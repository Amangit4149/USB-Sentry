import hashlib
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QFrame, QPushButton, QLineEdit, QFormLayout, 
                             QMessageBox, QSpinBox, QComboBox)
from Config.config_manager import ConfigManager
from Database.db_manager import DBManager
from Email.email_sender import EmailSender
from Email.telegram_sender import TelegramSender
from Encryption.password_manager import PasswordManager

class SettingsView(QWidget):
    def __init__(self, db_manager, config_manager, current_user=None, parent=None):
        if isinstance(current_user, QWidget) and parent is None:
            parent = current_user
            current_user = None
        super().__init__(parent)
        self.db = db_manager
        self.config = config_manager
        self.current_user = current_user
        self.email_sender = EmailSender(self.config, self.db)
        self.telegram_sender = TelegramSender(self.config, self.db)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        # Header
        header = QLabel("System Settings Configuration")
        header.setObjectName("sectionHeader")
        layout.addWidget(header)

        # Dual Column Layout
        columns_layout = QHBoxLayout()
        
        # Left Column: SMTP & Alert Notifications
        left_col = QVBoxLayout()
        
        # Email settings card
        email_card = QFrame()
        email_card.setObjectName("card")
        email_layout = QVBoxLayout(email_card)
        
        email_title = QLabel("SMTP Email Alert Settings")
        email_title.setStyleSheet("font-weight: bold; font-size: 14px; color: #38bdf8; margin-bottom: 10px;")
        email_layout.addWidget(email_title)
        
        self.email_form = QFormLayout()
        self.email_form.setSpacing(8)
        
        self.smtp_server_input = QLineEdit()
        self.smtp_port_input = QLineEdit()
        self.sender_email_input = QLineEdit()
        self.sender_pwd_input = QLineEdit()
        self.sender_pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.receiver_email_input = QLineEdit()
        
        self.email_form.addRow("SMTP Server:", self.smtp_server_input)
        self.email_form.addRow("SMTP Port (TLS):", self.smtp_port_input)
        self.email_form.addRow("Sender Email:", self.sender_email_input)
        self.email_form.addRow("Sender Password:", self.sender_pwd_input)
        self.email_form.addRow("Receiver Email:", self.receiver_email_input)
        
        email_layout.addLayout(self.email_form)
        
        # Test Email Button
        self.test_email_btn = QPushButton("Send Test Email")
        self.test_email_btn.setObjectName("secondaryBtn")
        self.test_email_btn.clicked.connect(self.test_email_settings)
        email_layout.addWidget(self.test_email_btn)
        
        left_col.addWidget(email_card)

        # Telegram notification card
        tg_card = QFrame()
        tg_card.setObjectName("card")
        tg_layout = QVBoxLayout(tg_card)
        
        tg_title = QLabel("Telegram Channel Alert Settings")
        tg_title.setStyleSheet("font-weight: bold; font-size: 14px; color: #38bdf8; margin-bottom: 10px;")
        tg_layout.addWidget(tg_title)
        
        self.tg_form = QFormLayout()
        self.tg_form.setSpacing(8)
        
        self.tg_token_input = QLineEdit()
        self.tg_chat_input = QLineEdit()
        
        self.tg_form.addRow("Bot Token:", self.tg_token_input)
        self.tg_form.addRow("Chat / Channel ID:", self.tg_chat_input)
        
        tg_layout.addLayout(self.tg_form)
        
        # Test Telegram Button
        self.test_tg_btn = QPushButton("Send Test Telegram Message")
        self.test_tg_btn.setObjectName("secondaryBtn")
        self.test_tg_btn.clicked.connect(self.test_telegram_settings)
        tg_layout.addWidget(self.test_tg_btn)
        
        left_col.addWidget(tg_card)
        columns_layout.addLayout(left_col, 1)

        # Right Column: Security, Limits & Admin Credentials
        right_col = QVBoxLayout()
        
        # System Limits card
        limits_card = QFrame()
        limits_card.setObjectName("card")
        limits_layout = QVBoxLayout(limits_card)
        
        limits_title = QLabel("Alert Rate Limiting")
        limits_title.setStyleSheet("font-weight: bold; font-size: 14px; color: #38bdf8; margin-bottom: 10px;")
        limits_layout.addWidget(limits_title)
        
        self.limits_form = QFormLayout()
        self.limits_form.setSpacing(10)
        
        self.rate_limit_input = QSpinBox()
        self.rate_limit_input.setRange(1, 180)
        self.rate_limit_input.setSuffix(" Minutes")
        
        self.limits_form.addRow("Rate Limit Interval:", self.rate_limit_input)
        
        limits_layout.addLayout(self.limits_form)
        limits_layout.addStretch()
        right_col.addWidget(limits_card)

        # Change Password card
        pwd_card = QFrame()
        pwd_card.setObjectName("card")
        pwd_layout = QVBoxLayout(pwd_card)
        
        pwd_title = QLabel("Change Administrator Password")
        pwd_title.setStyleSheet("font-weight: bold; font-size: 14px; color: #38bdf8; margin-bottom: 10px;")
        pwd_layout.addWidget(pwd_title)
        
        self.pwd_form = QFormLayout()
        self.pwd_form.setSpacing(8)
        
        self.current_pwd_input = QLineEdit()
        self.current_pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_pwd_input = QLineEdit()
        self.new_pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_pwd_input = QLineEdit()
        self.confirm_pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        self.pwd_form.addRow("Current Password:", self.current_pwd_input)
        self.pwd_form.addRow("New Password:", self.new_pwd_input)
        self.pwd_form.addRow("Confirm Password:", self.confirm_pwd_input)
        
        pwd_layout.addLayout(self.pwd_form)
        
        self.change_pwd_btn = QPushButton("Update Admin Password")
        self.change_pwd_btn.setObjectName("secondaryBtn")
        self.change_pwd_btn.clicked.connect(self.change_admin_password)
        pwd_layout.addWidget(self.change_pwd_btn)
        
        right_col.addWidget(pwd_card)
        columns_layout.addLayout(right_col, 1)

        layout.addLayout(columns_layout)

        # Global Actions Row
        actions_layout = QHBoxLayout()
        actions_layout.addStretch()
        
        self.save_btn = QPushButton("Save Settings Configurations")
        self.save_btn.setObjectName("primaryBtn")
        self.save_btn.setFixedHeight(40)
        self.save_btn.setFixedWidth(220)
        self.save_btn.clicked.connect(self.save_settings)
        actions_layout.addWidget(self.save_btn)
        
        layout.addLayout(actions_layout)

        # Load values into forms
        self.load_values()

    def load_values(self):
        """Populates form controls with decrypted parameters from the ConfigManager."""
        self.smtp_server_input.setText(self.config.get("smtp_server"))
        self.smtp_port_input.setText(str(self.config.get("smtp_port") or 587))
        self.sender_email_input.setText(self.config.get("email_sender"))
        self.sender_pwd_input.setText(self.config.get("email_password"))
        self.receiver_email_input.setText(self.config.get("email_receiver"))
        
        self.tg_token_input.setText(self.config.get("telegram_token"))
        self.tg_chat_input.setText(self.config.get("telegram_chat_id"))
        
        self.rate_limit_input.setValue(int(self.config.get("rate_limit_minutes") or 15))

    def save_settings(self):
        """Saves current form inputs into the encrypted settings configurations."""
        self.config.set("smtp_server", self.smtp_server_input.text().strip())
        
        try:
            port = int(self.smtp_port_input.text().strip() or 587)
            self.config.set("smtp_port", port)
        except ValueError:
            QMessageBox.warning(self, "Invalid Port", "SMTP port must be a valid integer.")
            return

        self.config.set("email_sender", self.sender_email_input.text().strip())
        self.config.set("email_password", self.sender_pwd_input.text().strip())
        self.config.set("email_receiver", self.receiver_email_input.text().strip())
        
        self.config.set("telegram_token", self.tg_token_input.text().strip())
        self.config.set("telegram_chat_id", self.tg_chat_input.text().strip())
        
        self.config.set("rate_limit_minutes", self.rate_limit_input.value())

        if self.config.save_config():
            QMessageBox.information(self, "Success", "Configurations saved and encrypted successfully.")
        else:
            QMessageBox.critical(self, "Error", "Failed to save encrypted settings configurations.")

    def test_email_settings(self):
        """Fires an instant SMTP connection verification routine."""
        smtp_server = self.smtp_server_input.text().strip()
        smtp_port = self.smtp_port_input.text().strip()
        sender = self.sender_email_input.text().strip()
        pwd = self.sender_pwd_input.text().strip()
        receiver = self.receiver_email_input.text().strip()

        if not all([smtp_server, smtp_port, sender, pwd, receiver]):
            QMessageBox.warning(self, "Validation Error", "All SMTP configuration parameters are required for test.")
            return

        self.test_email_btn.setEnabled(False)
        self.test_email_btn.setText("Connecting...")
        
        success, message = self.email_sender.test_connection(smtp_server, smtp_port, sender, pwd, receiver)
        
        self.test_email_btn.setEnabled(True)
        self.test_email_btn.setText("Send Test Email")

        if success:
            QMessageBox.information(self, "SMTP Verification Success", message)
        else:
            QMessageBox.critical(self, "SMTP Verification Failed", message)

    def test_telegram_settings(self):
        """Fires an instant Telegram API connection verification message."""
        token = self.tg_token_input.text().strip()
        chat_id = self.tg_chat_input.text().strip()

        if not token or not chat_id:
            QMessageBox.warning(self, "Validation Error", "Telegram Bot token and Chat ID are required for test.")
            return

        self.test_tg_btn.setEnabled(False)
        self.test_tg_btn.setText("Sending...")
        
        success, message = TelegramSender.test_telegram(token, chat_id)
        
        self.test_tg_btn.setEnabled(True)
        self.test_tg_btn.setText("Send Test Telegram Message")

        if success:
            QMessageBox.information(self, "Telegram Verification Success", message)
        else:
            QMessageBox.critical(self, "Telegram Verification Failed", message)

    def change_admin_password(self):
        """Changes the admin password for Dashboard logins using secure salted hashing."""
        current_pwd = self.current_pwd_input.text()
        new_pwd = self.new_pwd_input.text()
        confirm_pwd = self.confirm_pwd_input.text()

        if not current_pwd or not new_pwd or not confirm_pwd:
            QMessageBox.warning(self, "Validation Error", "All fields are required to update password.")
            return

        if len(new_pwd) < 6:
            QMessageBox.warning(self, "Validation Error", "New password must be at least 6 characters long.")
            return

        if new_pwd != confirm_pwd:
            QMessageBox.warning(self, "Validation Error", "New password confirmation does not match.")
            return

        # Determine target user
        target_user = self.current_user
        if not target_user:
            users = self.db.get_all_users()
            target_user = users[0]["username"] if users else "admin"

        # Verify old password using constant-time salted verification
        is_valid = self.db.verify_user(target_user, current_pwd)
        if not is_valid:
            # Also check fallback if verifying against config hash
            config_hash = self.config.get("dashboard_password_hash")
            if config_hash and PasswordManager.verify_password(current_pwd, config_hash):
                is_valid = True

        if not is_valid:
            QMessageBox.critical(self, "Auth Error", "Current administrator password is incorrect.")
            return

        # Securely hash new password
        new_hash = PasswordManager.hash_password(new_pwd)
        
        # Save in database and sync in config
        db_updated = self.db.change_user_password(target_user, new_hash)
        self.config.set("dashboard_password_hash", new_hash)
        config_saved = self.config.save_config()

        if db_updated or config_saved:
            QMessageBox.information(self, "Success", "Administrator password updated successfully.")
            self.current_pwd_input.clear()
            self.new_pwd_input.clear()
            self.confirm_pwd_input.clear()
        else:
            QMessageBox.critical(self, "Error", "Failed to update administrator password.")
