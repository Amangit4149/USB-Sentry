import sys
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QStackedWidget, QFrame, QButtonGroup, QMessageBox)
from PyQt6.QtCore import Qt, pyqtSlot

# Add parent directory to sys.path to allow root-level module imports if needed
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Database.db_manager import DBManager
from Config.config_manager import ConfigManager
from Agent.agent_service import AgentService
from Encryption.password_manager import PasswordManager
from Dashboard.styles import Styles
from Dashboard.views.dashboard_view import DashboardView
from Dashboard.views.devices_view import DevicesView
from Dashboard.views.logs_view import LogsView
from Dashboard.views.map_view import MapView
from Dashboard.views.reports_view import ReportsView
from Dashboard.views.settings_view import SettingsView
from Dashboard.views.suspicious_view import SuspiciousFilesView
from Dashboard.views.unknown_devices_view import UnknownDevicesView


class FirstLaunchSetupWidget(QWidget):
    """
    Initial Administrator Account Setup wizard.
    Displayed on first run when no administrator account exists in the local database.
    Ensures every user creates their own unique credentials with secure salted hashing.
    """
    def __init__(self, db_manager, on_setup_success, parent=None):
        super().__init__(parent)
        self.db = db_manager
        self.on_setup_success = on_setup_success
        self.init_ui()

    def init_ui(self):
        self.setStyleSheet(Styles.LOGIN_THEME)
        
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card = QFrame()
        card.setObjectName("loginCard")
        card.setFixedWidth(460)
        
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(12)
        card_layout.setContentsMargins(32, 35, 32, 35)

        # Header titles
        logo_title = QLabel("🛡️ USB-Sentry")
        logo_title.setObjectName("logoTitle")
        logo_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(logo_title)

        setup_badge = QLabel("Initial Administrator Setup")
        setup_badge.setStyleSheet(
            "background: rgba(14, 165, 233, 0.15); color: #38bdf8; "
            "border: 1px solid #0284c7; border-radius: 6px; padding: 4px 8px; "
            "font-size: 12px; font-weight: bold;"
        )
        setup_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(setup_badge)

        desc = QLabel(
            "Welcome! This appears to be your first launch on this system.\n"
            "Create your primary administrator account to secure this installation."
        )
        desc.setStyleSheet("color: #94a3b8; font-size: 12px; line-height: 1.4; margin: 4px 0 10px 0;")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setWordWrap(True)
        card_layout.addWidget(desc)

        # Inputs
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Administrator Username")
        card_layout.addWidget(self.username_input)

        # Password input layout with toggle
        pwd_container = QHBoxLayout()
        pwd_container.setSpacing(6)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Master Password (min 6 characters)")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        pwd_container.addWidget(self.password_input)
        
        self.toggle_pwd_btn = QPushButton("👁️")
        self.toggle_pwd_btn.setFixedSize(38, 38)
        self.toggle_pwd_btn.setToolTip("Show / Hide Password")
        self.toggle_pwd_btn.setStyleSheet("background:#1e293b; color:#94a3b8; border:1px solid #334155; border-radius:6px; font-size:14px;")
        self.toggle_pwd_btn.setCheckable(True)
        self.toggle_pwd_btn.toggled.connect(self.toggle_password_visibility)
        pwd_container.addWidget(self.toggle_pwd_btn)
        card_layout.addLayout(pwd_container)

        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText("Confirm Master Password")
        self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_input.returnPressed.connect(self.handle_setup)
        card_layout.addWidget(self.confirm_input)

        # Security note
        note = QLabel("🔒 Credentials are bound to this Windows user account and never shared across systems.")
        note.setStyleSheet("color: #64748b; font-size: 11px; margin-top: 4px;")
        note.setWordWrap(True)
        card_layout.addWidget(note)

        # Submit button
        self.submit_btn = QPushButton("Create Administrator Account")
        self.submit_btn.setObjectName("loginBtn")
        self.submit_btn.clicked.connect(self.handle_setup)
        card_layout.addWidget(self.submit_btn)

        main_layout.addWidget(card)

    def toggle_password_visibility(self, checked: bool):
        mode = QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        self.password_input.setEchoMode(mode)
        self.confirm_input.setEchoMode(mode)
        self.toggle_pwd_btn.setStyleSheet(
            "background:#0ea5e9; color:#ffffff; border:1px solid #38bdf8; border-radius:6px; font-size:14px;"
            if checked else
            "background:#1e293b; color:#94a3b8; border:1px solid #334155; border-radius:6px; font-size:14px;"
        )

    def handle_setup(self):
        username = self.username_input.text().strip()
        pwd = self.password_input.text()
        confirm = self.confirm_input.text()

        if not username:
            QMessageBox.warning(self, "Validation Error", "Please provide an administrator username.")
            return

        if len(pwd) < 6:
            QMessageBox.warning(self, "Validation Error", "Password must be at least 6 characters long.")
            return

        if pwd != confirm:
            QMessageBox.warning(self, "Validation Error", "Password confirmation does not match.")
            return

        # Secure salted hashing via PasswordManager
        pwd_hash = PasswordManager.hash_password(pwd)
        if self.db.register_user(username, pwd_hash):
            QMessageBox.information(
                self, "Account Created",
                f"Administrator account '{username}' created successfully!\nProceeding to USB-Sentry Dashboard."
            )
            self.on_setup_success(username)
        else:
            QMessageBox.critical(self, "Error", "Failed to create administrator account. Please try again.")


class LoginWidget(QWidget):
    """
    Standard Administrator Authentication screen.
    Validates user credentials against the locally stored salted hash.
    No hardcoded credentials or fallback bypasses.
    """
    def __init__(self, db_manager, on_login_success, parent=None):
        super().__init__(parent)
        self.db = db_manager
        self.on_login_success = on_login_success
        self.init_ui()

    def init_ui(self):
        self.setStyleSheet(Styles.LOGIN_THEME)
        
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Login card container
        card = QFrame()
        card.setObjectName("loginCard")
        card.setFixedWidth(440)
        
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(12)
        card_layout.setContentsMargins(30, 35, 30, 35)

        # Header titles
        logo_title = QLabel("🛡️ USB-Sentry")
        logo_title.setObjectName("logoTitle")
        logo_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(logo_title)

        logo_subtitle = QLabel("Endpoint Protection & Tracking Portal")
        logo_subtitle.setObjectName("logoSubtitle")
        logo_subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(logo_subtitle)

        # Inputs
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Administrator Username")
        card_layout.addWidget(self.username_input)

        # Password input layout with toggle
        pwd_container = QHBoxLayout()
        pwd_container.setSpacing(6)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.returnPressed.connect(self.handle_login)
        pwd_container.addWidget(self.password_input)
        
        self.toggle_pwd_btn = QPushButton("👁️")
        self.toggle_pwd_btn.setFixedSize(38, 38)
        self.toggle_pwd_btn.setToolTip("Show / Hide Password")
        self.toggle_pwd_btn.setStyleSheet("background:#1e293b; color:#94a3b8; border:1px solid #334155; border-radius:6px; font-size:14px;")
        self.toggle_pwd_btn.setCheckable(True)
        self.toggle_pwd_btn.toggled.connect(self.toggle_password_visibility)
        pwd_container.addWidget(self.toggle_pwd_btn)
        
        card_layout.addLayout(pwd_container)

        # Login button
        self.login_btn = QPushButton("Authenticate Log In")
        self.login_btn.setObjectName("loginBtn")
        self.login_btn.clicked.connect(self.handle_login)
        card_layout.addWidget(self.login_btn)

        main_layout.addWidget(card)

    def toggle_password_visibility(self, checked: bool):
        if checked:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_pwd_btn.setStyleSheet("background:#0ea5e9; color:#ffffff; border:1px solid #38bdf8; border-radius:6px; font-size:14px;")
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_pwd_btn.setStyleSheet("background:#1e293b; color:#94a3b8; border:1px solid #334155; border-radius:6px; font-size:14px;")

    def handle_login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()

        if not username or not password:
            QMessageBox.warning(self, "Input Error", "Please provide administrator credentials.")
            return

        # Verify against local database using constant-time salted verification
        if self.db.verify_user(username, password):
            self.on_login_success(username)
            return

        QMessageBox.critical(self, "Access Denied", "Incorrect administrator username or password.")
        self.password_input.clear()


class MainWindow(QMainWindow):
    def __init__(self, db_manager, config_manager, agent_service, current_user=None):
        super().__init__()
        self.db = db_manager
        self.config = config_manager
        self.agent = agent_service
        self.current_user = current_user
        
        self.setWindowTitle("USB-Sentry – Intelligent USB Security & Data Loss Prevention System")
        self.setMinimumSize(1150, 780)
        self.init_ui()

        # Agent is ALWAYS active — start immediately and never stop
        if not self.agent.active:
            self.agent.start()
            print("✅  USB Monitoring Agent is permanently ACTIVE.")

    def init_ui(self):
        # Apply stylesheet
        self.setStyleSheet(Styles.MAIN_THEME)

        # Main central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Layout splitting: Sidebar (Left) + Content (Right)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 1. Left Sidebar Navigation
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)

        sidebar_title = QLabel("🛡️ USB-Sentry")
        sidebar_title.setObjectName("sidebarHeader")
        sidebar_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(sidebar_title)

        # Navigation Buttons Group
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        self.buttons = []
        nav_items = [
            ("📊  Overview",             0),
            ("🔌  Registered USBs",      1),
            ("⚠️  Unknown Devices",      2),
            ("📜  Historical Logs",      3),
            ("📍  Location Map",         4),
            ("📈  Reports & Audits",     5),
            ("🚨  Suspicious Files",     6),
            ("⚙️  System Settings",     7),
        ]

        for text, index in nav_items:
            btn = QPushButton(text)
            btn.setObjectName("navBtn")
            btn.setCheckable(True)
            if index == 0:
                btn.setChecked(True)
            self.nav_group.addButton(btn, index)
            sidebar_layout.addWidget(btn)
            self.buttons.append(btn)

        sidebar_layout.addStretch()

        # Branding label at the bottom of the sidebar
        user_info = f"User: {self.current_user}" if self.current_user else "v1.0.0 Stable"
        branding = QLabel(user_info)
        branding.setStyleSheet("color: #475569; font-size: 11px; padding: 15px; font-weight: 500;")
        branding.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(branding)

        main_layout.addWidget(sidebar)

        # 2. Right Stacked Widget
        self.content_frame = QFrame()
        self.content_frame.setObjectName("contentFrame")
        content_layout = QVBoxLayout(self.content_frame)
        content_layout.setContentsMargins(10, 10, 10, 10)

        self.stacked_widget = QStackedWidget()
        content_layout.addWidget(self.stacked_widget)
        main_layout.addWidget(self.content_frame, 1)

        # Instantiate Views
        self.view_dashboard  = DashboardView(self.db, self.agent, self)
        self.view_devices    = DevicesView(self.db, self)
        self.view_unknown    = UnknownDevicesView(self.db, self)
        self.view_logs       = LogsView(self.db, self)
        self.view_map        = MapView(self.db, self)
        self.view_reports    = ReportsView(self.db, self)
        self.view_suspicious = SuspiciousFilesView(self.db, self)
        self.view_settings   = SettingsView(self.db, self.config, current_user=self.current_user, parent=self)

        # Add Views to stacked widget (must match nav_items order)
        self.stacked_widget.addWidget(self.view_dashboard)   # 0
        self.stacked_widget.addWidget(self.view_devices)      # 1
        self.stacked_widget.addWidget(self.view_unknown)      # 2
        self.stacked_widget.addWidget(self.view_logs)         # 3
        self.stacked_widget.addWidget(self.view_map)          # 4
        self.stacked_widget.addWidget(self.view_reports)      # 5
        self.stacked_widget.addWidget(self.view_suspicious)   # 6
        self.stacked_widget.addWidget(self.view_settings)     # 7

        # Connect button signals
        self.nav_group.idClicked.connect(self.switch_view)

    @pyqtSlot(int)
    def switch_view(self, index: int):
        """Switches the current stacked index according to the pressed sidebar button."""
        self.stacked_widget.setCurrentIndex(index)
        self.on_view_changed(index)

    def on_view_changed(self, index: int):
        """Auto-refreshes subview states when selected."""
        if index == 0:
            self.view_dashboard.refresh_data()
        elif index == 1:
            self.view_devices.refresh_table()
            self.view_devices.refresh_drives()
        elif index == 2:
            self.view_unknown.refresh()
        elif index == 3:
            self.view_logs.refresh_logs()
        elif index == 4:
            self.view_map.refresh_map_logs()
        elif index == 6:
            self.view_suspicious.refresh()
        elif index == 7:
            self.view_settings.load_values()

    def closeEvent(self, event):
        """Clean shutdown hook to stop background monitoring agents."""
        reply = QMessageBox.question(
            self, "Confirm Exit",
            "Are you sure you want to close the USB-Sentry Dashboard?\n"
            "The background USB monitoring agent thread will be terminated.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.agent.stop()
            event.accept()
        else:
            event.ignore()


def run_gui(db_manager, config_manager, agent_service):
    app = QApplication(sys.argv)
    
    main_window_container = {}

    def launch_main_window(logged_in_user):
        main_win = MainWindow(db_manager, config_manager, agent_service, current_user=logged_in_user)
        main_window_container["window"] = main_win
        main_win.show()

    if not db_manager.check_user_exists():
        # First-launch experience: prompt user to create unique administrator credentials
        setup_widget = FirstLaunchSetupWidget(
            db_manager,
            on_setup_success=lambda u: (setup_widget.close(), launch_main_window(u))
        )
        setup_widget.setWindowTitle("USB-Sentry - Initial Administrator Setup")
        setup_widget.setMinimumSize(500, 480)
        setup_widget.show()
    else:
        # Returning user: prompt for login
        login_widget = LoginWidget(
            db_manager,
            on_login_success=lambda u: (login_widget.close(), launch_main_window(u))
        )
        login_widget.setWindowTitle("USB-Sentry - Administrator Authentication")
        login_widget.setMinimumSize(500, 440)
        login_widget.show()
    
    sys.exit(app.exec())
