import sys
import os
import hashlib
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QStackedWidget, QFrame, QButtonGroup, QMessageBox)
from PyQt6.QtCore import Qt, pyqtSlot

# Add parent directory to sys.path to allow root-level module imports if needed
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Database.db_manager import DBManager
from Config.config_manager import ConfigManager
from Agent.agent_service import AgentService
from Dashboard.styles import Styles
from Dashboard.views.dashboard_view import DashboardView
from Dashboard.views.devices_view import DevicesView
from Dashboard.views.logs_view import LogsView
from Dashboard.views.map_view import MapView
from Dashboard.views.reports_view import ReportsView
from Dashboard.views.settings_view import SettingsView
from Dashboard.views.suspicious_view import SuspiciousFilesView
from Dashboard.views.unknown_devices_view import UnknownDevicesView


class LoginWidget(QWidget):
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
        card.setFixedWidth(380)
        
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(15)
        card_layout.setContentsMargins(30, 40, 30, 40)

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
        self.username_input.setText("admin")  # Pre-fill default username
        card_layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.returnPressed.connect(self.handle_login)
        card_layout.addWidget(self.password_input)

        # Login button
        self.login_btn = QPushButton("Authenticate Log In")
        self.login_btn.setObjectName("loginBtn")
        self.login_btn.clicked.connect(self.handle_login)
        card_layout.addWidget(self.login_btn)

        main_layout.addWidget(card)

    def handle_login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()

        if not username or not password:
            QMessageBox.warning(self, "Input Error", "Please provide credentials.")
            return

        password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        
        # Verify in SQLite database
        if self.db.verify_user(username, password_hash):
            self.on_login_success()
        else:
            QMessageBox.critical(self, "Access Denied", "Incorrect administrator username or password.")
            self.password_input.clear()


class MainWindow(QMainWindow):
    def __init__(self, db_manager, config_manager, agent_service):
        super().__init__()
        self.db = db_manager
        self.config = config_manager
        self.agent = agent_service
        
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
        branding = QLabel("v1.0.0 Stable")
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
        self.view_settings   = SettingsView(self.db, self.config, self)

        # Add Views to stacked widget (must match nav_items order)
        self.stacked_widget.addWidget(self.view_dashboard)   # 0
        self.stacked_widget.addWidget(self.view_devices)      # 1
        self.stacked_widget.addWidget(self.view_unknown)      # 2
        self.stacked_widget.addWidget(self.view_logs)         # 3
        self.stacked_widget.addWidget(self.view_map)          # 4
        self.stacked_widget.addWidget(self.view_reports)      # 5
        self.stacked_widget.addWidget(self.view_suspicious)   # 6
        self.stacked_widget.addWidget(self.view_settings)     # 7

        # Connect Sidebar Buttons
        self.nav_group.idClicked.connect(self.switch_tab)
        
        # Connect Stacked view index changes for Auto-Refresh on Tab change
        self.stacked_widget.currentChanged.connect(self.on_tab_changed)

    @pyqtSlot(int)
    def switch_tab(self, index):
        self.stacked_widget.setCurrentIndex(index)

    @pyqtSlot(int)
    def on_tab_changed(self, index):
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
    
    # Initialize default admin credentials if DB is completely empty
    if not db_manager.check_user_exists():
        default_hash = hashlib.sha256(b"admin").hexdigest()
        db_manager.register_user("admin", default_hash)
        
    main_window = MainWindow(db_manager, config_manager, agent_service)
    
    login_widget = LoginWidget(db_manager, on_login_success=lambda: (
        login_widget.close(),
        main_window.show()
    ))
    
    login_widget.setWindowTitle("USB-Sentry - Administrator Authentication")
    login_widget.setMinimumSize(450, 400)
    login_widget.show()
    
    sys.exit(app.exec())
