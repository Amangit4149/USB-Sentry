from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QFrame, QTableWidget, QTableWidgetItem, QHeaderView, 
                             QPushButton, QLineEdit, QTabWidget, QAbstractItemView)
from PyQt6.QtCore import Qt

class LogsView(QWidget):
    def __init__(self, db_manager, parent=None):
        super().__init__(parent)
        self.db = db_manager
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Header and Search Filter
        top_layout = QHBoxLayout()
        header = QLabel("Historical Logs Explorer")
        header.setObjectName("sectionHeader")
        top_layout.addWidget(header)
        
        top_layout.addStretch()
        
        # Search Filter Input
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter logs by Serial, Host, User...")
        self.search_input.setFixedWidth(250)
        self.search_input.textChanged.connect(self.refresh_logs)
        top_layout.addWidget(self.search_input)
        
        self.refresh_btn = QPushButton("Refresh Logs")
        self.refresh_btn.setObjectName("secondaryBtn")
        self.refresh_btn.clicked.connect(self.refresh_logs)
        top_layout.addWidget(self.refresh_btn)
        
        layout.addLayout(top_layout)

        # Tab Widget to host different logs
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Tab 1: Device Connection Logs
        self.tab_devices = QWidget()
        devices_layout = QVBoxLayout(self.tab_devices)
        self.table_devices = QTableWidget(0, 8)
        self.table_devices.setHorizontalHeaderLabels([
            "Timestamp", "Device Label", "USB Serial", "Event", 
            "PC Name", "Username", "Local IP", "Public IP"
        ])
        self.table_devices.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table_devices.horizontalHeader().setStretchLastSection(True)
        self.table_devices.verticalHeader().setVisible(False)
        self.table_devices.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        devices_layout.addWidget(self.table_devices)
        self.tabs.addTab(self.tab_devices, "Device Connection Events")

        # Tab 2: Location Logs
        self.tab_location = QWidget()
        location_layout = QVBoxLayout(self.tab_location)
        self.table_location = QTableWidget(0, 7)
        self.table_location.setHorizontalHeaderLabels([
            "Timestamp", "Device Label", "USB Serial", "Country", 
            "State/Region", "City", "Maps Coordinates"
        ])
        self.table_location.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table_location.horizontalHeader().setStretchLastSection(True)
        self.table_location.verticalHeader().setVisible(False)
        self.table_location.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        location_layout.addWidget(self.table_location)
        self.tabs.addTab(self.tab_location, "Geographical Logs")

        # Tab 3: Dispatch Alerts Logs
        self.tab_alerts = QWidget()
        alerts_layout = QVBoxLayout(self.tab_alerts)
        self.table_alerts = QTableWidget(0, 6)
        self.table_alerts.setHorizontalHeaderLabels([
            "Timestamp", "Device Label", "Recipient", 
            "Type", "Status", "Details/Errors"
        ])
        self.table_alerts.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table_alerts.horizontalHeader().setStretchLastSection(True)
        self.table_alerts.verticalHeader().setVisible(False)
        self.table_alerts.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        alerts_layout.addWidget(self.table_alerts)
        self.tabs.addTab(self.tab_alerts, "Security Alerts Status")

        # Initial Refresh
        self.refresh_logs()

    def refresh_logs(self):
        """Fetches fresh log collections from SQLite database and binds to GUI Tables."""
        search_query = self.search_input.text().strip()
        
        # 1. Update Connection Logs (Merge Registered and Unknown)
        known_logs = self.db.get_device_logs(limit=150, search=search_query)
        unknown_logs = self.db.get_unknown_device_events(limit=150)
        
        # Format unknown logs to match the structure of known logs for display
        formatted_unknown = []
        for log in unknown_logs:
            # Apply search filter manually for unknown logs
            q = search_query.lower()
            if q and not (
                q in str(log.get("serial_number", "")).lower() or 
                q in str(log.get("computer_name", "")).lower() or 
                q in str(log.get("username", "")).lower()
            ):
                continue
                
            formatted_unknown.append({
                "timestamp": log.get("timestamp"),
                "label": "Unknown",
                "usb_serial": log.get("serial_number"),
                "event_type": "UNKNOWN DEVICE",
                "computer_name": log.get("computer_name"),
                "username": log.get("username"),
                "local_ip": log.get("local_ip"),
                "public_ip": log.get("public_ip")
            })
            
        # Combine and sort by timestamp descending
        all_logs = known_logs + formatted_unknown
        all_logs.sort(key=lambda x: str(x.get("timestamp", "")), reverse=True)
        # Cap at 150 total for performance
        all_logs = all_logs[:150]

        self.table_devices.setRowCount(len(all_logs))
        for row_idx, log in enumerate(all_logs):
            self.table_devices.setItem(row_idx, 0, QTableWidgetItem(str(log.get("timestamp", ""))[:19]))
            self.table_devices.setItem(row_idx, 1, QTableWidgetItem(str(log.get("label") or "Unknown")))
            self.table_devices.setItem(row_idx, 2, QTableWidgetItem(str(log.get("usb_serial", ""))))
            
            event_type = str(log.get("event_type", ""))
            evt_item = QTableWidgetItem(event_type)
            if event_type == "INSERTION":
                evt_item.setForeground(Qt.GlobalColor.green)
            elif event_type == "UNKNOWN DEVICE":
                evt_item.setForeground(Qt.GlobalColor.red)
                evt_item.setFont(self.font())
                evt_item.font().setBold(True)
            else:
                evt_item.setForeground(Qt.GlobalColor.red)
            self.table_devices.setItem(row_idx, 3, evt_item)
            
            self.table_devices.setItem(row_idx, 4, QTableWidgetItem(str(log.get("computer_name", ""))))
            self.table_devices.setItem(row_idx, 5, QTableWidgetItem(str(log.get("username", ""))))
            self.table_devices.setItem(row_idx, 6, QTableWidgetItem(str(log.get("local_ip", ""))))
            self.table_devices.setItem(row_idx, 7, QTableWidgetItem(str(log.get("public_ip", ""))))

        # 2. Update Location Logs
        loc_logs = self.db.get_location_logs(limit=150)
        # Apply local client filtering to location logs for search consistency
        if search_query:
            q = search_query.lower()
            loc_logs = [l for l in loc_logs if q in (l.get("usb_serial") or "").lower() or q in (l.get("label") or "").lower() or q in (l.get("country") or "").lower() or q in (l.get("city") or "").lower()]
            
        self.table_location.setRowCount(len(loc_logs))
        for row_idx, log in enumerate(loc_logs):
            self.table_location.setItem(row_idx, 0, QTableWidgetItem(log.get("timestamp", "")[:19]))
            self.table_location.setItem(row_idx, 1, QTableWidgetItem(log.get("label") or "Unknown"))
            self.table_location.setItem(row_idx, 2, QTableWidgetItem(log.get("usb_serial", "")))
            self.table_location.setItem(row_idx, 3, QTableWidgetItem(log.get("country", "")))
            self.table_location.setItem(row_idx, 4, QTableWidgetItem(log.get("state", "")))
            self.table_location.setItem(row_idx, 5, QTableWidgetItem(log.get("city", "")))
            
            lat = log.get("latitude", 0.0)
            lon = log.get("longitude", 0.0)
            coord_item = QTableWidgetItem(f"{lat:.4f}, {lon:.4f}")
            coord_item.setToolTip("Google Maps Link: " + (log.get("maps_link") or "None"))
            self.table_location.setItem(row_idx, 6, coord_item)

        # 3. Update Email/Telegram Notification Logs
        alert_logs = self.db.get_email_logs(limit=150)
        if search_query:
            q = search_query.lower()
            alert_logs = [a for a in alert_logs if q in (a.get("usb_serial") or "").lower() or q in (a.get("label") or "").lower() or q in (a.get("recipient") or "").lower()]
            
        self.table_alerts.setRowCount(len(alert_logs))
        for row_idx, log in enumerate(alert_logs):
            item_ts = QTableWidgetItem(log.get("timestamp", "")[:19])
            item_lbl = QTableWidgetItem(log.get("label") or "Unknown")
            item_rec = QTableWidgetItem(log.get("recipient", ""))
            item_type = QTableWidgetItem(log.get("notification_type", ""))
            
            # Align center for type
            item_type.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            
            status = log.get("status", "")
            stat_item = QTableWidgetItem(status)
            stat_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if status == "SENT":
                stat_item.setForeground(Qt.GlobalColor.green)
            else:
                stat_item.setForeground(Qt.GlobalColor.red)
                
            item_err = QTableWidgetItem(log.get("error_message", ""))
            
            self.table_alerts.setItem(row_idx, 0, item_ts)
            self.table_alerts.setItem(row_idx, 1, item_lbl)
            self.table_alerts.setItem(row_idx, 2, item_rec)
            self.table_alerts.setItem(row_idx, 3, item_type)
            self.table_alerts.setItem(row_idx, 4, stat_item)
            self.table_alerts.setItem(row_idx, 5, item_err)

        # Auto-resize columns to fit their contents so data isn't truncated
        self.table_devices.resizeColumnsToContents()
        self.table_location.resizeColumnsToContents()
        self.table_alerts.resizeColumnsToContents()
