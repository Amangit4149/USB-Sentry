"""
Dashboard view: Suspicious Files Scanner
Shows all USB events that contained suspicious files, with red highlights.
"""
import json
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QPushButton, QFrame, QHeaderView,
    QAbstractItemView, QSplitter, QTextEdit
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont


class SuspiciousFilesView(QWidget):
    def __init__(self, db_manager, parent=None):
        super().__init__(parent)
        self.db = db_manager
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # ── Header ────────────────────────────────────────────────────────────
        header = QLabel("⚠️  Suspicious File Scanner")
        header.setObjectName("sectionHeader")
        layout.addWidget(header)

        subtitle = QLabel(
            "All USB insertion events that contained suspicious files are listed below. "
            "Click any row to view the full file list for that event."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #94a3b8; font-size: 13px; margin-bottom: 4px;")
        layout.addWidget(subtitle)

        # ── Stat banner ───────────────────────────────────────────────────────
        self.banner = QFrame()
        self.banner.setObjectName("card")
        self.banner.setFixedHeight(54)
        banner_layout = QHBoxLayout(self.banner)
        banner_layout.setContentsMargins(16, 0, 16, 0)

        self.stat_label = QLabel("🔍  Scanning database…")
        self.stat_label.setStyleSheet("color: #f1f5f9; font-weight: bold; font-size: 13px;")
        banner_layout.addWidget(self.stat_label)
        banner_layout.addStretch()

        self.refresh_btn = QPushButton("🔄  Refresh")
        self.refresh_btn.setObjectName("primaryBtn")
        self.refresh_btn.setMinimumHeight(32)
        self.refresh_btn.clicked.connect(self.refresh)
        banner_layout.addWidget(self.refresh_btn)
        layout.addWidget(self.banner)

        # ── Splitter: events table (top) + file detail panel (bottom) ────────
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Events table ─────────────────────────────────────────────────────────
        events_card = QFrame()
        events_card.setObjectName("card")
        events_layout = QVBoxLayout(events_card)
        events_layout.setContentsMargins(12, 12, 12, 12)

        table_title = QLabel("Events with Suspicious Files")
        table_title.setStyleSheet("font-weight: bold; font-size: 13px; color: #f1f5f9; margin-bottom: 6px;")
        events_layout.addWidget(table_title)

        self.events_table = QTableWidget(0, 6)
        self.events_table.setHorizontalHeaderLabels([
            "Timestamp", "USB Serial", "PC / Username",
            "Public IP", "Suspicious Files", "Threat Level"
        ])
        self.events_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.events_table.horizontalHeader().setStretchLastSection(True)
        self.events_table.verticalHeader().setVisible(False)
        self.events_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.events_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.events_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.events_table.setAlternatingRowColors(True)
        self.events_table.itemSelectionChanged.connect(self.on_row_selected)
        self.events_table.setStyleSheet("""
            QTableWidget { gridline-color: #1e293b; }
            QTableWidget::item:selected { background: #1e3a5f; }
            QTableWidget::item[threat="HIGH"] { color: #ef4444; font-weight: bold; }
        """)
        events_layout.addWidget(self.events_table)
        splitter.addWidget(events_card)

        # File detail panel ────────────────────────────────────────────────────
        detail_card = QFrame()
        detail_card.setObjectName("card")
        detail_layout = QVBoxLayout(detail_card)
        detail_layout.setContentsMargins(12, 10, 12, 10)

        detail_header_row = QHBoxLayout()
        detail_title = QLabel("File Details for Selected Event")
        detail_title.setStyleSheet("font-weight: bold; font-size: 13px; color: #f1f5f9;")
        detail_header_row.addWidget(detail_title)
        detail_layout.addLayout(detail_header_row)

        self.detail_table = QTableWidget(0, 3)
        self.detail_table.setHorizontalHeaderLabels(["File Name", "Detection Reason", "Full Path on USB"])
        self.detail_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.detail_table.horizontalHeader().setStretchLastSection(True)
        self.detail_table.verticalHeader().setVisible(False)
        self.detail_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.detail_table.setAlternatingRowColors(True)
        detail_layout.addWidget(self.detail_table)
        splitter.addWidget(detail_card)

        splitter.setSizes([380, 200])
        layout.addWidget(splitter, 1)

        self.refresh()

    # ─────────────────────────────────────────────────────────────────────────
    def refresh(self):
        """Pull all insertion events that have suspicious_files data."""
        self.events_table.setRowCount(0)
        self.detail_table.setRowCount(0)

        try:
            with self.db.get_connection() as conn:
                conn.row_factory = __import__("sqlite3").Row
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, timestamp, usb_serial, computer_name, username,
                           public_ip, suspicious_files
                    FROM device_logs
                    WHERE suspicious_files IS NOT NULL AND suspicious_files != '[]'
                    
                    UNION ALL
                    
                    SELECT id, timestamp, serial_number as usb_serial, computer_name, username,
                           public_ip, suspicious_files
                    FROM unknown_device_logs
                    WHERE suspicious_files IS NOT NULL AND suspicious_files != '[]'
                    
                    ORDER BY timestamp DESC
                """)
                rows = cursor.fetchall()
        except Exception as e:
            self.stat_label.setText(f"❌  Database error: {e}")
            return

        total_events = len(rows)
        total_files = 0

        for row in rows:
            raw_susp = row["suspicious_files"]
            try:
                files = json.loads(raw_susp)
            except Exception:
                files = []
            if not files:
                continue

            total_files += len(files)
            r = self.events_table.rowCount()
            self.events_table.insertRow(r)

            # Threat level
            if len(files) >= 5:
                threat = "🔴 HIGH"
                threat_color = QColor("#ef4444")
            elif len(files) >= 2:
                threat = "🟠 MEDIUM"
                threat_color = QColor("#f97316")
            else:
                threat = "🟡 LOW"
                threat_color = QColor("#eab308")

            cells = [
                str(row["timestamp"]),
                row["usb_serial"] or "—",
                f"{row['computer_name']} / {row['username']}",
                row["public_ip"] or "—",
                str(len(files)),
                threat,
            ]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
                if col == 4:  # file count column — highlight red
                    item.setForeground(threat_color)
                    item.setFont(QFont("Consolas", 12, QFont.Weight.Bold))
                if col == 5:
                    item.setForeground(threat_color)
                self.events_table.setItem(r, col, item)

            # Store raw JSON string in hidden first column data to prevent PyQt type issues
            self.events_table.item(r, 0).setData(Qt.ItemDataRole.UserRole, raw_susp)

        if total_events == 0:
            self.stat_label.setText("✅  No suspicious file events found in the database.")
        else:
            self.stat_label.setText(
                f"⚠️  {total_events} event(s) with suspicious files found  •  "
                f"{total_files} total suspicious file(s) detected"
            )
            self.stat_label.setStyleSheet("color: #ef4444; font-weight: bold; font-size: 13px;")

        self.events_table.resizeColumnsToContents()

    def on_row_selected(self):
        """Populate the detail table with files from the selected event row."""
        selected = self.events_table.selectedItems()
        if not selected:
            return
        row_idx = self.events_table.currentRow()
        first_cell = self.events_table.item(row_idx, 0)
        if not first_cell:
            return
        
        raw_susp = first_cell.data(Qt.ItemDataRole.UserRole)
        if not raw_susp:
            return

        try:
            files = json.loads(raw_susp)
        except Exception:
            files = []

        self.detail_table.setRowCount(0)
        for f in files:
            r = self.detail_table.rowCount()
            self.detail_table.insertRow(r)

            name_item = QTableWidgetItem(f.get("name", "—"))
            name_item.setForeground(QColor("#fca5a5"))
            name_item.setFont(QFont("Consolas", 11, QFont.Weight.Bold))

            reason_item = QTableWidgetItem(f.get("reason", "—"))
            reason_item.setForeground(QColor("#ef4444"))

            path_item = QTableWidgetItem(f.get("path", "—"))
            path_item.setForeground(QColor("#94a3b8"))

            self.detail_table.setItem(r, 0, name_item)
            self.detail_table.setItem(r, 1, reason_item)
            self.detail_table.setItem(r, 2, path_item)
            self.detail_table.setRowHeight(r, 28)

        self.detail_table.resizeColumnsToContents()
