"""
Dashboard view: Unknown / Unregistered USB Devices
Every unregistered pendrive insertion is captured here with full forensic details.
Users can see WHO plugged it in, WHEN, WHERE, and WHAT files it had.
"""
import json
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QPushButton, QFrame, QHeaderView,
    QAbstractItemView, QSplitter, QScrollArea, QGridLayout,
    QLineEdit, QSizePolicy
)
from PyQt6.QtCore import Qt, QDateTime, QTimer
from PyQt6.QtGui import QColor, QFont


class UnknownDevicesView(QWidget):
    def __init__(self, db_manager, parent=None):
        super().__init__(parent)
        self.db = db_manager
        self._all_rows = []
        self.init_ui()
        
        # Auto-refresh every 5 seconds when visible
        self._auto_refresh_timer = QTimer(self)
        self._auto_refresh_timer.timeout.connect(self._auto_refresh)
        self._auto_refresh_timer.start(5000)
    
    def _auto_refresh(self):
        if self.isVisible():
            self.refresh()

    # ─────────────────────────────────────────────────────────────────────────
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        # ── Header ────────────────────────────────────────────────────────────
        hdr_row = QHBoxLayout()

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title = QLabel("⚠️  Unregistered USB Intrusion Log")
        title.setStyleSheet("font-size:18px; font-weight:800; color:#f1f5f9;")
        subtitle = QLabel(
            "Every unregistered pendrive plugged into this machine is captured below. "
            "Click any row to see the full forensic report.")
        subtitle.setStyleSheet("font-size:12px; color:#64748b;")
        subtitle.setWordWrap(True)
        title_col.addWidget(title)
        title_col.addWidget(subtitle)
        hdr_row.addLayout(title_col, 1)

        # Live badge
        self.badge = QLabel("  ● AGENT ACTIVE – Monitoring all USB ports  ")
        self.badge.setFixedHeight(28)
        self.badge.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        self.badge.setStyleSheet(
            "background:#0d2b1a; color:#4ade80; border:1px solid #16a34a;"
            " border-radius:14px; font-weight:700; font-size:11px; padding:0 10px;"
        )
        hdr_row.addWidget(self.badge)

        refresh_btn = QPushButton("🔄  Refresh")
        refresh_btn.setFixedHeight(30)
        refresh_btn.setObjectName("primaryBtn")
        refresh_btn.clicked.connect(self.refresh)
        hdr_row.addWidget(refresh_btn)
        layout.addLayout(hdr_row)

        # ── Stat bar ──────────────────────────────────────────────────────────
        stat_bar = QFrame()
        stat_bar.setObjectName("card")
        stat_bar.setFixedHeight(80)
        sb_layout = QHBoxLayout(stat_bar)
        sb_layout.setContentsMargins(16, 0, 16, 0)
        sb_layout.setSpacing(24)

        self.stat_total   = self._stat_pill("Total Events",    "0", "#f97316")
        self.stat_today   = self._stat_pill("Today",           "0", "#ef4444")
        self.stat_susp    = self._stat_pill("With Susp. Files","0", "#a78bfa")
        self.stat_unique  = self._stat_pill("Unique Serials",  "0", "#38bdf8")

        for pill in (self.stat_total, self.stat_today, self.stat_susp, self.stat_unique):
            sb_layout.addWidget(pill)
        sb_layout.addStretch()

        # Search box
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("🔍  Filter by serial, PC, user, IP…")
        self.search_box.setFixedWidth(260)
        self.search_box.setFixedHeight(30)
        self.search_box.setStyleSheet(
            "background:#1e293b; color:#f1f5f9; border:1px solid #334155;"
            " border-radius:6px; padding:0 10px; font-size:12px;"
        )
        self.search_box.textChanged.connect(self._apply_filter)
        sb_layout.addWidget(self.search_box)
        layout.addWidget(stat_bar)

        # ── Splitter: events table (top) + forensic detail panel (bottom) ────
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Events table ─────────────────────────────────────────────────────────
        tbl_card = QFrame()
        tbl_card.setObjectName("card")
        tbl_layout = QVBoxLayout(tbl_card)
        tbl_layout.setContentsMargins(12, 10, 12, 10)
        tbl_layout.setSpacing(6)

        tbl_hdr = QLabel("📋  Captured Unregistered USB Events")
        tbl_hdr.setStyleSheet("font-weight:700; font-size:13px; color:#f1f5f9;")
        tbl_layout.addWidget(tbl_hdr)

        self.events_table = QTableWidget(0, 8)
        self.events_table.setHorizontalHeaderLabels([
            "Date & Time", "Serial Number", "Manufacturer",
            "Drive", "PC Name", "Logged-In User",
            "Public IP", "Threat"
        ])
        hh = self.events_table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hh.setStretchLastSection(True)
        self.events_table.verticalHeader().setVisible(False)
        self.events_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.events_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.events_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.events_table.setAlternatingRowColors(True)
        self.events_table.setStyleSheet(
            "QTableWidget { gridline-color: #1e293b; }"
            "QTableWidget::item:selected { background:#1e3a5f; color:#f1f5f9; }"
        )
        self.events_table.itemSelectionChanged.connect(self._on_row_selected)
        tbl_layout.addWidget(self.events_table)
        splitter.addWidget(tbl_card)

        # Forensic detail panel ────────────────────────────────────────────────
        detail_card = QFrame()
        detail_card.setObjectName("card")
        detail_layout = QVBoxLayout(detail_card)
        detail_layout.setContentsMargins(14, 10, 14, 10)
        detail_layout.setSpacing(8)

        detail_hdr = QHBoxLayout()
        detail_title = QLabel("🔬  Forensic Report — Selected Event")
        detail_title.setStyleSheet("font-weight:700; font-size:13px; color:#f1f5f9;")
        detail_hdr.addWidget(detail_title)
        detail_hdr.addStretch()
        self.detail_hint = QLabel("← Select a row above to view details")
        self.detail_hint.setStyleSheet("font-size:11px; color:#475569; font-style:italic;")
        detail_hdr.addWidget(self.detail_hint)
        detail_layout.addLayout(detail_hdr)

        # Scrollable grid for detail fields + suspicious file table side-by-side
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border:none; background:transparent; }")
        detail_inner = QWidget()
        detail_inner.setStyleSheet("background:transparent;")
        inner_row = QHBoxLayout(detail_inner)
        inner_row.setContentsMargins(0, 0, 0, 0)
        inner_row.setSpacing(16)

        # Left: key-value grid
        grid_frame = QFrame()
        grid_frame.setStyleSheet("background:transparent;")
        self.kv_grid = QGridLayout(grid_frame)
        self.kv_grid.setContentsMargins(0, 0, 0, 0)
        self.kv_grid.setSpacing(6)
        self.kv_grid.setColumnMinimumWidth(0, 160)
        inner_row.addWidget(grid_frame, 1)

        # Right: suspicious file table
        susp_frame = QFrame()
        susp_frame.setObjectName("card")
        susp_frame.setStyleSheet(
            "QFrame#card { background:#2d1a0a; border:1px solid #7c2d12; border-radius:8px; }"
        )
        susp_v = QVBoxLayout(susp_frame)
        susp_v.setContentsMargins(10, 8, 10, 8)
        susp_v.setSpacing(4)
        susp_lbl = QLabel("⚠️  Suspicious Files on Drive")
        susp_lbl.setStyleSheet("font-weight:700; color:#f97316; font-size:12px;")
        susp_v.addWidget(susp_lbl)

        self.susp_table = QTableWidget(0, 3)
        self.susp_table.setHorizontalHeaderLabels(["File Name", "Reason", "Path"])
        self.susp_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.susp_table.horizontalHeader().setStretchLastSection(True)
        self.susp_table.verticalHeader().setVisible(False)
        self.susp_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.susp_table.setStyleSheet(
            "QTableWidget { background:#2d1a0a; gridline-color:#3d2222; color:#fecaca; }"
            "QHeaderView::section { background:#3d2222; color:#fca5a5; }"
        )
        self.susp_table.setFixedWidth(420)
        self.susp_table.setMinimumHeight(150)
        susp_v.addWidget(self.susp_table)
        inner_row.addWidget(susp_frame)

        scroll.setWidget(detail_inner)
        detail_layout.addWidget(scroll, 1)
        splitter.addWidget(detail_card)

        splitter.setSizes([420, 260])
        layout.addWidget(splitter, 1)

        self.refresh()

    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def _stat_pill(label: str, value: str, color: str) -> QFrame:
        f = QFrame()
        f.setStyleSheet("background:transparent;")
        v = QVBoxLayout(f)
        v.setContentsMargins(0, 4, 0, 4)
        v.setSpacing(1)
        lbl = QLabel(value)
        lbl.setObjectName("sv")
        lbl.setStyleSheet(f"font-size:22px; font-weight:800; color:{color};")
        sub = QLabel(label)
        sub.setStyleSheet("font-size:10px; color:#64748b; font-weight:600;")
        v.addWidget(lbl)
        v.addWidget(sub)
        return f

    def _update_pill(self, frame: QFrame, value: str):
        frame.findChild(QLabel, "sv").setText(value)

    # ─────────────────────────────────────────────────────────────────────────
    def refresh(self):
        rows = self.db.get_unknown_device_events(limit=500)
        self._all_rows = rows
        self._populate_table(rows)

        # Stats
        today_str = QDateTime.currentDateTime().toString("yyyy-MM-dd")
        today_count = sum(1 for r in rows if str(r.get("timestamp","")).startswith(today_str))
        susp_count  = sum(1 for r in rows if r.get("suspicious_files") and r["suspicious_files"] != "[]")
        serials     = len({r.get("serial_number","") for r in rows if r.get("serial_number")})

        self._update_pill(self.stat_total,  str(len(rows)))
        self._update_pill(self.stat_today,  str(today_count))
        self._update_pill(self.stat_susp,   str(susp_count))
        self._update_pill(self.stat_unique, str(serials))

        # Clear detail panel
        self._clear_detail()

    def _populate_table(self, rows):
        self.events_table.setRowCount(0)
        for row in rows:
            try:
                susp = json.loads(row.get("suspicious_files") or "[]")
            except Exception:
                susp = []

            threat = f"🔴 {len(susp)} file(s)" if susp else "✅ Clean"
            cells = [
                str(row.get("timestamp",""))[:19],
                row.get("serial_number","—"),
                row.get("manufacturer","—"),
                row.get("drive_letter","—"),
                row.get("computer_name","—"),
                row.get("username","—"),
                row.get("public_ip","—"),
                threat,
            ]
            r = self.events_table.rowCount()
            self.events_table.insertRow(r)
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
                if c == 7 and susp:
                    item.setForeground(QColor("#ef4444"))
                    item.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
                elif c == 7:
                    item.setForeground(QColor("#4ade80"))
                # Highlight rows with suspicious files
                if susp:
                    item.setBackground(QColor("#1c1007"))
                self.events_table.setItem(r, c, item)
            # Store raw record as a dict in first cell to avoid sqlite3.Row binding issues
            row_dict = dict(row)
            self.events_table.item(r, 0).setData(Qt.ItemDataRole.UserRole, row_dict)
            self.events_table.setRowHeight(r, 30)

        # Auto-resize columns to fit content
        self.events_table.resizeColumnsToContents()

    def _apply_filter(self, text: str):
        q = text.strip().lower()
        if not q:
            self._populate_table(self._all_rows)
            return
        filtered = [
            r for r in self._all_rows
            if q in str(r.get("serial_number","")).lower()
            or q in str(r.get("computer_name","")).lower()
            or q in str(r.get("username","")).lower()
            or q in str(r.get("public_ip","")).lower()
            or q in str(r.get("manufacturer","")).lower()
        ]
        self._populate_table(filtered)

    # ─────────────────────────────────────────────────────────────────────────
    def _on_row_selected(self):
        sel = self.events_table.selectedItems()
        if not sel:
            return
        row_data = self.events_table.item(self.events_table.currentRow(), 0).data(
            Qt.ItemDataRole.UserRole
        )
        if not row_data:
            return
        self._render_detail(row_data)

    def _clear_detail(self):
        while self.kv_grid.count():
            item = self.kv_grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.susp_table.setRowCount(0)

    def _render_detail(self, row: dict):
        self._clear_detail()
        self.detail_hint.setText("")

        # Detect threat level
        try:
            susp_files = json.loads(row.get("suspicious_files") or "[]")
        except Exception:
            susp_files = []

        fields = [
            ("📅  Date & Time",        str(row.get("timestamp","—"))[:19]),
            ("🔢  Serial Number",       row.get("serial_number","—")),
            ("🏭  Manufacturer",        row.get("manufacturer","—")),
            ("🔌  VID / PID",           f"{row.get('vid','—')} / {row.get('pid','—')}"),
            ("💾  Drive Letter",        row.get("drive_letter","—")),
            ("🖥️  Computer Name",       row.get("computer_name","—")),
            ("👤  Logged-In User",      row.get("username","—")),
            ("💻  Operating System",    row.get("os_version","—")),
            ("🌐  Local IP Address",    row.get("local_ip","—")),
            ("🌍  Public IP Address",   row.get("public_ip","—")),
            ("🔒  MAC Address",         row.get("mac_address","—")),
            ("⚠️  Suspicious Files",   f"{len(susp_files)} file(s) detected" if susp_files else "None"),
        ]

        for row_idx, (key, val) in enumerate(fields):
            key_lbl = QLabel(key)
            key_lbl.setStyleSheet("color:#64748b; font-size:12px; font-weight:600;")
            key_lbl.setFixedWidth(180)

            val_lbl = QLabel(str(val))
            is_alert = (key.startswith("⚠️") and susp_files)
            val_color = "#ef4444" if is_alert else "#f1f5f9"
            val_lbl.setStyleSheet(
                f"color:{val_color}; font-size:12px; font-weight:{'700' if is_alert else '400'};"
                f"font-family:{'Consolas' if 'IP' in key or 'MAC' in key or 'Serial' in key else 'Segoe UI'};"
            )
            val_lbl.setWordWrap(True)
            val_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

            self.kv_grid.addWidget(key_lbl, row_idx, 0, Qt.AlignmentFlag.AlignTop)
            self.kv_grid.addWidget(val_lbl, row_idx, 1, Qt.AlignmentFlag.AlignTop)

        # Populate suspicious files table
        self.susp_table.setRowCount(0)
        if susp_files:
            for f in susp_files:
                r = self.susp_table.rowCount()
                self.susp_table.insertRow(r)
                name_item  = QTableWidgetItem(f.get("name","—"))
                reason_item = QTableWidgetItem(f.get("reason","—"))
                path_item  = QTableWidgetItem(f.get("path","—"))
                name_item.setForeground(QColor("#fca5a5"))
                name_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
                reason_item.setForeground(QColor("#ef4444"))
                path_item.setForeground(QColor("#94a3b8"))
                self.susp_table.setItem(r, 0, name_item)
                self.susp_table.setItem(r, 1, reason_item)
                self.susp_table.setItem(r, 2, path_item)
                self.susp_table.setRowHeight(r, 26)
        else:
            # Show "clean" placeholder
            self.susp_table.insertRow(0)
            clean = QTableWidgetItem("✅  No suspicious files found on this drive")
            clean.setForeground(QColor("#4ade80"))
            clean.setFont(QFont("Segoe UI", 10))
            self.susp_table.setItem(0, 0, clean)
            self.susp_table.setSpan(0, 0, 1, 3)

        # Auto-resize columns to fit content
        self.susp_table.resizeColumnsToContents()
