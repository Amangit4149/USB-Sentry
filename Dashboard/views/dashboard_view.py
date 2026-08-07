import os
import sys
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QFrame, QTableWidget, QTableWidgetItem,
                             QHeaderView, QPushButton, QSizePolicy)
from PyQt6.QtCore import Qt, pyqtSignal, QSize
from PyQt6.QtGui import QColor, QFont
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

# Import startup manager for autorun toggling
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from Agent.startup_manager import StartupManager


class DashboardView(QWidget):
    def __init__(self, db_manager, agent_service, parent=None):
        super().__init__(parent)
        self.db = db_manager
        self.agent = agent_service
        self.startup_mgr = StartupManager()
        self.init_ui()

    # ─────────────────────────────────────────────────────────────────────────
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 20)
        layout.setSpacing(14)

        # ── 1. Professional header bar ────────────────────────────────────────
        header_bar = QFrame()
        header_bar.setObjectName("card")
        header_bar.setFixedHeight(72)
        header_bar.setStyleSheet(
            "QFrame#card { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "stop:0 #0f2744, stop:1 #1e293b); border: 1px solid #1e3a5f; border-radius: 10px; }"
        )
        hbar_layout = QHBoxLayout(header_bar)
        hbar_layout.setContentsMargins(20, 0, 16, 0)
        hbar_layout.setSpacing(12)

        # Title block
        title_block = QVBoxLayout()
        title_block.setSpacing(1)
        title_lbl = QLabel("🛡️  Smart USB Guardian")
        title_lbl.setStyleSheet("font-size: 18px; font-weight: 700; color: #f1f5f9;")
        subtitle_lbl = QLabel("Intelligent USB Tracking & Security Operations Centre")
        subtitle_lbl.setStyleSheet("font-size: 11px; color: #64748b;")
        title_block.addWidget(title_lbl)
        title_block.addWidget(subtitle_lbl)
        hbar_layout.addLayout(title_block)
        hbar_layout.addStretch()

        # ── Agent Status pill ──
        self.status_pill = QLabel("● INACTIVE")
        self.status_pill.setFixedHeight(30)
        self.status_pill.setContentsMargins(14, 0, 14, 0)
        self.status_pill.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        self.status_pill.setStyleSheet(
            "background:#1c1c2e; color:#f87171; border:1px solid #f87171;"
            "border-radius:15px; font-weight:700; font-size:12px;"
        )
        hbar_layout.addWidget(self.status_pill)

        # ── Autorun toggle button ──
        is_registered = self.startup_mgr.is_registered()
        self.autorun_btn = QPushButton()
        self.autorun_btn.setFixedHeight(34)
        self.autorun_btn.setMinimumWidth(155)
        self._refresh_autorun_btn_style(is_registered)
        self.autorun_btn.clicked.connect(self.toggle_autorun)
        hbar_layout.addWidget(self.autorun_btn)

        layout.addWidget(header_bar)

        # ── 2. Stat cards row ─────────────────────────────────────────────────
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(12)

        self.reg_card     = self._make_stat_card("💾  Registered USBs",     "0", "#38bdf8")
        self.events_card  = self._make_stat_card("📡  Security Events",     "0", "#a78bfa")
        self.unknown_card = self._make_stat_card("⚠️   Unknown Devices",   "0", "#f97316")
        self.alerts_card  = self._make_stat_card("✅  Alerts Dispatched",   "0", "#4ade80")

        for card in (self.reg_card, self.events_card, self.unknown_card, self.alerts_card):
            stats_layout.addWidget(card)
        layout.addLayout(stats_layout)

        # ── 3. Main split (activity table + chart) ────────────────────────────
        split_layout = QHBoxLayout()
        split_layout.setSpacing(12)

        # Activity table
        table_card = QFrame()
        table_card.setObjectName("card")
        table_layout = QVBoxLayout(table_card)
        table_layout.setContentsMargins(12, 10, 12, 10)

        table_title = QLabel("📋  Live Security Event Feed")
        table_title.setStyleSheet("font-weight:700; font-size:13px; color:#f1f5f9; margin-bottom:6px;")
        table_layout.addWidget(table_title)

        self.activity_table = QTableWidget(0, 6)
        self.activity_table.setHorizontalHeaderLabels(
            ["Time", "Device / Serial", "Event", "PC / User", "Public IP", "Threat"])
        self.activity_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.activity_table.verticalHeader().setVisible(False)
        self.activity_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.activity_table.setAlternatingRowColors(True)
        self.activity_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.activity_table.setStyleSheet("QTableWidget { gridline-color: #1e293b; }")
        table_layout.addWidget(self.activity_table)
        split_layout.addWidget(table_card, 3)

        # Chart panel
        chart_card = QFrame()
        chart_card.setObjectName("card")
        chart_layout = QVBoxLayout(chart_card)
        chart_layout.setContentsMargins(12, 10, 12, 10)

        chart_title = QLabel("📈  Activity Timeline (Last 7 Days)")
        chart_title.setStyleSheet("font-weight:700; font-size:13px; color:#f1f5f9; margin-bottom:4px;")
        chart_layout.addWidget(chart_title)

        self.figure = Figure(facecolor="#1e293b")
        self.canvas = FigureCanvas(self.figure)
        chart_layout.addWidget(self.canvas)
        split_layout.addWidget(chart_card, 2)

        layout.addLayout(split_layout, 1)

        # Initial render
        self.refresh_data()

    # ─────────────────────────────────────────────────────────────────────────
    def _make_stat_card(self, title: str, value: str, accent: str) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        card.setMinimumHeight(88)
        card.setStyleSheet(
            f"QFrame#card {{ border-left: 4px solid {accent}; border-radius: 8px; }}"
        )
        cl = QVBoxLayout(card)
        cl.setContentsMargins(16, 12, 16, 12)
        cl.setSpacing(4)

        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("font-size: 11px; color: #64748b; font-weight: 600; text-transform: uppercase;")
        cl.addWidget(lbl_title)

        lbl_value = QLabel(value)
        lbl_value.setObjectName("cardValue")
        lbl_value.setStyleSheet(f"font-size: 32px; font-weight: 800; color: {accent};")
        cl.addWidget(lbl_value)
        return card

    def _get_stat_value_label(self, card: QFrame) -> QLabel:
        return card.findChild(QLabel, "cardValue")

    # ─────────────────────────────────────────────────────────────────────────
    def _refresh_autorun_btn_style(self, is_registered: bool):
        if is_registered:
            self.autorun_btn.setText("🔁  Auto-Run: ON")
            self.autorun_btn.setStyleSheet(
                "QPushButton { background: #1e3a5f; color: #38bdf8; border: 1px solid #0ea5e9;"
                " border-radius: 6px; font-weight:700; padding: 0 16px; }"
                "QPushButton:hover { background: #164e84; }"
            )
        else:
            self.autorun_btn.setText("🔁  Auto-Run: OFF")
            self.autorun_btn.setStyleSheet(
                "QPushButton { background: #1e1e2e; color: #64748b; border: 1px solid #334155;"
                " border-radius: 6px; font-weight:700; padding: 0 16px; }"
                "QPushButton:hover { background: #27272e; }"
            )

    def toggle_autorun(self):
        if self.startup_mgr.is_registered():
            self.startup_mgr.unregister()
            self._refresh_autorun_btn_style(False)
        else:
            self.startup_mgr.register()
            self._refresh_autorun_btn_style(True)

    # ─────────────────────────────────────────────────────────────────────────
    def refresh_data(self):
        stats = self.db.get_device_statistics()

        self._get_stat_value_label(self.reg_card).setText(str(stats.get("total_registered", 0)))
        self._get_stat_value_label(self.events_card).setText(str(stats.get("total_events", 0)))
        self._get_stat_value_label(self.alerts_card).setText(str(stats.get("successful_alerts", 0)))

        # Count unknown devices
        try:
            with self.db.get_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT COUNT(*) FROM unknown_device_logs")
                unk_count = c.fetchone()[0]
        except Exception:
            unk_count = 0
        self._get_stat_value_label(self.unknown_card).setText(str(unk_count))

        # Activity table — blend registered events + unknown events
        logs = self.db.get_device_logs(limit=10)
        unknown_logs = self.db.get_unknown_device_events(limit=5)

        # Merge & sort by timestamp descending
        combined = []
        for log in logs:
            combined.append({
                "timestamp": str(log.get("timestamp", ""))[:19],
                "label": log.get("label") or log.get("usb_serial", "—"),
                "serial": log.get("usb_serial", "—"),
                "event": log.get("event_type", "—"),
                "pc_user": f"{log.get('computer_name','—')} / {log.get('username','—')}",
                "public_ip": log.get("public_ip", "—"),
                "threat": "⚠️ FILES" if log.get("suspicious_files") else "✅ Clean",
                "is_unknown": False,
            })
        for log in unknown_logs:
            combined.append({
                "timestamp": str(log.get("timestamp", ""))[:19],
                "label": f"[UNKNOWN] {log.get('manufacturer','?')}",
                "serial": log.get("serial_number", "—"),
                "event": "UNKNOWN_DEVICE",
                "pc_user": f"{log.get('computer_name','—')} / {log.get('username','—')}",
                "public_ip": log.get("public_ip", "—"),
                "threat": "⚠️ FILES" if log.get("suspicious_files") else "🔴 Unregistered",
                "is_unknown": True,
            })
        combined.sort(key=lambda x: x["timestamp"], reverse=True)
        combined = combined[:15]

        self.activity_table.setRowCount(len(combined))
        for r, row in enumerate(combined):
            cells = [
                row["timestamp"],
                f"{row['label']}\n{row['serial']}",
                row["event"],
                row["pc_user"],
                row["public_ip"],
                row["threat"],
            ]
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
                # Colour coding
                if row["is_unknown"]:
                    item.setBackground(QColor("#2d1a0a"))
                    item.setForeground(QColor("#f97316"))
                elif row["event"] == "INSERTION":
                    if c == 2:
                        item.setForeground(QColor("#4ade80"))
                elif row["event"] == "REMOVAL":
                    if c == 2:
                        item.setForeground(QColor("#f87171"))
                if c == 5 and "FILES" in text:
                    item.setForeground(QColor("#ef4444"))
                    item.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
                self.activity_table.setItem(r, c, item)
            self.activity_table.setRowHeight(r, 36)

        self.update_agent_status_ui()
        self.draw_chart(stats.get("timeline", []))

    # ─────────────────────────────────────────────────────────────────────────
    def update_agent_status_ui(self):
        if self.agent.active:
            self.status_pill.setText("● ACTIVE")
            self.status_pill.setStyleSheet(
                "background:#0d2b1a; color:#4ade80; border:1px solid #16a34a;"
                "border-radius:15px; font-weight:700; font-size:12px; padding: 0 14px;"
            )
        else:
            self.status_pill.setText("● INACTIVE")
            self.status_pill.setStyleSheet(
                "background:#1c1c2e; color:#f87171; border:1px solid #f87171;"
                "border-radius:15px; font-weight:700; font-size:12px; padding: 0 14px;"
            )

    # ─────────────────────────────────────────────────────────────────────────
    def draw_chart(self, timeline):
        self.figure.clear()
        if not timeline:
            ax = self.figure.add_subplot(111)
            ax.set_facecolor("#1e293b")
            ax.text(0.5, 0.5, "No Activity Data Yet", color="#475569",
                    ha="center", va="center", fontsize=11)
            ax.axis("off")
            self.canvas.draw()
            return
        try:
            timeline = sorted(timeline, key=lambda x: x["date_val"])
            dates = [t["date_val"] for t in timeline]
            counts = [t["count_val"] for t in timeline]

            ax = self.figure.add_subplot(111)
            ax.set_facecolor("#1e293b")
            ax.plot(dates, counts, color="#38bdf8", marker="o", linewidth=2, markersize=6)
            ax.fill_between(dates, counts, color="#38bdf8", alpha=0.12)
            ax.tick_params(colors="#64748b", labelsize=8)
            for spine in ax.spines.values():
                spine.set_color("#334155")
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)
            ax.grid(axis="y", linestyle="--", color="#334155", alpha=0.5)
            self.figure.tight_layout(pad=1.2)
            self.canvas.draw()
        except Exception as e:
            print(f"Chart render error: {e}")
