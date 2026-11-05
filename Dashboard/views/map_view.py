import os
import webbrowser
import folium
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QFrame, QTableWidget, QTableWidgetItem, QHeaderView, 
                             QPushButton, QMessageBox)
from PyQt6.QtCore import Qt

class MapView(QWidget):
    def __init__(self, db_manager, parent=None):
        super().__init__(parent)
        self.db = db_manager
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Header Block
        header_layout = QHBoxLayout()
        header = QLabel("Geographical Tracking Map")
        header.setObjectName("sectionHeader")
        header_layout.addWidget(header)
        
        header_layout.addStretch()
        
        self.folium_btn = QPushButton("Launch Folium Interactive Map")
        self.folium_btn.setObjectName("primaryBtn")
        self.folium_btn.clicked.connect(self.generate_and_open_folium_map)
        header_layout.addWidget(self.folium_btn)
        
        layout.addLayout(header_layout)

        # Main Layout: Table of coordinates + Details panel
        main_layout = QHBoxLayout()
        
        # Coordinates List Card
        list_container = QFrame()
        list_container.setObjectName("card")
        list_layout = QVBoxLayout(list_container)
        
        list_title = QLabel("Captured GPS Coordinates")
        list_title.setStyleSheet("font-weight: bold; font-size: 14px; color: #f1f5f9; margin-bottom: 5px;")
        list_layout.addWidget(list_title)
        
        self.map_table = QTableWidget(0, 6)
        self.map_table.setHorizontalHeaderLabels(["Timestamp", "USB Device", "Country", "City", "Latitude", "Longitude"])
        self.map_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.map_table.horizontalHeader().setStretchLastSection(True)
        self.map_table.verticalHeader().setVisible(False)
        self.map_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.map_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.map_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        list_layout.addWidget(self.map_table)
        
        main_layout.addWidget(list_container, 3)

        # Quick Actions Card
        details_container = QFrame()
        details_container.setObjectName("card")
        details_layout = QVBoxLayout(details_container)
        details_layout.setContentsMargins(15, 15, 15, 15)
        
        details_title = QLabel("Selected Location Actions")
        details_title.setStyleSheet("font-weight: bold; font-size: 14px; color: #f1f5f9; margin-bottom: 15px;")
        details_layout.addWidget(details_title)
        
        self.info_box = QLabel("Select a tracking entry from the list to view maps options.")
        self.info_box.setWordWrap(True)
        self.info_box.setStyleSheet("color: #94a3b8; font-size: 13px; line-height: 1.4;")
        details_layout.addWidget(self.info_box)
        
        details_layout.addStretch()
        
        self.google_maps_btn = QPushButton("Open in Google Maps")
        self.google_maps_btn.setObjectName("secondaryBtn")
        self.google_maps_btn.setEnabled(False)
        self.google_maps_btn.clicked.connect(self.open_in_google_maps)
        details_layout.addWidget(self.google_maps_btn)
        
        main_layout.addWidget(details_container, 1)
        layout.addLayout(main_layout)

        # Connect Table selection change
        self.map_table.itemSelectionChanged.connect(self.on_selection_changed)

        # Refresh
        self.refresh_map_logs()

    def refresh_map_logs(self):
        """Reloads coordinate events from SQLite."""
        self.logs = self.db.get_location_logs(limit=100)
        self.map_table.setRowCount(len(self.logs))
        for row_idx, log in enumerate(self.logs):
            self.map_table.setItem(row_idx, 0, QTableWidgetItem(log.get("timestamp", "")[:19]))
            self.map_table.setItem(row_idx, 1, QTableWidgetItem(log.get("label") or "Unknown"))
            self.map_table.setItem(row_idx, 2, QTableWidgetItem(log.get("country", "Unknown")))
            self.map_table.setItem(row_idx, 3, QTableWidgetItem(log.get("city", "Unknown")))
            self.map_table.setItem(row_idx, 4, QTableWidgetItem(f"{log.get('latitude', 0.0):.5f}"))
            self.map_table.setItem(row_idx, 5, QTableWidgetItem(f"{log.get('longitude', 0.0):.5f}"))

        self.google_maps_btn.setEnabled(False)
        self.info_box.setText("Select a tracking entry from the list to view maps options.")
        self.map_table.resizeColumnsToContents()

    def on_selection_changed(self):
        """Triggered when user clicks a row. Enables coordinates buttons."""
        selected_ranges = self.map_table.selectedRanges()
        if not selected_ranges:
            self.google_maps_btn.setEnabled(False)
            return

        row = selected_ranges[0].topRow()
        log = self.logs[row]
        
        details_text = (
            f"📍 *Device Tracking Event*\n\n"
            f"*USB Device:* {log.get('label', 'Unknown')}\n"
            f"*Serial:* {log.get('usb_serial')}\n"
            f"*Country:* {log.get('country')}\n"
            f"*State/City:* {log.get('state')} / {log.get('city')}\n"
            f"*Coordinates:* {log.get('latitude')}, {log.get('longitude')}\n"
            f"*Timestamp:* {log.get('timestamp')[:19]}"
        )
        self.info_box.setText(details_text.replace("*", ""))
        self.google_maps_btn.setEnabled(True)

    def open_in_google_maps(self):
        """Launches Google Maps coordinate URL in browser."""
        selected_ranges = self.map_table.selectedRanges()
        if not selected_ranges:
            return
            
        row = selected_ranges[0].topRow()
        log = self.logs[row]
        link = log.get("maps_link")
        
        if link:
            webbrowser.open(link)
        else:
            lat = log.get("latitude")
            lon = log.get("longitude")
            if lat and lon:
                webbrowser.open(f"https://www.google.com/maps?q={lat},{lon}")

    def generate_and_open_folium_map(self):
        """Generates a Folium maps HTML representation of all logged coordinates and launches in browser."""
        logs = self.db.get_location_logs(limit=250)
        valid_logs = [l for l in logs if l.get("latitude") and l.get("longitude")]

        if not valid_logs:
            QMessageBox.information(self, "No Coordinates", "There are no captured geolocation events in the database to display.")
            return

        try:
            # Average coordinates to center map
            avg_lat = sum(l["latitude"] for l in valid_logs) / len(valid_logs)
            avg_lon = sum(l["longitude"] for l in valid_logs) / len(valid_logs)
            
            # Create Map
            m = folium.Map(location=[avg_lat, avg_lon], zoom_start=4, control_scale=True)
            
            # Add markers
            for log in valid_logs:
                lat = log["latitude"]
                lon = log["longitude"]
                
                popup_html = (
                    f"<div style='font-family: Arial, sans-serif; color: #1e293b;'>"
                    f"<h4>🛡️ USB Insertion Tracking</h4>"
                    f"<b>Device:</b> {log.get('label')}<br/>"
                    f"<b>Serial:</b> {log.get('usb_serial')}<br/>"
                    f"<b>City:</b> {log.get('city')}, {log.get('country')}<br/>"
                    f"<b>Time:</b> {log.get('timestamp')[:19]}<br/>"
                    f"<b>Coordinates:</b> {lat:.5f}, {lon:.5f}<br/>"
                    f"</div>"
                )
                
                folium.Marker(
                    location=[lat, lon],
                    popup=folium.Popup(popup_html, max_width=300),
                    tooltip=f"{log.get('label')} - {log.get('city')}",
                    icon=folium.Icon(color="red", icon="info-sign")
                ).add_to(m)
                
            # Save HTML to user temp directory (avoid polluting project directory or Git tracking)
            import tempfile
            map_path = os.path.join(tempfile.gettempdir(), "usb_sentry_map.html")
            m.save(map_path)
            
            # Open in browser
            webbrowser.open(map_path)
        except Exception as e:
            QMessageBox.critical(self, "Map Generation Failed", f"Failed to generate Folium map: {str(e)}")
