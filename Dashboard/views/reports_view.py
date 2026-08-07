import os
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QFrame, QPushButton, QFileDialog, QMessageBox, QRadioButton, QButtonGroup)
from Reports.report_generator import ReportGenerator

class ReportsView(QWidget):
    def __init__(self, db_manager, parent=None):
        super().__init__(parent)
        self.db = db_manager
        self.generator = ReportGenerator(self.db)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        # Header
        header = QLabel("Security Reporting & Audit Center")
        header.setObjectName("sectionHeader")
        layout.addWidget(header)

        # Content Split Layout
        split_layout = QHBoxLayout()
        
        # Left Side: PDF Report Builder Card
        pdf_container = QFrame()
        pdf_container.setObjectName("card")
        pdf_layout = QVBoxLayout(pdf_container)
        pdf_layout.setContentsMargins(20, 20, 20, 20)
        
        pdf_title = QLabel("PDF Security Audit Report")
        pdf_title.setStyleSheet("font-weight: bold; font-size: 16px; color: #38bdf8; margin-bottom: 10px;")
        pdf_layout.addWidget(pdf_title)
        
        pdf_desc = QLabel(
            "Compile a comprehensive, print-ready PDF document containing:\n\n"
            "• High-level system activity statistics.\n"
            "• Detailed tables of all registered USB profiles.\n"
            "• Recent device insertion/removal event history.\n"
            "• Embedded graphical connection timeline charts.\n\n"
            "Classification: CONFIDENTIAL / ADMINISTRATOR USE ONLY."
        )
        pdf_desc.setStyleSheet("color: #94a3b8; font-size: 13px; line-height: 1.5; margin-bottom: 20px;")
        pdf_desc.setWordWrap(True)
        pdf_layout.addWidget(pdf_desc)
        
        pdf_layout.addStretch()
        
        self.build_pdf_btn = QPushButton("Generate PDF Audit Report")
        self.build_pdf_btn.setObjectName("primaryBtn")
        self.build_pdf_btn.setFixedHeight(40)
        self.build_pdf_btn.clicked.connect(self.generate_pdf)
        pdf_layout.addWidget(self.build_pdf_btn)
        
        split_layout.addWidget(pdf_container, 1)

        # Right Side: CSV Spreadsheet Exporter Card
        csv_container = QFrame()
        csv_container.setObjectName("card")
        csv_layout = QVBoxLayout(csv_container)
        csv_layout.setContentsMargins(20, 20, 20, 20)
        
        csv_title = QLabel("CSV Spreadsheet Exporter")
        csv_title.setStyleSheet("font-weight: bold; font-size: 16px; color: #38bdf8; margin-bottom: 10px;")
        csv_layout.addWidget(csv_title)
        
        csv_desc = QLabel(
            "Export raw historical records directly to standard Excel-friendly CSV spreadsheets. "
            "Select the dataset you wish to export:"
        )
        csv_desc.setStyleSheet("color: #94a3b8; font-size: 13px; line-height: 1.5; margin-bottom: 15px;")
        csv_desc.setWordWrap(True)
        csv_layout.addWidget(csv_desc)

        # Selection Group
        self.csv_group = QButtonGroup(self)
        
        self.radio_devices = QRadioButton("Device Connection Events log")
        self.radio_devices.setChecked(True)
        self.csv_group.addButton(self.radio_devices, 1)
        csv_layout.addWidget(self.radio_devices)
        
        self.radio_location = QRadioButton("Geographical Coordinates tracking log")
        self.csv_group.addButton(self.radio_location, 2)
        csv_layout.addWidget(self.radio_location)
        
        self.radio_emails = QRadioButton("Security Notification Dispatch status log")
        self.csv_group.addButton(self.radio_emails, 3)
        csv_layout.addWidget(self.radio_emails)
        
        csv_layout.addStretch()
        
        self.build_csv_btn = QPushButton("Export selected data (CSV)")
        self.build_csv_btn.setObjectName("secondaryBtn")
        self.build_csv_btn.setFixedHeight(40)
        self.build_csv_btn.clicked.connect(self.generate_csv)
        csv_layout.addWidget(self.build_csv_btn)

        split_layout.addWidget(csv_container, 1)
        layout.addLayout(split_layout)

    def generate_pdf(self):
        """Triggers system save dialog and exports PDF audit log."""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save PDF Security Report", 
            os.path.join(os.path.expanduser("~"), "Documents", "smart_usb_guardian_report.pdf"), 
            "PDF Documents (*.pdf)"
        )
        
        if not file_path:
            return

        self.build_pdf_btn.setEnabled(False)
        self.build_pdf_btn.setText("Generating Report...")
        
        success = self.generator.generate_pdf_report(file_path)
        
        self.build_pdf_btn.setEnabled(True)
        self.build_pdf_btn.setText("Generate PDF Audit Report")
        
        if success:
            QMessageBox.information(
                self, "Success", 
                f"PDF Security Audit Report generated successfully at:\n\n{file_path}"
            )
        else:
            QMessageBox.critical(
                self, "Error", 
                "An error occurred while compiling the PDF. Please check write permissions."
            )

    def generate_csv(self):
        """Triggers system save dialog and exports selected logs to CSV."""
        selected_id = self.csv_group.checkedId()
        
        if selected_id == 1:
            log_type = "device"
            default_name = "usb_connections_log.csv"
        elif selected_id == 2:
            log_type = "location"
            default_name = "usb_geo_tracking_log.csv"
        else:
            log_type = "email"
            default_name = "usb_notifications_log.csv"

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV Logs", 
            os.path.join(os.path.expanduser("~"), "Documents", default_name), 
            "CSV Spreadsheet (*.csv)"
        )
        
        if not file_path:
            return

        success = self.generator.generate_csv_report(file_path, log_type)
        
        if success:
            QMessageBox.information(
                self, "Success", 
                f"Dataset exported successfully to CSV spreadsheet:\n\n{file_path}"
            )
        else:
            QMessageBox.critical(
                self, "Error", 
                "An error occurred while saving the CSV spreadsheet."
            )
