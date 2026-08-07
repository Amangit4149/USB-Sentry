import os
import json
import wmi
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QFrame, QTableWidget, QTableWidgetItem, QHeaderView, 
                             QPushButton, QLineEdit, QFormLayout, QComboBox, QMessageBox)
from PyQt6.QtCore import Qt
from USBMonitor.monitor import USBMonitor, SIGNING_KEY

class DevicesView(QWidget):
    def __init__(self, db_manager, parent=None):
        super().__init__(parent)
        self.db = db_manager
        self._wmi_conn = None
        self.init_ui()

    def init_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        # Left Column: Registered USBs Table
        table_container = QFrame()
        table_container.setObjectName("card")
        table_layout = QVBoxLayout(table_container)
        
        table_header = QLabel("Registered USB Drives")
        table_header.setObjectName("sectionHeader")
        table_layout.addWidget(table_header)

        self.devices_table = QTableWidget(0, 5)
        self.devices_table.setHorizontalHeaderLabels(["Label", "Serial Number", "Manufacturer", "Owner", "Email"])
        self.devices_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.devices_table.verticalHeader().setVisible(False)
        self.devices_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.devices_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.devices_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table_layout.addWidget(self.devices_table)
        
        # Action Buttons below table
        actions_layout = QHBoxLayout()
        self.delete_btn = QPushButton("Delete Selected Device")
        self.delete_btn.setObjectName("dangerBtn")
        self.delete_btn.clicked.connect(self.delete_selected_device)
        actions_layout.addWidget(self.delete_btn)
        actions_layout.addStretch()
        table_layout.addLayout(actions_layout)

        layout.addWidget(table_container, 3)

        # Right Column: Registration & Provisioning Form
        form_container = QFrame()
        form_container.setObjectName("card")
        form_layout = QVBoxLayout(form_container)
        
        form_header = QLabel("Device Provisioning")
        form_header.setObjectName("sectionHeader")
        form_layout.addWidget(form_header)
        
        # Drive detection dropdown for auto-fill
        detect_layout = QHBoxLayout()
        detect_label = QLabel("Detect USB Drive:")
        detect_layout.addWidget(detect_label)
        
        self.drive_selector = QComboBox()
        self.refresh_drives()
        detect_layout.addWidget(self.drive_selector)
        
        self.detect_btn = QPushButton("Detect & Auto-Fill")
        self.detect_btn.setObjectName("secondaryBtn")
        self.detect_btn.clicked.connect(self.auto_fill_usb_details)
        detect_layout.addWidget(self.detect_btn)
        form_layout.addLayout(detect_layout)
        
        # Registration Form fields
        self.input_form = QFormLayout()
        self.input_form.setSpacing(10)
        
        self.serial_input = QLineEdit()
        self.label_input = QLineEdit()
        self.mfr_input = QLineEdit()
        self.pid_input = QLineEdit()
        self.vid_input = QLineEdit()
        self.owner_input = QLineEdit()
        self.email_input = QLineEdit()
        self.contact_input = QLineEdit()
        
        self.input_form.addRow("USB Serial Number:", self.serial_input)
        self.input_form.addRow("Volume Label:", self.label_input)
        self.input_form.addRow("Manufacturer:", self.mfr_input)
        self.input_form.addRow("Product ID (PID):", self.pid_input)
        self.input_form.addRow("Vendor ID (VID):", self.vid_input)
        self.input_form.addRow("Owner Full Name:", self.owner_input)
        self.input_form.addRow("Owner Email Address:", self.email_input)
        self.input_form.addRow("Emergency Phone/Contact:", self.contact_input)
        
        form_layout.addLayout(self.input_form)
        
        # Provisioning actions
        provision_btns_layout = QHBoxLayout()
        self.register_only_btn = QPushButton("Register Locally Only")
        self.register_only_btn.setObjectName("secondaryBtn")
        self.register_only_btn.clicked.connect(self.register_device_only)
        
        self.provision_btn = QPushButton("Provision & Register")
        self.provision_btn.setObjectName("primaryBtn")
        self.provision_btn.clicked.connect(self.provision_and_register_device)
        
        provision_btns_layout.addWidget(self.register_only_btn)
        provision_btns_layout.addWidget(self.provision_btn)
        form_layout.addLayout(provision_btns_layout)

        layout.addWidget(form_container, 2)
        
        # Load table values
        self.refresh_table()

    def refresh_drives(self):
        """Scans system logical disks to populate USB drive letters in dropdown."""
        self.drive_selector.clear()
        self.drive_selector.addItem("Select Connected USB...", None)
        try:
            if not self._wmi_conn:
                self._wmi_conn = wmi.WMI()
            # Removable drives are DriveType 2
            for disk in self._wmi_conn.Win32_LogicalDisk(DriveType=2):
                vol_name = disk.VolumeName or "Unnamed"
                self.drive_selector.addItem(f"{disk.DeviceID} ({vol_name})", disk.DeviceID)
        except Exception as e:
            print(f"Error listing removable drives: {e}")

    def auto_fill_usb_details(self):
        """Reads hardware details of the selected USB drive and populates the forms."""
        drive_letter = self.drive_selector.currentData()
        if not drive_letter:
            QMessageBox.warning(self, "Auto-Fill Error", "Please select a connected USB drive letter first.")
            return

        monitor_helper = USBMonitor()
        details = monitor_helper.get_drive_details(drive_letter)
        
        if not details.get("is_usb"):
            QMessageBox.warning(self, "Invalid Device", "The selected drive is not recognized as a removable USB device.")
            return

        # Auto-populate details
        self.serial_input.setText(details["serial_number"])
        self.label_input.setText(details["label"])
        self.mfr_input.setText(details["manufacturer"])
        self.pid_input.setText(details["pid"])
        self.vid_input.setText(details["vid"])

    def refresh_table(self):
        """Reloads registered USB drives from SQLite and paints the table view."""
        devices = self.db.get_registered_usbs()
        self.devices_table.setRowCount(len(devices))
        for row_idx, dev in enumerate(devices):
            self.devices_table.setItem(row_idx, 0, QTableWidgetItem(dev.get("label", "")))
            self.devices_table.setItem(row_idx, 1, QTableWidgetItem(dev.get("serial_number", "")))
            self.devices_table.setItem(row_idx, 2, QTableWidgetItem(dev.get("manufacturer", "")))
            self.devices_table.setItem(row_idx, 3, QTableWidgetItem(dev.get("owner_name", "")))
            self.devices_table.setItem(row_idx, 4, QTableWidgetItem(dev.get("owner_email", "")))

    def register_device_only(self) -> bool:
        """Saves device settings directly in the local database without writing tracking files to the USB."""
        serial = self.serial_input.text().strip()
        label = self.label_input.text().strip()
        mfr = self.mfr_input.text().strip()
        pid = self.pid_input.text().strip()
        vid = self.vid_input.text().strip()
        owner = self.owner_input.text().strip()
        email = self.email_input.text().strip()
        contact = self.contact_input.text().strip()

        if not serial or not label or not owner or not email:
            QMessageBox.warning(self, "Validation Error", "Serial, Label, Owner Name, and Email are required.")
            return False

        success = self.db.register_usb(
            serial_number=serial,
            label=label,
            manufacturer=mfr,
            pid=pid,
            vid=vid,
            owner_name=owner,
            owner_email=email,
            emergency_contact=contact,
            secret_key=""
        )

        if success:
            QMessageBox.information(self, "Success", f"USB {label} has been registered locally.")
            self.clear_form()
            self.refresh_table()
            return True
        else:
            QMessageBox.critical(self, "Database Error", "Failed to register USB drive in local database.")
            return False

    def provision_and_register_device(self):
        """Registers the USB locally AND provisions the drive with recovery metadata files."""
        drive_letter = self.drive_selector.currentData()
        serial = self.serial_input.text().strip()
        email = self.email_input.text().strip()
        owner = self.owner_input.text().strip()
        label = self.label_input.text().strip()
        contact = self.contact_input.text().strip()

        if not drive_letter:
            # We need a drive letter to write metadata to
            QMessageBox.warning(self, "Provisioning Error", "Please select a connected USB drive letter to provision.")
            return

        if not serial or not email or not owner or not label:
            QMessageBox.warning(self, "Validation Error", "Serial, Label, Owner Name, and Email are required.")
            return

        # Double check drive is connected and matches details
        usb_dir = drive_letter + "\\"
        if not os.path.exists(usb_dir):
            QMessageBox.critical(self, "Access Error", f"Cannot access the path {usb_dir}. Is the drive mounted?")
            return

        # 1. Register locally
        if not self.register_device_only():
            return

        try:
            # 2. Write metadata configuration file
            meta_file = os.path.join(usb_dir, ".usb_guardian.json")
            
            # Generate cryptographic digital signature
            signature = USBMonitor.generate_usb_metadata_signature(serial, email)
            
            metadata = {
                "serial_number": serial,
                "label": label,
                "owner_name": owner,
                "owner_email": email,
                "emergency_contact": contact,
                "signature": signature,
                "system_agent_url": "USB-Sentry Endpoint Agent",
                "recovery_instructions": (
                    "This USB drive is registered in the USB-Sentry tracking network. "
                    "If found, please return it to the owner or plug it into an internet-connected "
                    "computer. Safe recovery steps will run in the background."
                )
            }
            
            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=4)
                
            # Set the file as hidden on Windows
            import ctypes
            FILE_ATTRIBUTE_HIDDEN = 0x02
            ctypes.windll.kernel32.SetFileAttributesW(meta_file, FILE_ATTRIBUTE_HIDDEN)

            # 3. Write visible Text Recovery Instruction File
            readme_file = os.path.join(usb_dir, "README_RECOVERY.txt")
            readme_text = (
                "========================================================================\n"
                "🛡️ USB-SENTRY - INTELLIGENT USB SECURITY & RECOVERY SYSTEM\n"
                "========================================================================\n\n"
                "LOST AND FOUND WARNING NOTICE:\n"
                f"This USB flash drive named '{label}' has been lost by its owner.\n\n"
                f"OWNER EMERGENCY CONTACT DETAILS:\n"
                f"Owner Name:  {owner}\n"
                f"Owner Email: {email}\n"
                f"Emergency Contact Info: {contact}\n\n"
                "INSTRUCTIONS FOR THE FINDER:\n"
                "If you have found this drive, please do one of the following:\n"
                "1. Connect with the owner via the email or phone number above.\n"
                "2. Connect the drive to any PC running the USB-Sentry Agent.\n"
                "   The agent will securely notify the owner of the device's location\n"
                "   to facilitate a swift recovery.\n\n"
                "Thank you for your honesty and cooperation in returning this device!\n"
                "========================================================================\n"
            )
            with open(readme_file, "w", encoding="utf-8") as f:
                f.write(readme_text)

            QMessageBox.information(
                self, "Provisioning Success", 
                f"USB Drive '{label}' provisioned successfully!\n\n"
                f"Created tracking token: .usb_guardian.json (Hidden)\n"
                f"Created instructions: README_RECOVERY.txt"
            )
            self.clear_form()
            self.refresh_drives()
            self.refresh_table()

        except Exception as e:
            QMessageBox.critical(self, "Write Failure", f"Failed to provision USB files: {str(e)}")

    def delete_selected_device(self):
        """Deletes the selected device from the local SQL database."""
        selected_ranges = self.devices_table.selectedRanges()
        if not selected_ranges:
            QMessageBox.warning(self, "Selection Error", "Please select a USB drive from the table to delete.")
            return

        row = selected_ranges[0].topRow()
        serial = self.devices_table.item(row, 1).text()
        label = self.devices_table.item(row, 0).text()

        confirm = QMessageBox.question(
            self, "Confirm Delete", 
            f"Are you sure you want to remove '{label}' (Serial: {serial}) from the registration database?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if confirm == QMessageBox.StandardButton.Yes:
            if self.db.delete_usb(serial):
                QMessageBox.information(self, "Success", "Device registration removed.")
                self.refresh_table()
            else:
                QMessageBox.critical(self, "Database Error", "Failed to delete device records.")

    def clear_form(self):
        self.serial_input.clear()
        self.label_input.clear()
        self.mfr_input.clear()
        self.pid_input.clear()
        self.vid_input.clear()
        self.owner_input.clear()
        self.email_input.clear()
        self.contact_input.clear()
        self.drive_selector.setCurrentIndex(0)
