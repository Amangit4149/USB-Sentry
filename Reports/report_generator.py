import os
import csv
import matplotlib
matplotlib.use('Agg') # Thread-safe headless backend for Matplotlib
import matplotlib.pyplot as plt
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from Database.db_manager import DBManager

class ReportGenerator:
    def __init__(self, db_manager: DBManager):
        self.db = db_manager

    def generate_csv_report(self, output_path: str, log_type: str = "device") -> bool:
        """Exports log data directly to a CSV file."""
        try:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                if log_type == "device":
                    logs = self.db.get_device_logs(limit=1000)
                    writer.writerow([
                        "Log ID", "USB Serial", "Label", "Event Type", 
                        "Computer Name", "Username", "Local IP", 
                        "Public IP", "MAC Address", "OS Version", 
                        "CPU Info", "RAM Info", "Timestamp"
                    ])
                    for log in logs:
                        writer.writerow([
                            log.get("id"), log.get("usb_serial"), log.get("label"), log.get("event_type"),
                            log.get("computer_name"), log.get("username"), log.get("local_ip"),
                            log.get("public_ip"), log.get("mac_address"), log.get("os_version"),
                            log.get("cpu_info"), log.get("ram_info"), log.get("timestamp")
                        ])
                elif log_type == "location":
                    logs = self.db.get_location_logs(limit=1000)
                    writer.writerow([
                        "Log ID", "USB Serial", "Label", "Country", 
                        "State", "City", "Latitude", "Longitude", 
                        "Google Maps Link", "Timestamp"
                    ])
                    for log in logs:
                        writer.writerow([
                            log.get("id"), log.get("usb_serial"), log.get("label"), log.get("country"),
                            log.get("state"), log.get("city"), log.get("latitude"), log.get("longitude"),
                            log.get("maps_link"), log.get("timestamp")
                        ])
                elif log_type == "email":
                    logs = self.db.get_email_logs(limit=1000)
                    writer.writerow([
                        "Log ID", "USB Serial", "Label", "Recipient", 
                        "Notification Type", "Status", "Error Message", "Timestamp"
                    ])
                    for log in logs:
                        writer.writerow([
                            log.get("id"), log.get("usb_serial"), log.get("label"), log.get("recipient"),
                            log.get("notification_type"), log.get("status"), log.get("error_message"), log.get("timestamp")
                        ])
                elif log_type == "file_activity":
                    logs = self.db.get_file_activity_logs(limit=1000)
                    writer.writerow([
                        "Log ID", "Drive / Serial", "Event Action", "File Path", "Size (Bytes)", "Timestamp"
                    ])
                    for log in logs:
                        writer.writerow([
                            log.get("id"), log.get("drive_serial"), log.get("event_action"),
                            log.get("file_path"), log.get("file_size"), log.get("timestamp")
                        ])
            return True
        except Exception as e:
            print(f"Error generating CSV report: {e}")
            return False

    def generate_pdf_report(self, output_path: str) -> bool:
        """Compiles a professional PDF security audit report containing device activity lists and dynamic charts."""
        try:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            stats = self.db.get_device_statistics()
            device_logs = self.db.get_device_logs(limit=50)
            registered_usbs = self.db.get_registered_usbs()
            
            # 1. Create Matplotlib Chart
            chart_path = self._generate_timeline_chart(stats.get('timeline', []))
            
            # 2. Setup ReportLab Document
            doc = SimpleDocTemplate(
                output_path,
                pagesize=letter,
                rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36
            )
            
            styles = getSampleStyleSheet()
            
            # Custom Styles
            title_style = ParagraphStyle(
                'ReportTitle',
                parent=styles['Heading1'],
                fontName='Helvetica-Bold',
                fontSize=22,
                leading=26,
                textColor=colors.HexColor('#0f172a'),
                spaceAfter=15
            )
            
            subtitle_style = ParagraphStyle(
                'ReportSubtitle',
                parent=styles['Normal'],
                fontName='Helvetica',
                fontSize=10,
                leading=14,
                textColor=colors.HexColor('#475569'),
                spaceAfter=25
            )
            
            h2_style = ParagraphStyle(
                'Heading2_Custom',
                parent=styles['Heading2'],
                fontName='Helvetica-Bold',
                fontSize=14,
                leading=18,
                textColor=colors.HexColor('#1e293b'),
                spaceBefore=15,
                spaceAfter=10,
                keepWithNext=True
            )
            
            cell_style = ParagraphStyle(
                'CellText',
                parent=styles['Normal'],
                fontName='Helvetica',
                fontSize=8,
                leading=10,
                textColor=colors.HexColor('#334155')
            )
            
            cell_header_style = ParagraphStyle(
                'CellHeader',
                parent=styles['Normal'],
                fontName='Helvetica-Bold',
                fontSize=8,
                leading=10,
                textColor=colors.white
            )

            story = []

            # --- HEADER SECTION ---
            story.append(Paragraph("USB-Sentry", title_style))
            story.append(Paragraph(
                f"<b>Intelligent USB Security & Data Loss Prevention Audit Report</b><br/>"
                f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>"
                f"Security Classification: Confidential / Administrator Use Only",
                subtitle_style
            ))
            story.append(Spacer(1, 10))

            # --- SYSTEM STATISTICS SUMMARY ---
            story.append(Paragraph("System Metrics Summary", h2_style))
            summary_data = [
                [
                    Paragraph("<b>Total Registered USBs</b>", cell_style),
                    Paragraph(str(stats.get('total_registered', 0)), cell_style),
                    Paragraph("<b>Successful Security Notifications</b>", cell_style),
                    Paragraph(str(stats.get('successful_alerts', 0)), cell_style),
                ],
                [
                    Paragraph("<b>Total Insertion/Removal Events</b>", cell_style),
                    Paragraph(str(stats.get('total_events', 0)), cell_style),
                    Paragraph("<b>Failed Dispatch Notifications</b>", cell_style),
                    Paragraph(str(stats.get('failed_alerts', 0)), cell_style),
                ]
            ]
            
            summary_table = Table(summary_data, colWidths=[2.0*inch, 1.25*inch, 2.5*inch, 1.25*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0,0), (-1,-1), 8),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 20))

            # --- TIMELINE CHART ---
            if chart_path and os.path.exists(chart_path):
                story.append(Paragraph("USB Activity Timeline (Last 15 Days)", h2_style))
                story.append(Image(chart_path, width=7.0*inch, height=2.5*inch))
                story.append(Spacer(1, 20))

            story.append(PageBreak())

            # --- REGISTERED DEVICES TABLE ---
            story.append(Paragraph("Registered USB Profiles", h2_style))
            devices_data = [[
                Paragraph("<b>Serial Number</b>", cell_header_style),
                Paragraph("<b>Label</b>", cell_header_style),
                Paragraph("<b>Manufacturer</b>", cell_header_style),
                Paragraph("<b>Owner Name</b>", cell_header_style),
                Paragraph("<b>Owner Email</b>", cell_header_style),
                Paragraph("<b>Registered At</b>", cell_header_style),
            ]]
            
            for usb in registered_usbs:
                devices_data.append([
                    Paragraph(usb.get("serial_number", ""), cell_style),
                    Paragraph(usb.get("label", ""), cell_style),
                    Paragraph(usb.get("manufacturer", ""), cell_style),
                    Paragraph(usb.get("owner_name", ""), cell_style),
                    Paragraph(usb.get("owner_email", ""), cell_style),
                    Paragraph(usb.get("registered_at", "")[:19], cell_style),
                ])
                
            col_widths = [1.3*inch, 1.0*inch, 1.3*inch, 1.1*inch, 1.3*inch, 1.3*inch]
            devices_table = Table(devices_data, colWidths=col_widths)
            devices_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
                ('PADDING', (0,0), (-1,-1), 6),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            story.append(devices_table)
            story.append(Spacer(1, 20))

            # --- EVENT HISTORY LOGS TABLE ---
            story.append(Paragraph("Forensic Activity Logs (Recent Events)", h2_style))
            logs_data = [[
                Paragraph("<b>USB Serial</b>", cell_header_style),
                Paragraph("<b>Event</b>", cell_header_style),
                Paragraph("<b>Computer Name</b>", cell_header_style),
                Paragraph("<b>User</b>", cell_header_style),
                Paragraph("<b>Public IP</b>", cell_header_style),
                Paragraph("<b>Timestamp</b>", cell_header_style),
            ]]
            
            for log in device_logs[:20]: # Limit to top 20 for PDF length readability
                event_color = "#22c55e" if log.get("event_type") == "INSERTION" else "#ef4444"
                event_para = Paragraph(f"<font color='{event_color}'><b>{log.get('event_type')}</b></font>", cell_style)
                
                logs_data.append([
                    Paragraph(log.get("usb_serial", ""), cell_style),
                    event_para,
                    Paragraph(log.get("computer_name", ""), cell_style),
                    Paragraph(log.get("username", ""), cell_style),
                    Paragraph(log.get("public_ip", ""), cell_style),
                    Paragraph(log.get("timestamp", "")[:19], cell_style),
                ])
                
            logs_widths = [1.3*inch, 0.9*inch, 1.2*inch, 1.0*inch, 1.3*inch, 1.3*inch]
            logs_table = Table(logs_data, colWidths=logs_widths)
            logs_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
                ('PADDING', (0,0), (-1,-1), 5),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            story.append(logs_table)
            
            # Build PDF Document
            doc.build(story)
            
            # Clean up temporary chart file
            if chart_path and os.path.exists(chart_path):
                try:
                    os.remove(chart_path)
                except Exception:
                    pass
            return True
        except Exception as e:
            print(f"Error compiling PDF report: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _generate_timeline_chart(self, timeline_data: list) -> str:
        """Helper to create a beautiful Matplotlib timeline chart image for PDF embedding."""
        if not timeline_data:
            return ""
        try:
            # Sort by date ascending
            timeline_data = sorted(timeline_data, key=lambda x: x['date_val'])
            dates = [d['date_val'] for d in timeline_data]
            counts = [c['count_val'] for c in timeline_data]
            
            plt.figure(figsize=(7, 2.5))
            
            # Modern flat bar chart design
            plt.bar(dates, counts, color='#38bdf8', width=0.4, align='center', edgecolor='#0284c7', linewidth=0.5)
            
            plt.title('USB Guardian Connections Timeline', fontsize=10, fontweight='bold', color='#1e293b')
            plt.xlabel('Date', fontsize=8, color='#475569')
            plt.ylabel('Connection Counts', fontsize=8, color='#475569')
            
            plt.xticks(rotation=45, ha='right', fontsize=7)
            plt.yticks(fontsize=7)
            plt.grid(axis='y', linestyle='--', alpha=0.3)
            
            # Adjust styling bounds
            plt.tight_layout()
            
            temp_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp_chart.png")
            plt.savefig(temp_path, dpi=200)
            plt.close()
            return temp_path
        except Exception as e:
            print(f"Failed to generate matplotlib chart: {e}")
            return ""
