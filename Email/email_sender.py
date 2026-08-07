import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import threading
from Config.config_manager import ConfigManager
from Database.db_manager import DBManager

class EmailSender:
    def __init__(self, config_manager: ConfigManager, db_manager: DBManager):
        self.config = config_manager
        self.db = db_manager

    def is_rate_limited(self, usb_serial: str, notification_type: str = "EMAIL") -> bool:
        """
        Check database if a successful alert was sent for this USB in the rate-limit window.
        Prevents spamming the owner's inbox if the USB is repeatedly plugged/unplugged.
        """
        rate_limit_minutes = self.config.get("rate_limit_minutes", 15)
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            time_threshold = datetime.now() - timedelta(minutes=rate_limit_minutes)
            cursor.execute("""
                SELECT COUNT(*) FROM email_logs 
                WHERE usb_serial = ? AND notification_type = ? AND status = 'SENT' AND timestamp > ?
            """, (usb_serial, notification_type, time_threshold))
            count = cursor.fetchone()[0]
            return count > 0

    def send_alert(self, usb_info: dict, sys_info: dict, geo_info: dict) -> bool:
        """Sends an HTML formatted security alert to the registered owner (non-blocking)."""
        usb_serial = usb_info.get("serial_number", "UNKNOWN")
        
        # Check rate limit
        if self.is_rate_limited(usb_serial, "EMAIL"):
            print(f"Email alert for USB {usb_serial} is rate-limited. Skipping email dispatch.")
            return False

        # Run email dispatch in a background thread to prevent GUI/Agent thread freeze
        thread = threading.Thread(target=self._dispatch_email, args=(usb_info, sys_info, geo_info))
        thread.daemon = True
        thread.start()
        return True

    def _dispatch_email(self, usb_info: dict, sys_info: dict, geo_info: dict):
        usb_serial = usb_info.get("serial_number", "UNKNOWN")
        recipient = usb_info.get("owner_email") or self.config.get("email_receiver")
        
        if not recipient:
            print("No recipient email found. Logging failure.")
            self.db.log_email(usb_serial, "Unknown", "EMAIL", "FAILED", "No recipient email configured.")
            return

        smtp_server = self.config.get("smtp_server")
        smtp_port = int(self.config.get("smtp_port") or 587)
        sender = self.config.get("email_sender")
        password = self.config.get("email_password")

        if not all([smtp_server, smtp_port, sender, password]):
            err_msg = "SMTP settings are incomplete."
            print(err_msg)
            self.db.log_email(usb_serial, recipient, "EMAIL", "FAILED", err_msg)
            return

        try:
            # Construct Email
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"⚠️ [SECURITY ALERT] USB-Sentry - Lost Device Connected: {usb_info.get('label', 'USB Drive')}"
            msg['From'] = f"USB-Sentry <{sender}>"
            msg['To'] = recipient

            # Render styled HTML Template
            html_content = self.render_html_template(usb_info, sys_info, geo_info)
            msg.attach(MIMEText(html_content, 'html'))

            # Setup SMTP server
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.ehlo()
            if smtp_port == 587:
                server.starttls()
                server.ehlo()
            server.login(sender, password)
            server.sendmail(sender, recipient, msg.as_string())
            server.quit()

            # Log Success
            self.db.log_email(usb_serial, recipient, "EMAIL", "SENT", "")
            print(f"Security email alert sent successfully to {recipient} for USB {usb_serial}")
        except Exception as e:
            err_msg = str(e)
            print(f"SMTP error while sending alert: {err_msg}")
            self.db.log_email(usb_serial, recipient, "EMAIL", "FAILED", err_msg)

    def send_unknown_device_alert(self, usb_info: dict, sys_info: dict, geo_info: dict, device_details: dict):
        """Send an email alert for an unregistered/unknown USB device insertion."""
        smtp_server = self.config.get("smtp_server")
        smtp_port = int(self.config.get("smtp_port") or 587)
        sender_email = self.config.get("email_sender")
        sender_password = self.config.get("email_password")
        receiver_email = self.config.get("email_receiver")
        if not all([smtp_server, sender_email, sender_password, receiver_email]):
            print("Email not configured — skipping unknown device alert email.")
            return
        try:
            susp_files = sys_info.get("suspicious_files") or []
            susp_html = ""
            if susp_files:
                susp_html = "<br/><b style='color:#ef4444;'>⚠️ Suspicious files found on this drive:</b><ul style='color:#fecaca;font-family:monospace;'>"
                for f in susp_files:
                    susp_html += f"<li><b>{f.get('name')}</b> — {f.get('reason')}<br/><small style='color:#fca5a5'>{f.get('path')}</small></li>"
                susp_html += "</ul>"

            html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"/>
            <style>
              body {{ font-family: Arial, sans-serif; background-color: #f4f4f5; margin: 0; padding: 20px; color: #333333; }}
              .container {{ max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border: 1px solid #e4e4e7; }}
              .header {{ background-color: #ef4444; color: #ffffff; padding: 20px; text-align: center; }}
              .header h1 {{ margin: 0; font-size: 22px; font-weight: bold; }}
              .content {{ padding: 20px 30px; }}
              .alert-text {{ color: #b91c1c; font-size: 15px; font-weight: bold; margin-bottom: 20px; }}
              .section-title {{ color: #ef4444; font-size: 14px; font-weight: bold; text-transform: uppercase; margin: 20px 0 10px 0; border-bottom: 2px solid #fee2e2; padding-bottom: 5px; }}
              table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
              td {{ padding: 10px; border-bottom: 1px solid #f4f4f5; font-size: 14px; }}
              td:first-child {{ color: #71717a; width: 40%; font-weight: bold; }}
              td:last-child {{ color: #27272a; font-family: monospace; font-weight: bold; }}
              .footer {{ background-color: #f8fafc; padding: 15px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #e2e8f0; }}
              a.btn {{ display: inline-block; background-color: #3b82f6; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold; margin-top: 10px; }}
            </style></head><body>
            <div class="container">
              <div class="header">
                <h1>🚨 UNREGISTERED USB DEVICE DETECTED</h1>
              </div>
              <div class="content">
                <p class="alert-text">
                  An unregistered USB drive was just inserted into a machine running USB-Sentry.
                  This device is NOT in your authorized list.
                </p>
                <div class="section-title">Device Hardware Info</div>
                <table>
                  <tr><td>Serial Number</td><td>{usb_info.get('serial_number','—')}</td></tr>
                  <tr><td>Manufacturer</td><td>{device_details.get('manufacturer','—')}</td></tr>
                  <tr><td>Vendor ID (VID)</td><td>{device_details.get('vid','—')}</td></tr>
                  <tr><td>Product ID (PID)</td><td>{device_details.get('pid','—')}</td></tr>
                  <tr><td>Drive Letter</td><td>{device_details.get('drive_letter','—')}</td></tr>
                </table>
                <div class="section-title">Host System Details</div>
                <table>
                  <tr><td>Computer Name</td><td>{sys_info.get('computer_name','—')}</td></tr>
                  <tr><td>Logged-in User</td><td>{sys_info.get('username','—')}</td></tr>
                  <tr><td>OS Version</td><td>{sys_info.get('os_version','—')}</td></tr>
                  <tr><td>Local IP</td><td>{sys_info.get('local_ip','—')}</td></tr>
                  <tr><td>MAC Address</td><td>{sys_info.get('mac_address','—')}</td></tr>
                  <tr><td>Public IP</td><td>{geo_info.get('public_ip','—')}</td></tr>
                  <tr><td>Location</td><td>{geo_info.get('city','—')}, {geo_info.get('country','—')}</td></tr>
                </table>
                <div style="text-align: center;">
                  <a href="{geo_info.get('maps_link','#')}" class="btn">📍 View on Google Maps</a>
                </div>
                {susp_html}
              </div>
              <div class="footer">
                USB-Sentry • Automated Security Alert • {sys_info.get('timestamp','')}
              </div>
            </div>
            </body></html>"""

            msg = MIMEMultipart("alternative")
            msg["Subject"] = "🚨 UNREGISTERED USB DETECTED — USB-Sentry"
            msg["From"] = f"USB-Sentry <{sender_email}>"
            msg["To"] = receiver_email
            msg.attach(MIMEText(html, "html"))
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.ehlo()
                server.starttls()
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, receiver_email, msg.as_string())
            print(f"Unknown device alert email sent to {receiver_email}")
        except Exception as e:
            print(f"Failed to send unknown device alert email: {e}")

    def test_connection(self, smtp_server, smtp_port, sender, password, receiver) -> tuple:
        """Tests the SMTP configuration with a test email."""
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = "USB-Sentry - SMTP Connection Test"
            msg['From'] = f"USB-Sentry Test <{sender}>"
            msg['To'] = receiver
            
            html = """
            <html>
                <body style="font-family: Arial, sans-serif; background-color: #0f172a; color: #f1f5f9; padding: 20px;">
                    <div style="max-width: 600px; margin: 0 auto; background-color: #1e293b; border-radius: 8px; padding: 30px; border: 1px solid #334155;">
                        <h2 style="color: #38bdf8;">SMTP Configuration Verified</h2>
                        <p>This is a test email sent from <strong>USB-Sentry</strong> dashboard.</p>
                        <p>Your SMTP mail servers and connection settings are configured correctly.</p>
                        <hr style="border: 0; border-top: 1px solid #334155; margin: 20px 0;">
                        <small style="color: #64748b;">USB-Sentry Intelligent Security & DLP System</small>
                    </div>
                </body>
            </html>
            """
            msg.attach(MIMEText(html, 'html'))
            
            server = smtplib.SMTP(smtp_server, int(smtp_port))
            server.ehlo()
            if int(smtp_port) == 587:
                server.starttls()
                server.ehlo()
            server.login(sender, password)
            server.sendmail(sender, receiver, msg.as_string())
            server.quit()
            return True, "SMTP connection test succeeded. Test email sent!"
        except Exception as e:
            return False, f"SMTP Connection failed: {str(e)}"

    def render_html_template(self, usb_info: dict, sys_info: dict, geo_info: dict) -> str:
        """Generates a premium dark-themed HTML alert email for registered USB devices."""
        maps_link = geo_info.get("maps_link", "#")
        maps_button = ""
        if maps_link and maps_link != "#":
            maps_button = f"""
            <div style="text-align: center; margin: 30px 0;">
                <a href="{maps_link}" target="_blank" style="background-color: #ef4444; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
                    📍 View Geolocation on Google Maps
                </a>
            </div>
            """

        # Render suspicious files block if any
        susp_files = sys_info.get("suspicious_files") or []
        susp_html = ""
        if susp_files:
            susp_html += """
            <div class="section" style="border: 2px solid #ef4444; background-color: #2d1a1a; padding: 15px; border-radius: 8px; margin-bottom: 25px; border-left: 5px solid #ef4444;">
                <div class="section-title" style="color: #ef4444; font-weight: bold; border-bottom: 1px solid #4a2828; padding-bottom: 5px; margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.5px;">⚠️ SUSPICIOUS FILES DETECTED ON USB</div>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr style="border-bottom: 1px solid #4a2828;">
                        <th style="color: #fca5a5; width: 40%; text-align: left; font-size: 13px; padding: 4px;">File Name</th>
                        <th style="color: #fca5a5; width: 60%; text-align: left; font-size: 13px; padding: 4px;">Details</th>
                    </tr>
            """
            for file_item in susp_files:
                susp_html += f"""
                    <tr style="border-bottom: 1px solid #3d2222;">
                        <td style="color: #fecaca; font-family: monospace; font-size: 13px; font-weight: bold; padding: 6px 4px; word-break: break-all;">{file_item.get('name')}</td>
                        <td style="color: #fecaca; font-size: 13px; padding: 6px 4px;"><b>{file_item.get('reason')}</b><br/><span style="font-size: 11px; color: #fca5a5; opacity: 0.8;">Path: {file_item.get('path')}</span></td>
                    </tr>
                """
            susp_html += """
                </table>
            </div>
            """

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #0b0f19;
                    color: #e2e8f0;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    max-width: 600px;
                    margin: 20px auto;
                    background-color: #111827;
                    border: 1px solid #1f2937;
                    border-radius: 12px;
                    overflow: hidden;
                    box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.5);
                }}
                .header {{
                    background: linear-gradient(135deg, #ef4444, #b91c1c);
                    padding: 25px;
                    text-align: center;
                }}
                .header h1 {{
                    color: #ffffff;
                    margin: 0;
                    font-size: 24px;
                    font-weight: 700;
                    letter-spacing: 0.5px;
                }}
                .content {{
                    padding: 30px;
                }}
                .section {{
                    margin-bottom: 25px;
                    background-color: #1f2937;
                    border-radius: 8px;
                    padding: 20px;
                    border: 1px solid #374151;
                }}
                .section-title {{
                    font-size: 16px;
                    font-weight: bold;
                    color: #f87171;
                    margin-top: 0;
                    margin-bottom: 15px;
                    border-bottom: 1px solid #374151;
                    padding-bottom: 5px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                td {{
                    padding: 8px 4px;
                    font-size: 14px;
                    vertical-align: top;
                }}
                .label {{
                    color: #9ca3af;
                    font-weight: 600;
                    width: 40%;
                }}
                .value {{
                    color: #f1f5f9;
                }}
                .footer {{
                    background-color: #0f172a;
                    padding: 15px 30px;
                    text-align: center;
                    border-top: 1px solid #1e293b;
                    font-size: 12px;
                    color: #64748b;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>⚠️ SECURITY ALERT: REGISTERED USB DETECTED</h1>
                </div>
                <div class="content">
                    <p style="margin-top: 0; font-size: 15px; line-height: 1.5; color: #cbd5e1;">
                        A registered tracking device has been inserted into a computer running the USB-Sentry Agent. Forensic indicators have been captured below:
                    </p>

                    {susp_html}

                    <!-- USB Details -->
                    <div class="section">
                        <div class="section-title">Device Profile</div>
                        <table>
                            <tr>
                                <td class="label">USB Serial Number</td>
                                <td class="value" style="font-family: monospace; font-weight: bold; color: #38bdf8;">{usb_info.get('serial_number')}</td>
                            </tr>
                            <tr>
                                <td class="label">Volume Label</td>
                                <td class="value">{usb_info.get('label')}</td>
                            </tr>
                            <tr>
                                <td class="label">Manufacturer / Hardware</td>
                                <td class="value">{usb_info.get('manufacturer')} (PID: {usb_info.get('pid')}, VID: {usb_info.get('vid')})</td>
                            </tr>
                            <tr>
                                <td class="label">Device Owner</td>
                                <td class="value">{usb_info.get('owner_name')} ({usb_info.get('owner_email')})</td>
                            </tr>
                        </table>
                    </div>

                    <!-- Host Info -->
                    <div class="section">
                        <div class="section-title">Host Forensic Info</div>
                        <table>
                            <tr>
                                <td class="label">Computer Name</td>
                                <td class="value">{sys_info.get('computer_name')}</td>
                            </tr>
                            <tr>
                                <td class="label">Logged User</td>
                                <td class="value">{sys_info.get('username')}</td>
                            </tr>
                            <tr>
                                <td class="label">Local IP Address</td>
                                <td class="value">{sys_info.get('local_ip')}</td>
                            </tr>
                            <tr>
                                <td class="label">MAC Address</td>
                                <td class="value" style="font-family: monospace;">{sys_info.get('mac_address')}</td>
                            </tr>
                            <tr>
                                <td class="label">Operating System</td>
                                <td class="value">{sys_info.get('os_version')}</td>
                            </tr>
                            <tr>
                                <td class="label">CPU Specs</td>
                                <td class="value">{sys_info.get('cpu_info')}</td>
                            </tr>
                            <tr>
                                <td class="label">Total System RAM</td>
                                <td class="value">{sys_info.get('ram_info')}</td>
                            </tr>
                            <tr>
                                <td class="label">Capture Date/Time</td>
                                <td class="value">{sys_info.get('timestamp')} ({sys_info.get('timezone')})</td>
                            </tr>
                        </table>
                    </div>

                    <!-- Geolocation Info -->
                    <div class="section">
                        <div class="section-title">Geographical Tracking</div>
                        <table>
                            <tr>
                                <td class="label">Public IP Address</td>
                                <td class="value" style="font-weight: bold; color: #38bdf8;">{geo_info.get('public_ip')}</td>
                            </tr>
                            <tr>
                                <td class="label">Country / Region</td>
                                <td class="value">{geo_info.get('country')}</td>
                            </tr>
                            <tr>
                                <td class="label">State / City</td>
                                <td class="value">{geo_info.get('state')} / {geo_info.get('city')}</td>
                            </tr>
                            <tr>
                                <td class="label">Coordinates (Lat, Lon)</td>
                                <td class="value">{geo_info.get('latitude')}, {geo_info.get('longitude')}</td>
                            </tr>
                        </table>
                    </div>

                    {maps_button}
                </div>
                <div class="footer">
                    This email is auto-generated by the USB-Sentry Endpoint Protection Agent.<br>
                    &copy; {datetime.now().year} USB-Sentry. All Rights Reserved. Confidential Alert.
                </div>
            </div>
        </body>
        </html>
        """
        return html
