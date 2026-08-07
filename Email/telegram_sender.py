import requests
import threading
from datetime import datetime, timedelta
from Config.config_manager import ConfigManager
from Database.db_manager import DBManager

class TelegramSender:
    def __init__(self, config_manager: ConfigManager, db_manager: DBManager):
        self.config = config_manager
        self.db = db_manager

    def is_rate_limited(self, usb_serial: str, notification_type: str = "TELEGRAM") -> bool:
        """Checks if a Telegram alert was already sent within the rate-limit window."""
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
        """Sends a Telegram alert to the configured Chat ID (non-blocking)."""
        usb_serial = usb_info.get("serial_number", "UNKNOWN")
        
        if self.is_rate_limited(usb_serial, "TELEGRAM"):
            print(f"Telegram alert for USB {usb_serial} is rate-limited. Skipping telegram dispatch.")
            return False

        # Dispatch Telegram notification in background thread
        thread = threading.Thread(target=self._dispatch_telegram, args=(usb_info, sys_info, geo_info))
        thread.daemon = True
        thread.start()
        return True

    def _dispatch_telegram(self, usb_info: dict, sys_info: dict, geo_info: dict):
        usb_serial = usb_info.get("serial_number", "UNKNOWN")
        token = self.config.get("telegram_token")
        chat_id = self.config.get("telegram_chat_id")

        if not token or not chat_id:
            print("Telegram token or chat_id not configured. Skipping.")
            return

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        
        # Build clean markdown text
        susp_files = sys_info.get("suspicious_files") or []
        susp_block = ""
        if susp_files:
            susp_block = f"\n\n🚨 *SUSPICIOUS FILES DETECTED ({len(susp_files)}):*\n"
            for f in susp_files[:10]:  # Cap at 10 for Telegram message length
                susp_block += f"• `{f.get('name')}` — {f.get('reason')}\n"
            if len(susp_files) > 10:
                susp_block += f"_...and {len(susp_files) - 10} more. Check dashboard for full list._\n"

        text = (
            f"⚠️ *[SECURITY ALERT]*\n"
            f"*Smart USB Guardian* detected registered USB device connection!\n\n"
            f"👤 *Device:* {usb_info.get('label', 'USB Drive')}\n"
            f"🔢 *Serial:* `{usb_info.get('serial_number')}`\n"
            f"🏢 *Owner:* {usb_info.get('owner_name')}\n\n"
            f"💻 *Host Information:*\n"
            f"• *PC Name:* {sys_info.get('computer_name')}\n"
            f"• *Username:* {sys_info.get('username')}\n"
            f"• *OS:* {sys_info.get('os_version')}\n"
            f"• *Local IP:* {sys_info.get('local_ip')}\n"
            f"• *MAC:* `{sys_info.get('mac_address')}`\n\n"
            f"📍 *Location:*\n"
            f"• *Public IP:* {geo_info.get('public_ip')}\n"
            f"• *Country/Region:* {geo_info.get('country')}\n"
            f"• *State/City:* {geo_info.get('state')} / {geo_info.get('city')}\n"
            f"• *Google Maps:* [View Location]({geo_info.get('maps_link', '#')})"
            f"{susp_block}"
        )

        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": False
        }

        try:
            response = requests.post(url, json=payload, timeout=8)
            res_json = response.json()
            if response.status_code == 200 and res_json.get("ok"):
                self.db.log_email(usb_serial, chat_id, "TELEGRAM", "SENT", "")
                print(f"Telegram notification sent successfully to chat_id {chat_id}")
            else:
                err_msg = res_json.get("description", f"HTTP Error {response.status_code}")
                self.db.log_email(usb_serial, chat_id, "TELEGRAM", "FAILED", err_msg)
                print(f"Telegram API failed: {err_msg}")
        except Exception as e:
            err_msg = str(e)
            self.db.log_email(usb_serial, chat_id, "TELEGRAM", "FAILED", err_msg)
            print(f"Error sending Telegram notification: {err_msg}")

    @staticmethod
    def test_telegram(token: str, chat_id: str) -> tuple:
        """Tests the Telegram Bot credentials by sending a verification message."""
        try:
            url = f"https://api.telegram.org/bot{token}/getMe"
            response = requests.get(url, timeout=5)
            if response.status_code != 200:
                return False, f"Invalid token or bot status: {response.text}"
            
            res_json = response.json()
            if not res_json.get("ok"):
                return False, f"Telegram Bot validation failed: {res_json.get('description')}"
                
            bot_name = res_json.get("result", {}).get("first_name", "Bot")
            
            # Send test message
            send_url = f"https://api.telegram.org/bot{token}/sendMessage"
            test_msg = f"🔔 *Smart USB Guardian* test message from *{bot_name}*. Your configurations are correct!"
            payload = {
                "chat_id": chat_id,
                "text": test_msg,
                "parse_mode": "Markdown"
            }
            
            send_response = requests.post(send_url, json=payload, timeout=5)
            send_res = send_response.json()
            if send_response.status_code == 200 and send_res.get("ok"):
                return True, f"Telegram test passed! Message sent by bot @{res_json.get('result', {}).get('username')}"
            else:
                return False, f"Failed to send message: {send_res.get('description')}"
                
        except Exception as e:
            return False, f"Telegram validation connection error: {str(e)}"
