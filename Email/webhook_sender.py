import json
import threading
import requests
from datetime import datetime

class WebhookSender:
    """
    Industry-Standard Webhook & SIEM Integration Engine.
    Dispatches real-time security events to:
    - Microsoft Teams Webhooks
    - Slack Incoming Webhooks
    - Discord Webhooks
    - Enterprise SIEM / SOAR HTTP Event Collectors (Splunk, Elastic, Datadog)
    """

    @classmethod
    def send_event_async(cls, webhook_url: str, event_data: dict):
        """Asynchronously dispatches a webhook payload without blocking the caller."""
        if not webhook_url:
            return
        thread = threading.Thread(target=cls._post_payload, args=(webhook_url, event_data), daemon=True)
        thread.start()

    @classmethod
    def _post_payload(cls, webhook_url: str, event_data: dict):
        try:
            # Build unified SIEM JSON payload
            payload = {
                "source": "USB-Sentry Endpoint Protection",
                "version": "1.0.0",
                "timestamp": datetime.now().isoformat(),
                "event_type": event_data.get("event_type", "SECURITY_ALERT"),
                "severity": event_data.get("severity", "MEDIUM"),
                "device": {
                    "serial": event_data.get("serial", "UNKNOWN"),
                    "label": event_data.get("label", "Generic USB"),
                    "drive_letter": event_data.get("drive_letter", "—"),
                    "manufacturer": event_data.get("manufacturer", "Generic")
                },
                "endpoint": {
                    "computer_name": event_data.get("computer_name", "UNKNOWN"),
                    "username": event_data.get("username", "UNKNOWN"),
                    "local_ip": event_data.get("local_ip", "0.0.0.0"),
                    "public_ip": event_data.get("public_ip", "0.0.0.0"),
                    "mac_address": event_data.get("mac_address", "00:00:00:00:00:00"),
                    "location": f"{event_data.get('city', 'Unknown')}, {event_data.get('country', 'Unknown')}"
                },
                "details": event_data.get("details", "")
            }

            # Optional: Add Slack/Teams compatible fallback text
            text_summary = (
                f"🛡️ *[USB-Sentry Security Alert]*\n"
                f"• *Event:* {payload['event_type']} (Severity: {payload['severity']})\n"
                f"• *USB Device:* {payload['device']['label']} (Serial: `{payload['device']['serial']}`)\n"
                f"• *Endpoint:* `{payload['endpoint']['computer_name']}` (User: `{payload['endpoint']['username']}`)\n"
                f"• *IP Address:* {payload['endpoint']['local_ip']} / {payload['endpoint']['public_ip']}\n"
                f"• *Details:* {payload['details']}"
            )
            payload["text"] = text_summary

            headers = {"Content-Type": "application/json"}
            requests.post(webhook_url, json=payload, headers=headers, timeout=5)
        except Exception as e:
            print(f"Webhook/SIEM dispatch warning: {e}")

    @classmethod
    def test_webhook(cls, webhook_url: str) -> tuple:
        """Sends an immediate test ping to the configured webhook URL."""
        if not webhook_url:
            return False, "Webhook URL cannot be empty."
        try:
            test_payload = {
                "source": "USB-Sentry",
                "event_type": "TEST_PING",
                "severity": "INFO",
                "text": "🛡️ *USB-Sentry Test Ping*: Webhook channel configured and responding successfully!",
                "timestamp": datetime.now().isoformat()
            }
            res = requests.post(webhook_url, json=test_payload, timeout=5)
            if res.status_code in (200, 201, 204):
                return True, f"Webhook verified successfully! HTTP Response: {res.status_code}"
            return False, f"Server responded with status code: {res.status_code}"
        except Exception as e:
            return False, f"Failed to connect to Webhook URL: {str(e)}"

