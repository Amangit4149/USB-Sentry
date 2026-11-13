import unittest
from unittest import mock

from Agent.agent_service import AgentService
from Agent.info_collector import InfoCollector
from Email.email_sender import EmailSender
from USBMonitor import monitor


class UnknownUSBLoggingTests(unittest.TestCase):
    def test_unknown_usb_with_unreadable_serial_is_still_logged(self):
        service = AgentService.__new__(AgentService)
        service.db = mock.Mock()
        service.db.get_usb_by_serial.return_value = None
        service.monitor = mock.Mock()
        service.file_watcher = mock.Mock()
        service.config = mock.Mock()
        service.config.get.return_value = ""
        service.email_sender = mock.Mock()
        service.telegram_sender = mock.Mock()
        device_details = {
            "drive_letter": "E:",
            "serial_number": "",
            "manufacturer": "USB",
            "vid": "1234",
            "pid": "5678",
        }
        system_info = {
            "computer_name": "host",
            "username": "user",
            "local_ip": "127.0.0.1",
            "mac_address": "00:00:00:00:00:00",
            "os_version": "Windows",
            "cpu_info": "test CPU",
            "ram_info": "16 GB",
        }
        geo_info = {
            "public_ip": "0.0.0.0",
            "country": "Unknown",
            "state": "Unknown",
            "city": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0,
            "maps_link": "",
        }

        with (
            mock.patch.object(InfoCollector, "collect_system_info", return_value=system_info),
            mock.patch.object(InfoCollector, "collect_geolocation", return_value=geo_info),
            mock.patch.object(InfoCollector, "scan_usb_for_suspicious_files", return_value=[]),
        ):
            service._handle_usb_insertion(device_details)

        service.file_watcher.start_watching.assert_called_once_with("E:", "Unreadable serial")
        service.monitor.check_usb_for_metadata.assert_not_called()
        self.assertEqual(
            service.db.log_unknown_device.call_args.kwargs["serial_number"],
            "UNREADABLE-E:",
        )
        self.assertEqual(
            service.db.log_location.call_args.kwargs["usb_serial"],
            "UNREADABLE-E:",
        )

    def test_usb_present_at_monitor_start_triggers_insertion_callback(self):
        details = {"drive_letter": "E:", "serial_number": "SERIAL", "is_usb": True}
        connection = mock.Mock()
        connection.Win32_LogicalDisk.return_value = [mock.Mock(DeviceID="E:")]
        usb_monitor = monitor.USBMonitor(insertion_callback=mock.Mock())
        usb_monitor.running = True
        usb_monitor._wmi_conn = connection
        usb_monitor._ensure_wmi_connection = mock.Mock(return_value=True)
        usb_monitor.get_drive_details = mock.Mock(return_value=details)

        with mock.patch.object(
            monitor.time,
            "sleep",
            side_effect=lambda _: setattr(usb_monitor, "running", False),
        ):
            usb_monitor._run_polling()

        usb_monitor.insertion_callback.assert_called_once_with(details)

    def _email_sender(self, settings):
        config = mock.Mock()
        config.get.side_effect = lambda key, default=None: settings.get(key, default)
        db = mock.Mock()
        return EmailSender(config, db), db

    def _email_arguments(self):
        return (
            {"serial_number": "UNKNOWN-USB", "label": "Unregistered USB"},
            {"suspicious_files": []},
            {},
            {"drive_letter": "E:"},
        )

    def _smtp_settings(self):
        return {
            "smtp_server": "smtp.example.test",
            "smtp_port": 587,
            "email_sender": "sender@example.test",
            "email_password": "test-password",
            "email_receiver": "receiver@example.test",
        }

    def test_unconfigured_unknown_usb_email_is_logged(self):
        sender, db = self._email_sender({})

        sender.send_unknown_device_alert(*self._email_arguments())

        self.assertEqual(
            db.log_email.call_args.args[:4],
            ("UNKNOWN-USB", "Unknown", "EMAIL", "FAILED"),
        )
        self.assertIn("missing", db.log_email.call_args.args[4])

    def test_unknown_usb_email_success_is_logged(self):
        sender, db = self._email_sender(self._smtp_settings())
        smtp = mock.Mock()
        with mock.patch.object(sender, "_create_smtp_client", return_value=smtp):
            sender.send_unknown_device_alert(*self._email_arguments())

        self.assertEqual(
            db.log_email.call_args.args[:4],
            ("UNKNOWN-USB", "receiver@example.test", "EMAIL", "SENT"),
        )

    def test_unknown_usb_email_failure_is_logged(self):
        sender, db = self._email_sender(self._smtp_settings())
        smtp = mock.Mock()
        smtp.sendmail.side_effect = OSError("SMTP unavailable")
        with mock.patch.object(sender, "_create_smtp_client", return_value=smtp):
            sender.send_unknown_device_alert(*self._email_arguments())

        self.assertEqual(
            db.log_email.call_args.args[:4],
            ("UNKNOWN-USB", "receiver@example.test", "EMAIL", "FAILED"),
        )
        self.assertIn("SMTP unavailable", db.log_email.call_args.args[4])


if __name__ == "__main__":
    unittest.main()
