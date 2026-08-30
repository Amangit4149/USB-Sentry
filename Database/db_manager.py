import os
import sqlite3
from datetime import datetime

class DBManager:
    def __init__(self, db_path=None):
        if db_path is None:
            # Create standard database in a subfolder Database
            current_dir = os.path.dirname(os.path.abspath(__file__))
            self.db_path = os.path.join(current_dir, "guardian.db")
        else:
            self.db_path = db_path
        
        # Ensure parent directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Users table (for admin credentials)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Registered USBs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS registered_usbs (
                    serial_number TEXT PRIMARY KEY,
                    label TEXT,
                    manufacturer TEXT,
                    pid TEXT,
                    vid TEXT,
                    owner_name TEXT,
                    owner_email TEXT,
                    emergency_contact TEXT,
                    secret_key TEXT,
                    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Device insertion/removal logs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS device_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usb_serial TEXT NOT NULL,
                    event_type TEXT NOT NULL, -- 'INSERTION' or 'REMOVAL'
                    computer_name TEXT,
                    username TEXT,
                    local_ip TEXT,
                    public_ip TEXT,
                    mac_address TEXT,
                    os_version TEXT,
                    cpu_info TEXT,
                    ram_info TEXT,
                    suspicious_files TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(usb_serial) REFERENCES registered_usbs(serial_number)
                )
            """)
            
            # Migration check: try adding suspicious_files column to device_logs if database already exists
            try:
                cursor.execute("ALTER TABLE device_logs ADD COLUMN suspicious_files TEXT")
            except sqlite3.OperationalError:
                pass
            
            # Geolocation logs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS location_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usb_serial TEXT NOT NULL,
                    country TEXT,
                    state TEXT,
                    city TEXT,
                    latitude REAL,
                    longitude REAL,
                    maps_link TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(usb_serial) REFERENCES registered_usbs(serial_number)
                )
            """)
            
            # Email/Telegram notification logs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS email_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usb_serial TEXT NOT NULL,
                    recipient TEXT,
                    notification_type TEXT, -- 'EMAIL' or 'TELEGRAM'
                    status TEXT, -- 'SENT' or 'FAILED'
                    error_message TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(usb_serial) REFERENCES registered_usbs(serial_number)
                )
            """)
            conn.commit()

            # Unknown / unregistered USB event logs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS unknown_device_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    serial_number TEXT,
                    manufacturer TEXT,
                    vid TEXT,
                    pid TEXT,
                    drive_letter TEXT,
                    computer_name TEXT,
                    username TEXT,
                    local_ip TEXT,
                    public_ip TEXT,
                    mac_address TEXT,
                    os_version TEXT,
                    suspicious_files TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

            # USB File Activity logs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    drive_serial TEXT NOT NULL,
                    event_action TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

            # Seed initial file activity logs if empty
            cursor.execute("SELECT COUNT(*) FROM file_activity_logs")
            if cursor.fetchone()[0] == 0:
                sample_data = [
                    ("D: (04015225CE90C96E055D)", "MODIFIED", r"D:\project\aaaa\New folder\ascii.webp", "20,664 B", "2026-08-30 08:46:39"),
                    ("D: (04015225CE90C96E055D)", "CREATED",  r"D:\project\aaaa\New folder\ascii.webp", "20,664 B", "2026-08-30 08:46:39"),
                    ("D: (04015225CE90C96E055D)", "MODIFIED", r"D:\project\aaaa\ascii.webp", "20,664 B", "2026-08-30 08:46:17"),
                    ("D: (04015225CE90C96E055D)", "CREATED",  r"D:\project\aaaa\ascii.webp", "20,664 B", "2026-08-30 08:46:17"),
                    ("D: (04015225CE90C96E055D)", "MODIFIED", r"D:\project\ascii.webp", "20,664 B", "2026-08-30 08:45:18"),
                    ("D: (04015225CE90C96E055D)", "CREATED",  r"D:\project\ascii.webp", "20,664 B", "2026-08-30 08:45:18"),
                    ("D: (04015225CE90C96E055D)", "DELETED",  r"D:\New folder", "—", "2026-08-30 08:43:59"),
                    ("D: (04015225CE90C96E055D)", "DELETED",  r"D:\New folder", "—", "2026-08-30 08:43:12"),
                ]
                cursor.executemany("""
                    INSERT INTO file_activity_logs (drive_serial, event_action, file_path, file_size, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, sample_data)
                conn.commit()

    # User Management functions
    def register_user(self, username, password_hash):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash)
                )
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False

    def verify_user(self, username, password_hash):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (username,)
            )
            row = cursor.fetchone()
            if row and row['password_hash'] == password_hash:
                return True
            return False

    def change_user_password(self, username, new_password_hash):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (new_password_hash, username)
            )
            conn.commit()
            return cursor.rowcount > 0

    def check_user_exists(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            count = cursor.fetchone()[0]
            return count > 0

    # Registered USB operations
    def register_usb(self, serial_number, label, manufacturer, pid, vid, owner_name, owner_email, emergency_contact, secret_key):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO registered_usbs 
                    (serial_number, label, manufacturer, pid, vid, owner_name, owner_email, emergency_contact, secret_key)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (serial_number, label, manufacturer, pid, vid, owner_name, owner_email, emergency_contact, secret_key))
                conn.commit()
                return True
        except sqlite3.Error as e:
            print(f"Error registering USB: {e}")
            return False

    def delete_usb(self, serial_number):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM registered_usbs WHERE serial_number = ?", (serial_number,))
            conn.commit()
            return cursor.rowcount > 0

    def get_registered_usbs(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM registered_usbs ORDER BY registered_at DESC")
            return [dict(row) for row in cursor.fetchall()]

    def get_usb_by_serial(self, serial_number):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM registered_usbs WHERE serial_number = ?", (serial_number,))
            row = cursor.fetchone()
            return dict(row) if row else None

    # Device Logging operations
    def log_device_event(self, usb_serial, event_type, computer_name, username, local_ip, public_ip, mac_address, os_version, cpu_info, ram_info, suspicious_files=None):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("""
                    INSERT INTO device_logs 
                    (usb_serial, event_type, computer_name, username, local_ip, public_ip, mac_address, os_version, cpu_info, ram_info, suspicious_files, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (usb_serial, event_type, computer_name, username, local_ip, public_ip, mac_address, os_version, cpu_info, ram_info, suspicious_files, now_str))
                conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            print(f"Error logging device event: {e}")
            return None
    def log_unknown_device(self, serial_number, manufacturer, vid, pid, drive_letter,
                           computer_name, username, local_ip, public_ip, mac_address,
                           os_version, suspicious_files=None):
        """Log an unregistered USB insertion event."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("""
                    INSERT INTO unknown_device_logs
                    (serial_number, manufacturer, vid, pid, drive_letter, computer_name,
                     username, local_ip, public_ip, mac_address, os_version, suspicious_files, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (serial_number, manufacturer, vid, pid, drive_letter, computer_name,
                      username, local_ip, public_ip, mac_address, os_version, suspicious_files,
                      now_str))
                conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            print(f"Error logging unknown device: {e}")
            return None

    def get_unknown_device_events(self, limit=200):
        """Return most recent unregistered USB events."""
        try:
            with self.get_connection() as conn:
                conn.row_factory = __import__('sqlite3').Row
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM unknown_device_logs ORDER BY timestamp DESC LIMIT ?
                """, (limit,))
                return [dict(r) for r in cursor.fetchall()]
        except Exception:
            return []


    def log_location(self, usb_serial, country, state, city, latitude, longitude, maps_link):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("""
                    INSERT INTO location_logs 
                    (usb_serial, country, state, city, latitude, longitude, maps_link, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (usb_serial, country, state, city, latitude, longitude, maps_link, now_str))
                conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            print(f"Error logging location: {e}")
            return None

    def log_email(self, usb_serial, recipient, notification_type, status, error_message):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("""
                    INSERT INTO email_logs 
                    (usb_serial, recipient, notification_type, status, error_message, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (usb_serial, recipient, notification_type, status, error_message, now_str))
                conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            print(f"Error logging email status: {e}")
            return None

    # Retrieving Logs
    def get_device_logs(self, limit=100, offset=0, search=""):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if search:
                query = """
                    SELECT dl.*, ru.label FROM device_logs dl
                    LEFT JOIN registered_usbs ru ON dl.usb_serial = ru.serial_number
                    WHERE dl.usb_serial LIKE ? OR dl.computer_name LIKE ? OR dl.username LIKE ? OR ru.label LIKE ? OR dl.timestamp LIKE ?
                    ORDER BY dl.timestamp DESC LIMIT ? OFFSET ?
                """
                search_val = f"%{search}%"
                cursor.execute(query, (search_val, search_val, search_val, search_val, search_val, limit, offset))
            else:
                query = """
                    SELECT dl.*, ru.label FROM device_logs dl
                    LEFT JOIN registered_usbs ru ON dl.usb_serial = ru.serial_number
                    ORDER BY dl.timestamp DESC LIMIT ? OFFSET ?
                """
                cursor.execute(query, (limit, offset))
            return [dict(row) for row in cursor.fetchall()]

    def get_location_logs(self, limit=100, offset=0):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT ll.*, ru.label FROM location_logs ll
                LEFT JOIN registered_usbs ru ON ll.usb_serial = ru.serial_number
                ORDER BY ll.timestamp DESC LIMIT ? OFFSET ?
            """, (limit, offset))
            return [dict(row) for row in cursor.fetchall()]

    def get_email_logs(self, limit=100, offset=0):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT el.*, ru.label FROM email_logs el
                LEFT JOIN registered_usbs ru ON el.usb_serial = ru.serial_number
                ORDER BY el.timestamp DESC LIMIT ? OFFSET ?
            """, (limit, offset))
            return [dict(row) for row in cursor.fetchall()]

    def log_file_activity(self, drive_serial, event_action, file_path, file_size="—"):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("""
                    INSERT INTO file_activity_logs (drive_serial, event_action, file_path, file_size, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (drive_serial, event_action, file_path, file_size, now_str))
                conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            print(f"Error logging file activity: {e}")
            return None

    def get_file_activity_logs(self, limit=150, search=""):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if search:
                query = """
                    SELECT * FROM file_activity_logs
                    WHERE drive_serial LIKE ? OR event_action LIKE ? OR file_path LIKE ? OR timestamp LIKE ?
                    ORDER BY timestamp DESC LIMIT ?
                """
                s = f"%{search}%"
                cursor.execute(query, (s, s, s, s, limit))
            else:
                query = "SELECT * FROM file_activity_logs ORDER BY timestamp DESC LIMIT ?"
                cursor.execute(query, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    # Stats queries
    def get_device_statistics(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            stats = {}
            
            # Total registered
            cursor.execute("SELECT COUNT(*) FROM registered_usbs")
            stats['total_registered'] = cursor.fetchone()[0]
            
            # Total logs
            cursor.execute("SELECT COUNT(*) FROM device_logs")
            stats['total_events'] = cursor.fetchone()[0]
            
            # Total email logs
            cursor.execute("SELECT COUNT(*) FROM email_logs WHERE status='SENT'")
            stats['successful_alerts'] = cursor.fetchone()[0]
            
            # Alerts failed
            cursor.execute("SELECT COUNT(*) FROM email_logs WHERE status='FAILED'")
            stats['failed_alerts'] = cursor.fetchone()[0]
            
            # Timeline of connections for chart
            cursor.execute("""
                SELECT DATE(timestamp) as date_val, COUNT(*) as count_val 
                FROM device_logs 
                GROUP BY date_val 
                ORDER BY date_val DESC 
                LIMIT 15
            """)
            stats['timeline'] = [dict(row) for row in cursor.fetchall()]
            
            # Distribution of alerts by USB
            cursor.execute("""
                SELECT ru.label, COUNT(*) as count_val 
                FROM device_logs dl
                JOIN registered_usbs ru ON dl.usb_serial = ru.serial_number
                GROUP BY ru.label
            """)
            stats['distribution'] = [dict(row) for row in cursor.fetchall()]
            
            return stats
