import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class USBFileActivityHandler(FileSystemEventHandler):
    def __init__(self, db_manager, drive_serial):
        super().__init__()
        self.db = db_manager
        self.drive_serial = drive_serial

    def _format_size(self, path):
        try:
            if os.path.isfile(path):
                size_bytes = os.path.getsize(path)
                return f"{size_bytes:,} B"
            return "—"
        except Exception:
            return "—"

    def on_created(self, event):
        path = event.src_path
        # Ignore system volume hidden metadata files
        if "System Volume Information" in path or "$RECYCLE.BIN" in path:
            return
        size = self._format_size(path)
        self.db.log_file_activity(self.drive_serial, "CREATED", path, size)

    def on_modified(self, event):
        path = event.src_path
        if "System Volume Information" in path or "$RECYCLE.BIN" in path:
            return
        if os.path.isfile(path):
            size = self._format_size(path)
            self.db.log_file_activity(self.drive_serial, "MODIFIED", path, size)

    def on_deleted(self, event):
        path = event.src_path
        if "System Volume Information" in path or "$RECYCLE.BIN" in path:
            return
        self.db.log_file_activity(self.drive_serial, "DELETED", path, "—")

    def on_moved(self, event):
        src_path = event.src_path
        dest_path = event.dest_path
        if "System Volume Information" in dest_path or "$RECYCLE.BIN" in dest_path:
            return
        size = self._format_size(dest_path)
        self.db.log_file_activity(self.drive_serial, "RENAMED", f"{src_path} -> {dest_path}", size)


class USBFileWatcher:
    def __init__(self, db_manager):
        self.db = db_manager
        self.observers = {}

    def start_watching(self, drive_letter: str, serial_number: str):
        if not drive_letter or not os.path.exists(drive_letter):
            return
        drive_path = drive_letter if drive_letter.endswith("\\") else drive_letter + "\\"
        if drive_path in self.observers:
            return
            
        drive_serial = f"{drive_letter[:2]} ({serial_number})"
        handler = USBFileActivityHandler(self.db, drive_serial)
        observer = Observer()
        try:
            observer.schedule(handler, drive_path, recursive=True)
            observer.start()
            self.observers[drive_path] = observer
            print(f"Started monitoring USB file activity on {drive_path} [{drive_serial}]")
        except Exception as e:
            print(f"Failed to start file watcher on {drive_path}: {e}")

    def stop_watching(self, drive_letter: str):
        drive_path = drive_letter if drive_letter.endswith("\\") else drive_letter + "\\"
        if drive_path in self.observers:
            try:
                self.observers[drive_path].stop()
                self.observers[drive_path].join(timeout=1)
            except Exception:
                pass
            del self.observers[drive_path]
            print(f"Stopped monitoring USB file activity on {drive_path}")

    def stop_all(self):
        for path, observer in list(self.observers.items()):
            try:
                observer.stop()
                observer.join(timeout=1)
            except Exception:
                pass
        self.observers.clear()
