import os
import sys
import winreg

class StartupManager:
    REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
    APP_NAME = "SmartUSBGuardian"

    @classmethod
    def get_run_command(cls) -> str:
        """Gets the command path to run the agent in the background using pythonw."""
        # Get python executable and replace python.exe with pythonw.exe if needed
        python_exe = sys.executable
        if python_exe.endswith("python.exe"):
            pythonw_exe = python_exe[:-10] + "pythonw.exe"
        else:
            pythonw_exe = python_exe
        
        # Check if pythonw exists, otherwise fallback to python
        if not os.path.exists(pythonw_exe):
            pythonw_exe = python_exe

        # Main script is in the root directory (parent of Agent folder)
        current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        main_script = os.path.join(current_dir, "main.py")
        
        return f'"{pythonw_exe}" "{main_script}" --agent'

    @classmethod
    def register_startup(cls) -> bool:
        """Registers the agent script to run at startup via HKCU Registry."""
        try:
            cmd = cls.get_run_command()
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_KEY, 0, winreg.KEY_SET_VALUE)
            with key:
                winreg.SetValueEx(key, cls.APP_NAME, 0, winreg.REG_SZ, cmd)
            print(f"Startup registration successful: {cmd}")
            return True
        except Exception as e:
            print(f"Failed to register startup in registry: {e}")
            return False

    @classmethod
    def unregister_startup(cls) -> bool:
        """Removes the registry startup key for the agent."""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_KEY, 0, winreg.KEY_SET_VALUE)
            with key:
                try:
                    winreg.DeleteValue(key, cls.APP_NAME)
                except FileNotFoundError:
                    # Already unregistered
                    pass
            print("Startup registration removed.")
            return True
        except Exception as e:
            print(f"Failed to unregister startup in registry: {e}")
            return False

    @classmethod
    def is_registered(cls) -> bool:
        """Checks if the startup key is currently registered."""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_KEY, 0, winreg.KEY_READ)
            with key:
                val, _ = winreg.QueryValueEx(key, cls.APP_NAME)
                return bool(val)
        except FileNotFoundError:
            return False
        except Exception as e:
            print(f"Error checking registry: {e}")
            return False

    # ── Convenience instance aliases ──────────────────────────────────────────
    def register(self) -> bool:
        return self.__class__.register_startup()

    def unregister(self) -> bool:
        return self.__class__.unregister_startup()
