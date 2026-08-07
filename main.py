import sys
import argparse
import time
from Database.db_manager import DBManager
from Config.config_manager import ConfigManager
from Agent.agent_service import AgentService
from Agent.startup_manager import StartupManager
from Dashboard.app import run_gui

def main():
    parser = argparse.ArgumentParser(
        description="USB-Sentry – Intelligent USB Security & Data Loss Prevention System"
    )
    parser.add_argument(
        "--agent", "-a",
        action="store_true",
        help="Launch in background monitoring agent mode (GUI-less)"
    )
    parser.add_argument(
        "--register-startup",
        action="store_true",
        help="Register background agent to run automatically on Windows logon"
    )
    parser.add_argument(
        "--unregister-startup",
        action="store_true",
        help="Remove background agent automatic startup registration"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show startup registry registration status of background agent"
    )
    
    args = parser.parse_args()

    # Instantiate Core Components
    db_manager = DBManager()
    config_manager = ConfigManager()
    agent_service = AgentService(db_path=db_manager.db_path, config_path=config_manager.config_file)

    if args.register_startup:
        success = StartupManager.register_startup()
        if success:
            print("Successfully registered USB-Sentry to run on Windows logon.")
            sys.exit(0)
        else:
            print("Failed to register startup registry entry.")
            sys.exit(1)

    elif args.unregister_startup:
        success = StartupManager.unregister_startup()
        if success:
            print("Successfully removed USB-Sentry startup registry key.")
            sys.exit(0)
        else:
            print("Failed to remove startup registry entry.")
            sys.exit(1)

    elif args.status:
        registered = StartupManager.is_registered()
        print(f"Windows logon startup registration status: {'REGISTERED' if registered else 'NOT REGISTERED'}")
        if registered:
            print(f"Command line: {StartupManager.get_run_command()}")
        sys.exit(0)

    elif args.agent:
        # Run agent in background service loop
        print("Initializing background USB monitor agent...")
        agent_service.start()
        print("Agent is active and monitoring USB insertion events. Press Ctrl+C to terminate.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down USB monitor agent...")
            agent_service.stop()
            print("Agent stopped. Safe exit.")
            sys.exit(0)
    
    else:
        # Launch PyQt6 Graphical Dashboard Interface
        print("Launching Graphical Dashboard Interface...")
        run_gui(db_manager, config_manager, agent_service)

if __name__ == "__main__":
    main()
