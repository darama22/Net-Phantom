#!/usr/bin/env python3
"""
Net-Phantom: Network Auditing Dashboard
Main entry point with privilege verification and signal handling
"""
import sys
import os
import ctypes
import signal
import atexit

def is_admin():
    """Check if the script is running with administrator/root privileges"""
    try:
        # Linux/macOS
        return os.getuid() == 0
    except AttributeError:
        # Windows
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

def cleanup_handler():
    """Emergency cleanup on exit"""
    print("\n[!] Performing emergency cleanup...")
    # This will be enhanced when we implement the ARPSpoofer class
    
def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[!] Interrupt received. Cleaning up...")
    sys.exit(0)

def main():
    """Main entry point"""
    # Check for admin privileges
    if not is_admin():
        print("╔═══════════════════════════════════════════════════════════╗")
        print("║  ⚠️  ADMINISTRATOR PRIVILEGES REQUIRED                    ║")
        print("╚═══════════════════════════════════════════════════════════╝")
        print("\nNet-Phantom requires elevated privileges to access raw sockets.")
        print("\nPlease run as:")
        if sys.platform == "win32":
            print("  • Right-click → 'Run as Administrator'")
        else:
            print("  • sudo python3 main.py")
        sys.exit(1)
    
    # Register cleanup handlers
    atexit.register(cleanup_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║           NET-PHANTOM v1.0                                ║")
    print("║           Network Auditing Dashboard                      ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print("\n[✓] Administrator privileges verified")
    print("[✓] Signal handlers registered")
    print("[*] Initializing GUI...\n")
    
    # Import and launch GUI (will be implemented next)
    try:
        from gui.app import NetPhantomApp
        app = NetPhantomApp()
        app.mainloop()
    except ImportError as e:
        print(f"[!] Error importing GUI: {e}")
        print("[*] GUI components not yet implemented")
        sys.exit(1)

if __name__ == "__main__":
    main()
