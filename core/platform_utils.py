"""
Platform-specific utilities for IP forwarding and OS detection
"""
import platform
import subprocess
import sys

class PlatformUtils:
    """Cross-platform utilities for network configuration"""
    
    @staticmethod
    def detect_os():
        """Detect the operating system"""
        system = platform.system()
        if system == "Windows":
            return "Windows"
        elif system == "Linux":
            return "Linux"
        elif system == "Darwin":
            return "macOS"
        else:
            return "Unknown"
    
    @staticmethod
    def enable_ip_forwarding():
        """Enable IP forwarding based on the operating system"""
        os_type = PlatformUtils.detect_os()
        
        try:
            if os_type == "Linux":
                # Linux: Write to /proc/sys/net/ipv4/ip_forward
                subprocess.run(
                    ["sysctl", "-w", "net.ipv4.ip_forward=1"],
                    check=True,
                    capture_output=True
                )
                print("[✓] IP Forwarding enabled (Linux)")
                return True
                
            elif os_type == "macOS":
                # macOS: Similar to Linux
                subprocess.run(
                    ["sysctl", "-w", "net.inet.ip.forwarding=1"],
                    check=True,
                    capture_output=True
                )
                print("[✓] IP Forwarding enabled (macOS)")
                return True
                
            elif os_type == "Windows":
                # Windows: Use PowerShell to enable forwarding on all interfaces
                # This command works immediately without restart
                result = subprocess.run(
                    ["powershell", "-Command",
                     "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Set-NetIPInterface -Forwarding Enabled"],
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                # Also enable router mode in registry
                subprocess.run(
                    ["reg", "add",
                     "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                     "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "1", "/f"],
                    capture_output=True,
                    check=False
                )
                
                print("[✓] IP Forwarding enabled (Windows)")
                return True
                
            else:
                print(f"[!] Unsupported OS: {os_type}")
                return False
                
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to enable IP forwarding: {e}")
            return False
    
    @staticmethod
    def disable_ip_forwarding():
        """Disable IP forwarding (restore original state)"""
        os_type = PlatformUtils.detect_os()
        
        try:
            if os_type == "Linux":
                subprocess.run(
                    ["sysctl", "-w", "net.ipv4.ip_forward=0"],
                    check=True,
                    capture_output=True
                )
                print("[✓] IP Forwarding disabled (Linux)")
                return True
                
            elif os_type == "macOS":
                subprocess.run(
                    ["sysctl", "-w", "net.inet.ip.forwarding=0"],
                    check=True,
                    capture_output=True
                )
                print("[✓] IP Forwarding disabled (macOS)")
                return True
                
            elif os_type == "Windows":
                # Windows: Disable forwarding on all interfaces
                subprocess.run(
                    ["powershell", "-Command",
                     "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Set-NetIPInterface -Forwarding Disabled"],
                    capture_output=True,
                    check=False
                )
                
                # Also update registry
                subprocess.run(
                    ["reg", "add",
                     "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                     "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "0", "/f"],
                    capture_output=True,
                    check=False
                )
                
                print("[✓] IP Forwarding disabled (Windows)")
                return True
                
            else:
                return False
                
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to disable IP forwarding: {e}")
            return False
