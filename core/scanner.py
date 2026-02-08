"""
Network Scanner - ARP-based device discovery
"""
import scapy.all as scapy
from mac_vendor_lookup import MacLookup, VendorNotFoundError
import socket
import time

class NetworkScanner:
    """ARP-based network scanner with vendor identification"""
    
    def __init__(self):
        """Initialize the scanner with vendor lookup database"""
        try:
            self.mac_lookup = MacLookup()
            self.mac_lookup.update_vendors()  # Update vendor database
        except Exception as e:
            print(f"[!] Warning: Could not initialize vendor lookup: {e}")
            self.mac_lookup = None
    
    def get_hostname(self, ip):
        """
        Try to resolve hostname from IP
        
        Args:
            ip (str): IP address
            
        Returns:
            str: Hostname or None
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def detect_device_type(self, ip, vendor, hostname):
        """
        Detect device type based on IP, vendor, and hostname
        
        Args:
            ip (str): IP address
            vendor (str): Vendor name
            hostname (str): Hostname
            
        Returns:
            str: Device type emoji and name
        """
        ip_parts = ip.split('.')
        last_octet = int(ip_parts[-1])
        
        # Check if it's likely the router (usually .1 or .254)
        if last_octet == 1 or last_octet == 254:
            return "🌐 Router/Gateway"
        
        # Check vendor for device type
        vendor_lower = vendor.lower() if vendor != "Unknown" else ""
        hostname_lower = hostname.lower() if hostname else ""
        
        # Apple devices - check hostname patterns first
        if 'iphone' in hostname_lower:
            return "📱 iPhone"
        if 'ipad' in hostname_lower:
            return "📱 iPad"
        if 'macbook' in hostname_lower or 'imac' in hostname_lower or 'mac-' in hostname_lower:
            return "💻 MacBook/iMac"
        if 'apple' in vendor_lower:
            return "📱 Apple Device"
        
        # Android devices
        if any(x in vendor_lower for x in ['samsung', 'xiaomi', 'huawei', 'oppo', 'oneplus', 'motorola', 'lg electronics']):
            if 'samsung' in vendor_lower:
                return "📱 Samsung Phone"
            return "📱 Android Phone"
        
        # Computers
        if any(x in vendor_lower for x in ['dell', 'hp', 'lenovo', 'asus', 'acer', 'microsoft']):
            return "💻 PC/Laptop"
        
        if any(x in hostname_lower for x in ['desktop', 'laptop', 'pc', 'workstation']):
            return "💻 PC/Laptop"
        
        # Smart TV / Streaming
        if any(x in vendor_lower for x in ['lg', 'sony', 'philips', 'tcl', 'hisense', 'roku', 'amazon']):
            return "📺 Smart TV"
        
        # IoT / Smart Home
        if any(x in vendor_lower for x in ['espressif', 'tuya', 'tp-link']):
            return "🏠 IoT Device"
        
        # Gaming consoles
        if any(x in vendor_lower for x in ['sony', 'nintendo', 'microsoft']) and any(x in hostname_lower for x in ['playstation', 'xbox', 'switch']):
            return "🎮 Gaming Console"
        
        # Default
        return "❓ Unknown Device"

    
    def scan_network(self, ip_range, timeout=2):
        """
        Scan the network for active devices using ARP
        
        Args:
            ip_range (str): IP range to scan (e.g., "192.168.1.0/24")
            timeout (int): Timeout in seconds for the scan
            
        Returns:
            list: List of dictionaries with device information
            
        Returns:
            list: List of discovered devices with their info
        """
        print(f"[*] Scanning network: {ip_range}")
        devices = []
        seen_ips = set()
        
        try:
            # Perform 3 scan passes to catch more devices
            # Mobile devices often don't respond to first ARP request
            for scan_pass in range(3):
                print(f"[*] Scan pass {scan_pass + 1}/3...")
                
                # Send ARP requests
                answered, _ = scapy.srp(
                    scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_range),
                    timeout=2,
                    verbose=False,
                    retry=2
                )
                
                # Process responses
                for sent, received in answered:
                    ip = received.psrc
                    mac = received.hwsrc
                    
                    # Skip if already found
                    if ip in seen_ips:
                        continue
                    
                    seen_ips.add(ip)
                    
                    # Get vendor info
                    vendor = self.get_vendor(mac)
                    
                    # Try to get hostname
                    hostname = self.get_hostname(ip)

                    # Detect device type
                    device_type = self.detect_device_type(ip, vendor, hostname)
                    
                    devices.append({
                        'ip': ip,
                        'mac': mac,
                        'vendor': vendor,
                        'type': device_type,
                        'hostname': hostname
                    })
                    
                    print(f"[+] Found: {ip} ({mac}) - {vendor}")
                
                # Wait between passes to let devices wake up
                if scan_pass < 2:
                    time.sleep(1)
            
            print(f"[✓] Scan complete: Found {len(devices)} device(s)")
            return devices
            
        except Exception as e:
            print(f"[!] Scan error: {e}")
            return devices
    
    def get_vendor(self, mac_address):
        """
        Get the vendor name from MAC address
        
        Args:
            mac_address (str): MAC address
            
        Returns:
            str: Vendor name or "Unknown"
        """
        if not self.mac_lookup:
            return "Unknown"
        
        try:
            vendor = self.mac_lookup.lookup(mac_address)
            return vendor
        except VendorNotFoundError:
            return "Unknown"
        except Exception:
            return "Unknown"

