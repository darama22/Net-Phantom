"""
Packet Sniffer - Real-time traffic monitoring
"""
import scapy.all as scapy
import threading
from queue import Queue
from gui.logger import logger

class PacketSniffer:
    """Real-time packet sniffer for traffic analysis"""
    
    def __init__(self):
        """Initialize the packet sniffer"""
        self.is_sniffing = False
        self.sniff_thread = None
        self.packet_queue = Queue()
        self.packet_count = 0
        self.data_size = 0
        self.callback = None
        self.target_ip = None  # IP to filter for
        
        # Import and initialize traffic filter
        from core.traffic_filter import TrafficFilter
        self.traffic_filter = TrafficFilter()
    
    def set_target_ip(self, target_ip):
        """Set target IP to filter traffic"""
        self.target_ip = target_ip
    
    def set_callback(self, callback):
        """Set callback function for packet updates"""
        self.callback = callback
    
    def _packet_handler(self, packet):
        """Handle each captured packet"""
        try:
            self.packet_count += 1
            self.data_size += len(packet)
            
            # Extract useful information
            packet_info = {
                'number': self.packet_count,
                'size': len(packet),
                'protocol': 'Unknown',
                'source': 'Unknown',
                'destination': 'Unknown',
                'info': ''
            }
            
            # Check for IP layer
            if packet.haslayer(scapy.IP):
                packet_info['source'] = packet[scapy.IP].src
                packet_info['destination'] = packet[scapy.IP].dst
                
                # Filter by target IP if set (only show traffic from target device)
                if self.target_ip:
                    # Only process packets FROM the target device
                    if packet_info['source'] != self.target_ip:
                        return
            
            # Check for DNS
            if packet.haslayer(scapy.DNS) and packet.haslayer(scapy.DNSQR):
                packet_info['protocol'] = 'DNS'
                
                # Extract DNS query - scapy stores it as bytes with DNS encoding
                try:
                    # Get the qname (query name) - it's in DNS wire format
                    qname = packet[scapy.DNSQR].qname
                    
                    # Convert bytes to string and remove trailing dot
                    if isinstance(qname, bytes):
                        # Decode from bytes, handle DNS encoding
                        query = qname.decode('utf-8', errors='replace').rstrip('.')
                    else:
                        query = str(qname).rstrip('.')
                    
                    # If query is empty or just a dot, skip it
                    if not query or query == '.':
                        return
                    
                    packet_info['info'] = f"Query: {query}"
                    
                    # Filter before logging
                    clean_domain = self.traffic_filter.get_clean_domain(query)
                    if clean_domain:
                        logger.network(f"DNS Query: {clean_domain}")
                        
                except Exception as e:
                    # Skip malformed DNS packets
                    return
            
            # Check for HTTP
            elif packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load
                try:
                    load_str = load.decode('utf-8', errors='ignore')
                    if 'HTTP' in load_str or 'GET' in load_str or 'POST' in load_str:
                        packet_info['protocol'] = 'HTTP'
                        # Extract first line
                        first_line = load_str.split('\r\n')[0]
                        packet_info['info'] = first_line[:100]
                        logger.network(f"HTTP: {first_line[:80]}")
                except:
                    pass
            
            # Check for TCP
            elif packet.haslayer(scapy.TCP):
                packet_info['protocol'] = 'TCP'
                packet_info['info'] = f"Port {packet[scapy.TCP].dport}"
            
            # Check for UDP
            elif packet.haslayer(scapy.UDP):
                packet_info['protocol'] = 'UDP'
                packet_info['info'] = f"Port {packet[scapy.UDP].dport}"
            
            # Add to queue
            self.packet_queue.put(packet_info)
            
            # Call callback if set (App will do additional filtering)
            if self.callback:
                self.callback(packet_info)
                
        except Exception as e:
            pass  # Silently ignore packet parsing errors
    
    def _sniff_loop(self, interface=None):
        """Internal sniffing loop"""
        logger.scan("Starting packet capture...")
        
        try:
            scapy.sniff(
                iface=interface,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: not self.is_sniffing
            )
        except Exception as e:
            logger.error(f"Sniffer error: {e}")
    
    def start_sniffing(self, interface=None):
        """
        Start packet sniffing in background thread
        
        Args:
            interface (str): Network interface to sniff on (optional)
        """
        if self.is_sniffing:
            print("[!] Sniffer already running")
            return False
        
        self.is_sniffing = True
        self.packet_count = 0
        self.data_size = 0
        
        # Start sniffing in background thread
        self.sniff_thread = threading.Thread(
            target=self._sniff_loop,
            args=(interface,),
            daemon=True
        )
        self.sniff_thread.start()
        
        print("[✓] Packet sniffer started")
        return True
    
    
    def stop_sniffing(self):
        """Stop packet sniffing"""
        if not self.is_sniffing:
            return
        
        self.is_sniffing = False
        
        # Wait for thread to finish
        if self.sniff_thread:
            self.sniff_thread.join(timeout=3)
        
        print(f"[✓] Sniffer stopped - Captured {self.packet_count} packets ({self.data_size / 1024:.2f} KB)")
        logger.scan(f"Sniffer stopped - Captured {self.packet_count} packets ({self.data_size / 1024:.2f} KB)")
    
    def get_stats(self):
        """Get current statistics"""
        return {
            'packet_count': self.packet_count,
            'data_mb': self.data_size / (1024 * 1024)
        }
