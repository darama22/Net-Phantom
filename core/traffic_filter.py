"""
Traffic Filter - Intelligent filtering for meaningful traffic analysis
"""
import re
from ipaddress import ip_address, ip_network

class TrafficFilter:
    """Filter out noise from network traffic"""
    
    def __init__(self):
        """Initialize filter with blacklists"""
        
        # Private IP ranges (RFC 1918)
        self.private_networks = [
            ip_network('10.0.0.0/8'),
            ip_network('172.16.0.0/12'),
            ip_network('192.168.0.0/16'),
            ip_network('127.0.0.0/8'),  # Loopback
            ip_network('169.254.0.0/16'),  # Link-local
        ]
        
        # CDN domains to filter
        self.cdn_patterns = [
            # Major CDNs
            r'.*\.cloudfront\.net$',
            r'.*\.akamai\.net$',
            r'.*\.fastly\.net$',
            r'.*\.cloudflare\.com$',
            r'.*\.cdn\..*',
            r'.*\.edgekey\.net$',
            r'.*\.edgesuite\.net$',
            r'.*akadns\.net$',
            r'.*akamaiedge\.net$',
            r'.*azureedge\.net$',
            
            # Content delivery
            r'.*\.fbcdn\.net$',
            r'.*\.twimg\.com$',
            r'.*\.ytimg\.com$',
            r'.*\.ggpht\.com$',
            r'.*\.googleusercontent\.com$',
            r'.*ibyteimg\.com$',  # TikTok CDN
            r'.*\.tiktokcdn.*',
            r'.*\.instagramcdn.*',
            r'.*byteoversea\.net$',  # TikTok CDN
            
            # Image/video servers
            r'.*\.imgur\.com$',
            r'.*\.giphy\.com$',
            r'.*\.gfycat\.com$',
        ]
        
        # Telemetry and analytics
        self.telemetry_patterns = [
            # Microsoft
            r'.*\.microsoft\.com$',
            r'.*\.windows\.com$',
            r'.*\.msftconnecttest\.com$',
            r'.*\.msftncsi\.com$',
            r'.*windowsupdate\.com$',
            
            # Google Analytics
            r'.*google-analytics\.com$',
            r'.*googletagmanager\.com$',
            r'.*doubleclick\.net$',
            r'.*googlesyndication\.com$',
            r'.*googleapis\.com$',
            r'.*googlevideo\.com$',
            
            # Apple
            r'.*\.apple\.com$',
            r'.*\.icloud\.com$',
            r'.*\.mzstatic\.com$',
            
            # Connectivity checks
            r'.*connectivity-check.*',
            r'.*captive\.apple\.com$',
            r'.*detectportal.*',
            r'.*alive\.github\.com$',
            
            # Analytics SDKs
            r'.*appsflyersdk\.com$',
            r'.*app-analytics-services\.com$',
            r'.*\.analytics\..*',
            r'.*\.tracking\..*',
            r'.*\.telemetry\..*',
            r'.*\.metrics\..*',
            
            # Certificate/PKI services
            r'.*pki\.goog$',
            r'.*lencr\.org$',
            r'.*ocsp\..*',
            r'.*crl\..*',
            
            # mDNS and local discovery
            r'.*\.local$',
            r'_tcp\.local$',
            r'_udp\.local$',
        ]
        
        # Ad networks
        self.ad_patterns = [
            r'.*\.doubleclick\..*',
            r'.*\.googlesyndication\..*',
            r'.*\.advertising\..*',
            r'.*\.adservice\..*',
            r'.*\.adsystem\..*',
            r'.*\.adnxs\.com$',
            r'.*\.criteo\..*',
            r'.*\.outbrain\..*',
            r'.*\.taboola\..*',
            r'.*\.ads\..*',
            r'.*servedbyadbutler\.com$',
            
            # Proxy auto-discovery
            r'wpad\..*',
        ]
        
        # Compile all patterns
        self.all_patterns = (
            self.cdn_patterns + 
            self.telemetry_patterns + 
            self.ad_patterns
        )
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.all_patterns]
    
    def is_private_ip(self, ip_str):
        """Check if IP is private/local"""
        try:
            ip = ip_address(ip_str)
            return any(ip in network for network in self.private_networks)
        except:
            return False
    
    def should_filter(self, domain):
        """
        Determine if domain should be filtered out
        
        Args:
            domain (str): Domain name or IP
            
        Returns:
            bool: True if should be filtered (noise), False if interesting
        """
        if not domain or domain == 'Unknown':
            return True
        
        # Filter private IPs
        if self.is_private_ip(domain):
            return True
        
        # Filter pure IP addresses (we want domain names, not IPs)
        # Check if it looks like an IP (contains only digits and dots)
        if re.match(r'^[\d\.]+$', domain):
            return True
        
        # Filter by domain patterns
        domain_lower = domain.lower().strip('.')
        
        for pattern in self.compiled_patterns:
            if pattern.match(domain_lower):
                return True
        
        return False
    
    def get_clean_domain(self, domain):
        """
        Extract clean, human-readable domain
        
        Args:
            domain (str): Raw domain
            
        Returns:
            str: Cleaned domain or None if should be filtered
        """
        if self.should_filter(domain):
            return None
        
        # Extract main domain from subdomains
        # e.g., "www.youtube.com" -> "youtube.com"
        parts = domain.split('.')
        if len(parts) >= 2:
            # Get last two parts (domain.tld)
            return '.'.join(parts[-2:])
        
        return domain
