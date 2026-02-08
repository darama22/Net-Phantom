"""
Net-Phantom Main Application Window
"""
import customtkinter as ctk
from gui.thread_manager import ThreadManager
from gui.pages.scanner_page import ScannerPage
from gui.pages.dashboard import Dashboard
from gui.logger import logger
from core.mitm import ARPSpoofer
from gui.pages.ai_page import AIPage
from core.ai_analyzer import AIAnalyzer

# Set appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class NetPhantomApp(ctk.CTk):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        
        # Window configuration
        self.title("NET-PHANTOM v1.0 - Network Auditing Dashboard")
        self.geometry("1200x800")
        
        # Initialize components
        self.thread_manager = ThreadManager()
        self.arp_spoofer = ARPSpoofer()
        
        # Import sniffer here to avoid circular import
        from core.sniffer import PacketSniffer
        from core.scanner import NetworkScanner
        from core.traffic_filter import TrafficFilter
        
        self.network_scanner = NetworkScanner()
        self.packet_sniffer = PacketSniffer()
        self.packet_sniffer.set_callback(self.on_packet_captured)
        
        # Initialize AI analyzer and traffic filter
        self.ai_analyzer = AIAnalyzer()
        self.traffic_filter = TrafficFilter()
        
        self.current_page = None
        
        # Status indicator state
        self.mitm_active = False
        self.sniffer_active = False
        self.active_target = None  # Stores the currently attacked device dict
        self.pulse_state = False
        
        # Create UI
        self._create_layout()
        
        # Setup logger callback
        logger.set_callback(self.add_log)
        
        # Initial log
        logger.success("Net-Phantom initialized successfully")
        logger.info("Ready to begin network auditing")
        
        # Show default page
        self.show_page("dashboard")
        
        # Handle window close
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def _create_layout(self):
        """Create the main layout with sidebar and content area"""
        # Configure grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        
        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.sidebar.grid_rowconfigure(6, weight=1)
        
        # Logo/Title
        self.logo_label = ctk.CTkLabel(
            self.sidebar,
            text="⚡ NET-PHANTOM",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        # Status indicator
        self.status_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.status_frame.grid(row=1, column=0, padx=20, pady=10)
        
        self.status_indicator = ctk.CTkLabel(
            self.status_frame,
            text="●",
            font=ctk.CTkFont(size=24),
            text_color="gray"
        )
        self.status_indicator.grid(row=0, column=0, padx=(0, 5))
        
        self.status_label = ctk.CTkLabel(
            self.status_frame,
            text="Idle",
            font=ctk.CTkFont(size=12)
        )
        self.status_label.grid(row=0, column=1)
        
        # Navigation buttons
        self.btn_dashboard = ctk.CTkButton(
            self.sidebar,
            text="📊 Dashboard",
            command=lambda: self.show_page("dashboard"),
            height=40
        )
        self.btn_dashboard.grid(row=2, column=0, padx=20, pady=10)
        
        self.btn_scanner = ctk.CTkButton(
            self.sidebar,
            text="🔍 Network Scanner",
            command=lambda: self.show_page("scanner"),
            height=40
        )
        self.btn_scanner.grid(row=3, column=0, padx=20, pady=10)
        
        self.btn_ai = ctk.CTkButton(
            self.sidebar,
            text="🧠 AI Analysis",
            command=lambda: self.show_page("ai"),
            height=40,
            fg_color="#4a148c",
            hover_color="#38006b"
        )
        self.btn_ai.grid(row=4, column=0, padx=20, pady=10)
        
        # Separator
        separator = ctk.CTkFrame(self.sidebar, height=2, fg_color="gray30")
        separator.grid(row=5, column=0, padx=20, pady=20, sticky="ew")
        
        # Info label
        self.info_label = ctk.CTkLabel(
            self.sidebar,
            text="Network Auditing\nDashboard v1.0",
            font=ctk.CTkFont(size=10),
            text_color="gray50"
        )
        self.info_label.grid(row=7, column=0, padx=20, pady=(0, 20))
        
        # Content area
        self.content_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.content_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        self.content_frame.grid_rowconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(0, weight=1)
        
        # Console log panel (bottom)
        console_frame = ctk.CTkFrame(self, corner_radius=0)
        console_frame.grid(row=1, column=1, sticky="nsew", padx=10, pady=(0, 10))
        
        # Console title
        console_title = ctk.CTkLabel(
            console_frame,
            text="📋 System Console",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        console_title.pack(pady=(5, 0), padx=10, anchor="w")
        
        # Console textbox
        self.console = ctk.CTkTextbox(
            console_frame,
            height=150,
            font=ctk.CTkFont(family="Consolas", size=11),
            wrap="word"
        )
        self.console.pack(fill="both", expand=True, padx=10, pady=10)
        self.console.configure(state="disabled")
    
    def add_log(self, message: str, level: str = "INFO"):
        """Add a log message to the console"""
        self.console.configure(state="normal")
        
        # Color coding based on level
        color_map = {
            "INFO": "white",
            "SUCCESS": "#00ff00",
            "WARNING": "#ffaa00",
            "ERROR": "#ff0000",
            "SCAN": "#00aaff",
            "MITM": "#ff00ff",
            "NETWORK": "#00ffff"
        }
        
        tag = f"tag_{level}"
        self.console.tag_config(tag, foreground=color_map.get(level, "white"))
        
        self.console.insert("end", message + "\n", tag)
        self.console.see("end")  # Auto-scroll to bottom
        self.console.configure(state="disabled")
    
    def show_page(self, page_name):
        """Switch to a different page"""
        # Destroy current page
        if self.current_page:
            self.current_page.destroy()
        
        # Create new page
        if page_name == "dashboard":
            logger.info("Navigating to Dashboard")
            self.current_page = Dashboard(self.content_frame, self)
        elif page_name == "scanner":
            logger.info("Navigating to Network Scanner")
            self.current_page = ScannerPage(self.content_frame, self)
        elif page_name == "ai":
            logger.info("Navigating to AI Analysis")
            self.current_page = AIPage(self.content_frame, self)
        
        if self.current_page:
            self.current_page.grid(row=0, column=0, sticky="nsew")
    
    def set_mitm_status(self, active, target=None):
        """Update MITM status indicator"""
        self.mitm_active = active
        if active:
            if target:
                self.active_target = target
            self.status_label.configure(text="MITM Active")
            logger.mitm("MITM mode activated - monitoring traffic")
            self._pulse_indicator()
        else:
            self.active_target = None
            self.status_indicator.configure(text_color="gray")
            self.status_label.configure(text="Idle")
            logger.info("System returned to idle state")
            
    def set_sniffer_status(self, active):
        """Update Sniffer status"""
        self.sniffer_active = active
    
    def _pulse_indicator(self):
        """Create pulsing effect for status indicator"""
        if not self.mitm_active:
            return
        
        # Toggle between red and dark red
        color = "#ff0000" if self.pulse_state else "#880000"
        self.status_indicator.configure(text_color=color)
        self.pulse_state = not self.pulse_state
        
        # Schedule next pulse
        self.after(500, self._pulse_indicator)
    
    def on_packet_captured(self, packet_info):
        """Handle captured packet"""
        # Extract domain from packet info
        domain = 'Unknown'
        packet_type = packet_info.get('protocol', 'Unknown')
        
        # Extract domain from DNS or HTTP
        if packet_type == 'DNS':
            # Extract from "Query: domain.com"
            info = packet_info.get('info', '')
            if 'Query:' in info:
                domain = info.replace('Query:', '').strip()
        elif packet_type == 'HTTP':
            # Extract from HTTP info
            info = packet_info.get('info', '')
            domain = info[:50] if info else 'HTTP Request'
        else:
            # For other protocols, use destination IP
            domain = packet_info.get('destination', 'Unknown')
        
        # Apply intelligent filtering
        clean_domain = self.traffic_filter.get_clean_domain(domain)
        
        # Skip if filtered (noise)
        if clean_domain is None:
            return
        
        # Use cleaned domain for display and analysis
        domain = clean_domain
        
        # ALWAYS send to AI Analyzer (background buffering)
        if hasattr(self, 'ai_analyzer'):
            self.ai_analyzer.add_traffic(domain, packet_type)
        
        # Forward to AI page UI if it's the current page
        if hasattr(self, 'current_page') and isinstance(self.current_page, AIPage):
            self.current_page.add_traffic_entry(domain, packet_type)
        
        # Update dashboard stats if on dashboard page
        if hasattr(self.current_page, 'update_stats'):
            stats = self.packet_sniffer.get_stats()
            self.current_page.update_stats(
                stats['packet_count'],
                stats['data_mb']
            )
    
    def on_closing(self):
        """Handle window close event"""
        logger.warning("Application shutdown initiated")
        
        # Disable close button to prevent multiple clicks
        self.protocol("WM_DELETE_WINDOW", lambda: None)
        
        try:
            # Stop packet sniffer
            if self.packet_sniffer.is_sniffing:
                logger.info("Stopping packet sniffer...")
                self.packet_sniffer.stop_sniffing()
            
            # Stop any active MITM
            if self.arp_spoofer.is_spoofing:
                logger.mitm("Stopping active MITM session...")
                self.arp_spoofer.stop_spoofing()
            
            # Cleanup threads
            self.thread_manager.cleanup()
            
            logger.success("Cleanup complete - goodbye!")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
        finally:
            # Force destroy after a short delay to ensure cleanup
            self.after(500, self._force_quit)
    
    def _force_quit(self):
        """Force quit the application"""
        try:
            self.quit()
            self.destroy()
        except:
            import sys
            sys.exit(0)

