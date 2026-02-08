"""
Dashboard Page - Real-time statistics and monitoring
"""
import customtkinter as ctk

class Dashboard(ctk.CTkFrame):
    """Dashboard with real-time network statistics"""
    
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        
        self.app = app
        self.packet_count = 0
        self.data_mb = 0.0
        
        self._create_widgets()
        self._start_updates()
    
    def _create_widgets(self):
        """Create dashboard widgets"""
        # Title
        title = ctk.CTkLabel(
            self,
            text="Network Auditing Dashboard",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.pack(pady=20)
        
        # Stats container
        stats_frame = ctk.CTkFrame(self)
        stats_frame.pack(fill="x", padx=40, pady=20)
        
        # Configure grid
        stats_frame.grid_columnconfigure((0, 1, 2), weight=1)
        
        # Packet counter
        self.packet_card = self._create_stat_card(
            stats_frame,
            "📦 Packets Captured",
            "0",
            0
        )
        
        # Data counter
        self.data_card = self._create_stat_card(
            stats_frame,
            "💾 Data Intercepted",
            "0.00 MB",
            1
        )
        
        # Status card
        self.status_card = self._create_stat_card(
            stats_frame,
            "⚡ System Status",
            "Ready",
            2
        )
        
        # Info panel
        info_frame = ctk.CTkFrame(self)
        info_frame.pack(fill="both", expand=True, padx=40, pady=20)
        
        info_title = ctk.CTkLabel(
            info_frame,
            text="ℹ️  About Net-Phantom",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        info_title.pack(pady=(20, 10))
        
        info_text = ctk.CTkTextbox(info_frame, height=200, wrap="word")
        info_text.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        info_content = """Net-Phantom is a professional Network Security Auditing Framework designed for educational and research purposes.

Features:
• ARP-based device discovery with vendor identification
• Man-in-the-Middle (MITM) capabilities for traffic analysis
• Cross-platform support (Windows, Linux, macOS)
• Real-time packet monitoring and statistics
• Automatic ARP table restoration for safety

⚠️ IMPORTANT: Only use this tool on networks you own or have explicit permission to audit. Unauthorized network analysis is illegal.

This tool is designed for security professionals, researchers, and students learning about network security."""
        
        info_text.insert("1.0", info_content)
        info_text.configure(state="disabled")
    
    def _create_stat_card(self, parent, title, value, column):
        """Create a statistics card"""
        card = ctk.CTkFrame(parent)
        card.grid(row=0, column=column, padx=10, pady=10, sticky="nsew")
        
        title_label = ctk.CTkLabel(
            card,
            text=title,
            font=ctk.CTkFont(size=14)
        )
        title_label.pack(pady=(20, 5))
        
        value_label = ctk.CTkLabel(
            card,
            text=value,
            font=ctk.CTkFont(size=24, weight="bold")
        )
        value_label.pack(pady=(5, 20))
        
        return value_label
    
    def _start_updates(self):
        """Start periodic updates (placeholder for future packet sniffer)"""
        # This will be connected to the packet sniffer later
        pass
    
    def update_stats(self, packets, data_mb):
        """Update statistics display"""
        self.packet_count = packets
        self.data_mb = data_mb
        
        self.packet_card.configure(text=str(packets))
        self.data_card.configure(text=f"{data_mb:.2f} MB")
