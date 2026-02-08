"""
AI Analysis Page - Llama 3 powered traffic insights
"""
import customtkinter as ctk
from datetime import datetime
from gui.logger import logger

class AIPage(ctk.CTkFrame):
    """AI Analysis page with Matrix-style traffic feed and insight cards"""
    
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        
        # Header
        header = ctk.CTkLabel(
            self,
            text="🧠 AI Traffic Analysis",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        header.pack(pady=20)
        
        # Status indicator
        self.status_label = ctk.CTkLabel(
            self,
            text="⚠️ AI Status: Checking connection...",
            font=ctk.CTkFont(size=12)
        )
        self.status_label.pack(pady=5)
        
        # Main content - Split view
        content_frame = ctk.CTkFrame(self, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # LEFT: Traffic Feed (Matrix style)
        left_frame = ctk.CTkFrame(content_frame, fg_color="#0a0a0a", corner_radius=10)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        traffic_header = ctk.CTkLabel(
            left_frame,
            text="📡 LIVE TRAFFIC FEED",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#00ff00"
        )
        traffic_header.pack(pady=10)
        
        # Scrollable traffic list
        self.traffic_list = ctk.CTkScrollableFrame(
            left_frame,
            fg_color="#000000",
            corner_radius=5
        )
        self.traffic_list.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # RIGHT: AI Insights (Timeline cards)
        right_frame = ctk.CTkFrame(content_frame, fg_color="#1a1a1a", corner_radius=10)
        right_frame.pack(side="right", fill="both", expand=True)
        
        insights_header = ctk.CTkLabel(
            right_frame,
            text="💡 AI INSIGHTS",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#00d4ff"
        )
        insights_header.pack(pady=10)
        
        # Scrollable insights timeline
        self.insights_list = ctk.CTkScrollableFrame(
            right_frame,
            fg_color="#0f0f0f",
            corner_radius=5
        )
        self.insights_list.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # Action buttons
        button_frame = ctk.CTkFrame(right_frame, fg_color="transparent")
        button_frame.pack(pady=10)
        
        self.analyze_btn = ctk.CTkButton(
            button_frame,
            text="🔍 Analyze Traffic",
            command=self.analyze_traffic,
            fg_color="#00a86b",
            hover_color="#008c5a",
            state="disabled"
        )
        self.analyze_btn.pack(side="left", padx=5)
        
        self.profile_btn = ctk.CTkButton(
            button_frame,
            text="👤 Generate Profile",
            command=self.generate_profile,
            fg_color="#4169e1",
            hover_color="#3457c9",
            state="disabled"
        )
        self.profile_btn.pack(side="left", padx=5)
        
        self.clear_btn = ctk.CTkButton(
            button_frame,
            text="🗑️ Clear",
            command=self.clear_all,
            fg_color="#8b0000",
            hover_color="#6b0000"
        )
        self.clear_btn.pack(side="left", padx=5)
        
        # Traffic counter
        self.traffic_count = 0
        
        # Check AI status
        self.check_ai_status()
    
    def check_ai_status(self):
        """Check if AI is connected"""
        if self.app.ai_analyzer.is_connected:
            self.status_label.configure(
                text="✅ AI Status: Llama 3 Connected",
                text_color="#00ff00"
            )
            self.analyze_btn.configure(state="normal")
            self.profile_btn.configure(state="normal")
        else:
            self.status_label.configure(
                text="❌ AI Status: Disconnected (Check Ollama)",
                text_color="#ff0000"
            )
    
    def add_traffic_entry(self, domain, packet_type):
        """
        Add traffic entry to Matrix-style feed
        
        Args:
            domain (str): Domain name
            packet_type (str): Type of packet
        """
        self.traffic_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Limit traffic entries to prevent UI collapse (keep last 100)
        MAX_ENTRIES = 100
        children = self.traffic_list.winfo_children()
        if len(children) >= MAX_ENTRIES:
            # Remove oldest entry
            children[0].destroy()
        
        # Create entry frame
        entry = ctk.CTkFrame(
            self.traffic_list,
            fg_color="#001a00",
            corner_radius=3,
            height=30
        )
        entry.pack(fill="x", pady=2)
        
        # Timestamp
        time_label = ctk.CTkLabel(
            entry,
            text=f"[{timestamp}]",
            font=ctk.CTkFont(size=10, family="Consolas"),
            text_color="#00ff00",
            width=80
        )
        time_label.pack(side="left", padx=5)
        
        # Type badge
        type_colors = {
            'DNS': '#00d4ff',
            'HTTP': '#ffa500',
            'HTTPS': '#ff6b6b'
        }
        type_label = ctk.CTkLabel(
            entry,
            text=packet_type,
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=type_colors.get(packet_type, '#ffffff'),
            width=50
        )
        type_label.pack(side="left", padx=5)
        
        # Domain
        domain_label = ctk.CTkLabel(
            entry,
            text=domain,
            font=ctk.CTkFont(size=10, family="Consolas"),
            text_color="#00ff00",
            anchor="w"
        )
        domain_label.pack(side="left", fill="x", expand=True, padx=5)
        
        # Auto-scroll to bottom
        self.traffic_list._parent_canvas.yview_moveto(1.0)
    
    def add_insight_card(self, title, content, icon="💡", color="#00d4ff"):
        """
        Add insight card to timeline
        
        Args:
            title (str): Card title
            content (str): Insight content
            icon (str): Emoji icon
            color (str): Accent color
        """
        timestamp = datetime.now().strftime("%H:%M")
        
        # Card frame
        card = ctk.CTkFrame(
            self.insights_list,
            fg_color="#1a1a1a",
            corner_radius=8,
            border_width=2,
            border_color=color
        )
        card.pack(fill="x", pady=8, padx=5)
        
        # Header
        header_frame = ctk.CTkFrame(card, fg_color="transparent")
        header_frame.pack(fill="x", padx=10, pady=(10, 5))
        
        icon_label = ctk.CTkLabel(
            header_frame,
            text=icon,
            font=ctk.CTkFont(size=20)
        )
        icon_label.pack(side="left", padx=(0, 10))
        
        title_label = ctk.CTkLabel(
            header_frame,
            text=title,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=color,
            anchor="w"
        )
        title_label.pack(side="left", fill="x", expand=True)
        
        time_label = ctk.CTkLabel(
            header_frame,
            text=f"🕐 {timestamp}",
            font=ctk.CTkFont(size=10),
            text_color="#666666"
        )
        time_label.pack(side="right")
        
        # Content
        content_label = ctk.CTkLabel(
            card,
            text=content,
            font=ctk.CTkFont(size=12),
            text_color="#cccccc",
            anchor="w",
            justify="left",
            wraplength=400
        )
        content_label.pack(fill="x", padx=10, pady=(0, 10))
        
        # Auto-scroll to bottom
        self.insights_list._parent_canvas.yview_moveto(1.0)
    
    def analyze_traffic(self):
        """Analyze buffered traffic with AI"""
        # Check actual AI buffer, not UI counter
        if not self.app.ai_analyzer.traffic_buffer:
            logger.warning("No traffic to analyze")
            return
        
        self.analyze_btn.configure(state="disabled", text="🔄 Analyzing...")
        logger.info("Starting AI traffic analysis...")
        
        # Run analysis in background
        def analyze():
            result = self.app.ai_analyzer.analyze_traffic()
            return result
        
        def on_complete(result):
            # Check if widget still exists before updating
            if not self.winfo_exists():
                return
            
            self.analyze_btn.configure(state="normal", text="🔍 Analyze Traffic")
            
            if result['success']:
                analysis = result['analysis']
                self.add_insight_card(
                    "Traffic Analysis",
                    analysis,
                    icon="🔍",
                    color="#00a86b"
                )
                logger.success(f"AI analysis complete - {result['insight']['domains_analyzed']} domains analyzed")
            else:
                logger.error(f"AI analysis failed: {result.get('error', 'Unknown error')}")
        
        self.app.thread_manager.run_in_background(analyze, on_complete)
    
    def generate_profile(self):
        """Generate behavioral profile"""
        # Check actual AI buffer, not UI counter
        if not self.app.ai_analyzer.traffic_buffer:
            logger.warning("No traffic data for profiling")
            return
        
        self.profile_btn.configure(state="disabled", text="🔄 Profiling...")
        logger.info("Generating behavioral profile...")
        
        def profile():
            result = self.app.ai_analyzer.generate_profile()
            return result
        
        def on_complete(result):
            # Check if widget still exists before updating
            if not self.winfo_exists():
                return
            
            self.profile_btn.configure(state="normal", text="👤 Generate Profile")
            
            if result and result['success']:
                profile = result['profile']
                self.add_insight_card(
                    "Behavioral Profile",
                    profile,
                    icon="👤",
                    color="#4169e1"
                )
                logger.success("Behavioral profile generated")
            else:
                logger.error(f"Profile generation failed: {result.get('error', 'Unknown error') if result else 'No result'}")
        
        self.app.thread_manager.run_in_background(profile, on_complete)
    
    def clear_all(self):
        """Clear all traffic and insights"""
        # Clear traffic feed
        for widget in self.traffic_list.winfo_children():
            widget.destroy()
        
        # Clear insights
        for widget in self.insights_list.winfo_children():
            widget.destroy()
        
        # Clear AI buffer
        self.app.ai_analyzer.clear_buffer()
        
        self.traffic_count = 0
        logger.info("AI analysis cleared")
