"""
Scanner Page - Network device discovery and targeting
"""
import customtkinter as ctk
from core.scanner import NetworkScanner
from core.device_nicknames import DeviceNicknames
from gui.logger import logger

class ScannerPage(ctk.CTkFrame):
    """Network scanner page with device list and controls"""
    
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        
        self.app = app
        self.scanner = self.app.network_scanner
        self.nicknames = DeviceNicknames()
        self.devices = []
        self.selected_device = None
        self.target_ip = None  # IP of device being targeted for MITM
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Create scanner page widgets"""
        # Title
        title = ctk.CTkLabel(
            self,
            text="Network Scanner",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.pack(pady=20)
        
        # Controls frame
        controls_frame = ctk.CTkFrame(self)
        controls_frame.pack(fill="x", padx=40, pady=10)
        
        # IP range input
        ctk.CTkLabel(
            controls_frame,
            text="IP Range:",
            font=ctk.CTkFont(size=14)
        ).grid(row=0, column=0, padx=10, pady=10)
        
        self.ip_range_entry = ctk.CTkEntry(
            controls_frame,
            placeholder_text="192.168.1.0/24",
            width=200
        )
        self.ip_range_entry.grid(row=0, column=1, padx=10, pady=10)
        self.ip_range_entry.insert(0, "192.168.1.0/24")
        
        # Scan button
        self.scan_btn = ctk.CTkButton(
            controls_frame,
            text="🔍 Scan Network",
            command=self.start_scan,
            width=150,
            height=35
        )
        self.scan_btn.grid(row=0, column=2, padx=10, pady=10)
        
        # Device list frame
        list_frame = ctk.CTkFrame(self)
        list_frame.pack(fill="both", expand=True, padx=40, pady=10)
        
        # List title
        list_title = ctk.CTkLabel(
            list_frame,
            text="Discovered Devices",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        list_title.pack(pady=(10, 5))
        
        # Scrollable device list
        self.device_list = ctk.CTkScrollableFrame(list_frame, height=300)
        self.device_list.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Action buttons frame
        action_frame = ctk.CTkFrame(self)
        action_frame.pack(fill="x", padx=40, pady=10)
        
        self.mitm_btn = ctk.CTkButton(
            action_frame,
            text="🎯 Start MITM Audit",
            command=self.start_mitm,
            state="disabled",
            fg_color="#1f6aa5",
            hover_color="#144870"
        )
        self.mitm_btn.pack(side="left", padx=10, pady=10)
        
        self.sniffer_btn = ctk.CTkButton(
            action_frame,
            text="📡 Start Sniffer",
            command=self.toggle_sniffer,
            state="disabled",
            fg_color="#0d7377",
            hover_color="#094d4f"
        )
        self.sniffer_btn.pack(side="left", padx=10, pady=10)
        # Kill Switch button
        self.kill_switch_btn = ctk.CTkButton(
            action_frame,
            text="🔪 Enable Kill Switch",
            command=self.toggle_kill_switch,
            state="disabled",
            fg_color="#8B0000",
            hover_color="#A52A2A"
        )
        self.kill_switch_btn.pack(side="left", padx=10, pady=10)
        
        self.stop_btn = ctk.CTkButton(
            action_frame,
            text="⏹ Stop Audit",
            command=self.stop_mitm,
            state="disabled",
            fg_color="#c42b1c",
            hover_color="#8b1f14"
        )
        self.stop_btn.pack(side="left", padx=10, pady=10)
        
        # Info label
        self.info_label = ctk.CTkLabel(
            action_frame,
            text="Select a target device to begin audit",
            font=ctk.CTkFont(size=12),
            text_color="gray50"
        )
        self.info_label.pack(side="left", padx=20)
        
        # Restore state if attack is active
        self.restore_state()
        
    def restore_state(self):
        """Restore UI state from app settings if returning to page"""
        if self.app.mitm_active and self.app.active_target:
            self.selected_device = self.app.active_target
            target_ip = self.selected_device['ip']
            
            # Restore UI elements
            self.mitm_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            self.sniffer_btn.configure(state="normal")
            self.kill_switch_btn.configure(state="normal")
            
            self.info_label.configure(text=f"✓ MITM active on {target_ip}")
            
            # Check if sniffer is active
            if self.app.sniffer_active:
                self.sniffer_btn.configure(text="🛑 Stop Sniffer", fg_color="#c42b1c", hover_color="#8b1f14")
                
            # Check if kill switch is active
            if self.app.arp_spoofer.kill_switch_active:
                self.kill_switch_btn.configure(text="🔓 Disable Kill Switch")
    
    def start_scan(self):
        """Start network scan in background thread"""
        ip_range = self.ip_range_entry.get()
        
        if not ip_range:
            self.info_label.configure(text="⚠️ Please enter an IP range")
            logger.warning("Scan aborted: No IP range specified")
            return
        
        # Disable scan button
        self.scan_btn.configure(state="disabled", text="⏳ Scanning...")
        self.info_label.configure(text="Scanning network...")
        
        logger.scan(f"Starting network scan on range: {ip_range}")
        
        # Clear previous results
        for widget in self.device_list.winfo_children():
            widget.destroy()
        
        # Run scan in background
        self.app.thread_manager.run_in_background(
            self.scanner.scan_network,
            self.on_scan_complete,
            ip_range
        )
    
    def on_scan_complete(self, devices):
        """Handle scan completion"""
        self.devices = devices if devices else []
        
        # Re-enable scan button
        self.scan_btn.configure(state="normal", text="🔍 Scan Network")
        
        if not self.devices:
            self.info_label.configure(text="No devices found")
            logger.warning("Scan complete: No devices discovered")
            return
        
        self.info_label.configure(text=f"Found {len(self.devices)} device(s)")
        logger.success(f"Scan complete: Found {len(self.devices)} device(s)")
        
        # Display devices
        for device in self.devices:
            # Clean hostname for display
            hostname_clean = device.get('hostname', 'Unknown')
            if hostname_clean and hostname_clean != "Unknown":
                hostname_clean = hostname_clean.replace('.home', '').replace('.local', '')
                hostname_info = f" ({hostname_clean})"
            else:
                hostname_info = ""
            
            logger.network(f"{device['type']}: {device['ip']}{hostname_info} - {device['vendor']}")
            self._create_device_card(device)
    
    def _create_device_card(self, device):
        """Create a card for each discovered device"""
        # Check for custom nickname
        custom_nickname = self.nicknames.get_nickname(device['mac'])
        
        # Color coding based on device type
        if "Router" in device['type']:
            card_color = "#1a4d2e"  # Dark green
        elif "iPhone" in device['type'] or "iPad" in device['type'] or "Apple" in device['type']:
            card_color = "#2d3748"  # Dark gray (Apple style)
        elif "Samsung" in device['type'] or "Android" in device['type']:
            card_color = "#1e3a5f"  # Dark blue
        elif "PC" in device['type'] or "Laptop" in device['type']:
            card_color = "#3d2e4f"  # Purple
        else:
            card_color = "#2d2d2d"  # Default dark
        
        card = ctk.CTkFrame(self.device_list, fg_color=card_color, border_width=2, border_color="#404040")
        card.pack(fill="x", padx=5, pady=8)
        
        # Device info
        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.pack(side="left", fill="both", expand=True, padx=15, pady=12)
        
        # Device type - Main header
        type_label = ctk.CTkLabel(
            info_frame,
            text=f"{device['type']}",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        )
        type_label.pack(anchor="w", pady=(0, 4))
        
        # Custom nickname (if set) - MOST PROMINENT
        if custom_nickname:
            nickname_label = ctk.CTkLabel(
                info_frame,
                text=f"⭐ {custom_nickname}",
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color="#FFD700",  # Gold color
                anchor="w"
            )
            nickname_label.pack(anchor="w", pady=(0, 6))
        
        # Hostname display (if no custom nickname)
        hostname_display = device.get('hostname', 'Unknown')
        if hostname_display and hostname_display != "Unknown" and not custom_nickname:
            # Remove .home, .local suffixes for cleaner display
            hostname_display = hostname_display.replace('.home', '').replace('.local', '')
            hostname_label = ctk.CTkLabel(
                info_frame,
                text=f"📛 {hostname_display}",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color="#00d4ff",
                anchor="w"
            )
            hostname_label.pack(anchor="w", pady=(0, 6))
        
        # IP address - prominent
        ip_label = ctk.CTkLabel(
            info_frame,
            text=f"🌐 {device['ip']}",
            font=ctk.CTkFont(size=12),
            text_color="#90EE90",
            anchor="w"
        )
        ip_label.pack(anchor="w", pady=(0, 2))
        
        # MAC address
        mac_label = ctk.CTkLabel(
            info_frame,
            text=f"MAC: {device['mac']}",
            font=ctk.CTkFont(size=10),
            text_color="gray60",
            anchor="w"
        )
        mac_label.pack(anchor="w", pady=(0, 2))
        
        # Vendor - only if not Unknown
        if device['vendor'] != "Unknown":
            vendor_label = ctk.CTkLabel(
                info_frame,
                text=f"Vendor: {device['vendor'][:40]}...",  # Truncate long names
                font=ctk.CTkFont(size=10),
                text_color="gray60",
                anchor="w"
            )
            vendor_label.pack(anchor="w")
        
        # Button frame
        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(side="right", padx=15, pady=12)
        
        # Rename button
        rename_btn = ctk.CTkButton(
            btn_frame,
            text="✏️",
            command=lambda d=device: self.rename_device(d),
            width=40,
            height=35,
            fg_color="#6b5b95",
            hover_color="#4a3f6b",
            font=ctk.CTkFont(size=14)
        )
        rename_btn.pack(side="top", pady=(0, 5))
        
        # Select button
        select_btn = ctk.CTkButton(
            btn_frame,
            text="🎯 Select",
            command=lambda d=device: self.select_device(d),
            width=100,
            height=35,
            fg_color="#1f6aa5",
            hover_color="#144870",
            font=ctk.CTkFont(size=12, weight="bold")
        )
        select_btn.pack(side="top")

    
    def select_device(self, device):
        """Select a device as target"""
        self.selected_device = device
        self.mitm_btn.configure(state="normal")
        self.info_label.configure(
            text=f"Target selected: {device['ip']} ({device['vendor']})"
        )
        logger.info(f"Target selected: {device['ip']} - {device['vendor']}")
    
    def start_mitm(self):
        """Start MITM attack on selected device"""
        if not self.selected_device:
            return
        
        # Get gateway IP (assume .1 for now, should be detected automatically)
        target_ip = self.selected_device['ip']
        gateway_ip = ".".join(target_ip.split(".")[:-1]) + ".1"
        
        # Store target IP for sniffer filtering
        self.target_ip = target_ip
        
        self.info_label.configure(text=f"Starting MITM on {target_ip}...")
        logger.mitm(f"Initiating MITM attack on target: {target_ip}")
        logger.network(f"Gateway detected: {gateway_ip}")
        
        # Start spoofing in background
        def start_spoof():
            success = self.app.arp_spoofer.start_spoofing(target_ip, gateway_ip)
            return success
        
        def on_complete(success):
            if success:
                self.mitm_btn.configure(state="disabled")
                self.stop_btn.configure(state="normal")
                self.sniffer_btn.configure(state="normal")
                self.kill_switch_btn.configure(state="normal")
                self.app.set_mitm_status(True, self.selected_device)
                self.info_label.configure(text=f"✓ MITM active on {target_ip}")
                logger.success(f"MITM successfully established on {target_ip}")
            else:
                self.info_label.configure(text="⚠️ Failed to start MITM")
                logger.error("MITM initialization failed - check network configuration")
        
        self.app.thread_manager.run_in_background(start_spoof, on_complete)
    
    def stop_mitm(self):
        """Stop MITM attack"""
        self.info_label.configure(text="Stopping MITM...")
        logger.mitm("Stopping MITM attack and restoring ARP tables...")
        
        def stop_spoof():
            self.app.arp_spoofer.stop_spoofing()
            return True
        
        def on_complete(success):
            self.mitm_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self.sniffer_btn.configure(state="disabled", text="📡 Start Sniffer")
            self.kill_switch_btn.configure(state="disabled", text="🔪 Enable Kill Switch")
            self.app.set_mitm_status(False)
            self.info_label.configure(text="MITM stopped")
            logger.success("MITM stopped - network restored to normal state")
            
            # Stop sniffer if running
            if self.app.packet_sniffer.is_sniffing:
                self.app.packet_sniffer.stop_sniffing()
                self.app.set_sniffer_status(False)
        
        self.app.thread_manager.run_in_background(stop_spoof, on_complete)
    
    def toggle_sniffer(self):
        """Toggle packet sniffer on/off"""
        if self.app.packet_sniffer.is_sniffing:
            # Stop sniffer
            self.app.packet_sniffer.stop_sniffing()
            self.app.set_sniffer_status(False)
            self.sniffer_btn.configure(text="📡 Start Sniffer", fg_color="#0c5460", hover_color="#094d4f")
            self.info_label.configure(text="Packet sniffer stopped")
        else:
            # Set target IP filter if MITM is active
            if self.target_ip:
                self.app.packet_sniffer.set_target_ip(self.target_ip)
                logger.scan(f"Sniffer filtering for target IP: {self.target_ip}")
            
            # Start sniffer
            self.app.packet_sniffer.start_sniffing()
            self.app.set_sniffer_status(True)
            self.sniffer_btn.configure(text="🛑 Stop Sniffer", fg_color="#c42b1c", hover_color="#8b1f14")
            self.info_label.configure(text="Packet sniffer active - monitoring traffic")
            logger.scan("Packet sniffer activated - capturing network traffic")
    
    def toggle_kill_switch(self):
        """Toggle kill switch on/off"""
        if not self.app.arp_spoofer.is_spoofing:
            logger.warning("MITM must be active to use kill switch")
            return
        
        # Check ACTUAL state from the spoofer
        if self.app.arp_spoofer.kill_switch_active:
            # Currently ACTIVE, so DISABLE it
            success = self.app.arp_spoofer.disable_kill_switch()
            if success:
                self.kill_switch_btn.configure(text="🔪 Enable Kill Switch")
                self.info_label.configure(text="Kill switch deactivated - target internet restored")
                logger.success("Kill switch deactivated - target internet access restored")
        else:
            # Currently INACTIVE, so ENABLE it
            success = self.app.arp_spoofer.enable_kill_switch()
            if success:
                self.kill_switch_btn.configure(text="🔓 Disable Kill Switch")
                self.info_label.configure(text="⚠️ Kill switch active - target internet blocked")
                logger.warning("Kill switch activated - target internet blocked")
    
    def rename_device(self, device):
        """Show dialog to rename a device"""
        dialog = ctk.CTkInputDialog(
            text=f"Enter custom name for:\n{device['ip']} ({device['type']})",
            title="Rename Device"
        )
        
        new_name = dialog.get_input()
        
        if new_name and new_name.strip():
            # Save nickname
            self.nicknames.set_nickname(device['mac'], new_name.strip())
            logger.success(f"Device renamed to: {new_name.strip()}")
            
            # Refresh device list to show new name
            self.on_scan_complete(self.devices)
