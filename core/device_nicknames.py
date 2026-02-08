"""
Device nickname storage - Remember custom names for devices
"""
import json
import os

class DeviceNicknames:
    """Store and retrieve custom device nicknames"""
    
    def __init__(self, storage_file="device_nicknames.json"):
        """Initialize nickname storage"""
        self.storage_file = storage_file
        self.nicknames = self._load_nicknames()
    
    def _load_nicknames(self):
        """Load nicknames from file"""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_nicknames(self):
        """Save nicknames to file"""
        try:
            with open(self.storage_file, 'w') as f:
                json.dump(self.nicknames, f, indent=2)
        except Exception as e:
            print(f"[!] Error saving nicknames: {e}")
    
    def set_nickname(self, mac_address, nickname):
        """
        Set a custom nickname for a device
        
        Args:
            mac_address (str): MAC address (unique identifier)
            nickname (str): Custom name
        """
        self.nicknames[mac_address] = nickname
        self._save_nicknames()
    
    def get_nickname(self, mac_address):
        """
        Get custom nickname for a device
        
        Args:
            mac_address (str): MAC address
            
        Returns:
            str: Nickname or None if not set
        """
        return self.nicknames.get(mac_address)
    
    def remove_nickname(self, mac_address):
        """Remove a nickname"""
        if mac_address in self.nicknames:
            del self.nicknames[mac_address]
            self._save_nicknames()
    
    def get_all_nicknames(self):
        """Get all stored nicknames"""
        return self.nicknames.copy()
