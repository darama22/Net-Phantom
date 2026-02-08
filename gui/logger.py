"""
Logger utility for GUI console output
"""
import datetime
from typing import Callable, Optional

class GUILogger:
    """Centralized logger that can output to GUI console"""
    
    def __init__(self):
        self.callback: Optional[Callable] = None
    
    def set_callback(self, callback: Callable):
        """Set the callback function to update GUI"""
        self.callback = callback
    
    def log(self, message: str, level: str = "INFO"):
        """
        Log a message with timestamp
        
        Args:
            message (str): Message to log
            level (str): Log level (INFO, SUCCESS, WARNING, ERROR)
        """
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        # Color codes for different levels
        prefix = {
            "INFO": "ℹ️",
            "SUCCESS": "✓",
            "WARNING": "⚠️",
            "ERROR": "❌",
            "SCAN": "🔍",
            "MITM": "🎯",
            "NETWORK": "🌐"
        }.get(level, "•")
        
        formatted_message = f"[{timestamp}] {prefix} {message}"
        
        # Print to console
        print(formatted_message)
        
        # Send to GUI if callback is set
        if self.callback:
            self.callback(formatted_message, level)
    
    def info(self, message: str):
        """Log info message"""
        self.log(message, "INFO")
    
    def success(self, message: str):
        """Log success message"""
        self.log(message, "SUCCESS")
    
    def warning(self, message: str):
        """Log warning message"""
        self.log(message, "WARNING")
    
    def error(self, message: str):
        """Log error message"""
        self.log(message, "ERROR")
    
    def scan(self, message: str):
        """Log scan-related message"""
        self.log(message, "SCAN")
    
    def mitm(self, message: str):
        """Log MITM-related message"""
        self.log(message, "MITM")
    
    def network(self, message: str):
        """Log network-related message"""
        self.log(message, "NETWORK")

# Global logger instance
logger = GUILogger()
