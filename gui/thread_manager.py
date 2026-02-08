"""
Thread Manager - Execute background operations without blocking GUI
"""
import threading
from queue import Queue

class ThreadManager:
    """Manages background threads for GUI operations"""
    
    def __init__(self):
        """Initialize the thread manager"""
        self.active_threads = []
    
    def run_in_background(self, func, callback=None, *args, **kwargs):
        """
        Execute a function in a background thread
        
        Args:
            func: Function to execute
            callback: Optional callback function to call with result
            *args, **kwargs: Arguments to pass to func
            
        Returns:
            threading.Thread: The created thread
        """
        def wrapper():
            try:
                result = func(*args, **kwargs)
                if callback:
                    callback(result)
            except Exception as e:
                print(f"[!] Thread error: {e}")
                if callback:
                    callback(None)
        
        thread = threading.Thread(target=wrapper, daemon=True)
        thread.start()
        self.active_threads.append(thread)
        
        # Clean up finished threads
        self.active_threads = [t for t in self.active_threads if t.is_alive()]
        
        return thread
    
    def cleanup(self):
        """Wait for all active threads to finish"""
        print(f"[*] Waiting for {len(self.active_threads)} thread(s) to finish...")
        for thread in self.active_threads:
            thread.join(timeout=2)
        self.active_threads.clear()
