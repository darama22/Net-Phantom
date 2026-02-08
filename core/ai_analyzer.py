"""
AI Analyzer - Llama 3 powered traffic analysis
"""
import ollama
from datetime import datetime
from collections import defaultdict
import json

class AIAnalyzer:
    """AI-powered network traffic analyzer using Llama 3"""
    
    def __init__(self):
        """Initialize AI analyzer"""
        self.model = "llama3"
        self.traffic_buffer = []
        self.insights = []
        self.current_profile = None
        self.is_connected = False
        
        # Test connection
        self._test_connection()
    
    def _test_connection(self):
        """Test connection to Ollama"""
        try:
            # Simple test prompt
            response = ollama.chat(
                model=self.model,
                messages=[{'role': 'user', 'content': 'Hello'}],
                options={'num_predict': 10}
            )
            self.is_connected = True
            print("[✓] AI Analyzer connected to Llama 3")
        except Exception as e:
            self.is_connected = False
            print(f"[!] AI Analyzer connection failed: {e}")
    
    def add_traffic(self, domain, packet_type):
        """
        Add traffic to buffer for analysis
        
        Args:
            domain (str): Domain or destination
            packet_type (str): Type of packet (DNS, HTTP, etc.)
        """
        # Limit buffer to last 500 entries to prevent memory issues
        MAX_BUFFER = 500
        if len(self.traffic_buffer) >= MAX_BUFFER:
            self.traffic_buffer.pop(0)  # Remove oldest
        
        self.traffic_buffer.append({
            'domain': domain,
            'type': packet_type,
            'timestamp': datetime.now()
        })
        
        # Debug: Log every 50th packet
        if len(self.traffic_buffer) % 50 == 0:
            print(f"[DEBUG] AI Buffer: {len(self.traffic_buffer)} entries")
    
    def analyze_traffic(self):
        """
        Analyze buffered traffic using Llama 3
        
        Returns:
            dict: Analysis results with insights
        """
        if not self.is_connected:
            return {
                'success': False,
                'error': 'AI not connected'
            }
        
        if not self.traffic_buffer:
            print(f"[DEBUG] AI Analyzer: Buffer is EMPTY (size: {len(self.traffic_buffer)})")
            return {
                'success': False,
                'error': 'No traffic to analyze'
            }
        
        print(f"[DEBUG] AI Analyzer: Analyzing {len(self.traffic_buffer)} entries")
        
        # Prepare traffic summary
        domains = [t['domain'] for t in self.traffic_buffer]
        domain_counts = defaultdict(int)
        for d in domains:
            domain_counts[d] += 1
        
        # Get top domains
        top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Get time of day
        now = datetime.now()
        hour = now.hour
        time_context = self._get_time_context(hour)
        
        # Build prompt
        prompt = self._build_analysis_prompt(top_domains, time_context)
        
        try:
            # Call Llama 3
            response = ollama.chat(
                model=self.model,
                messages=[{
                    'role': 'system',
                    'content': 'You are a cybersecurity analyst specializing in behavioral profiling from network traffic. Be concise and insightful.'
                }, {
                    'role': 'user',
                    'content': prompt
                }]
            )
            
            analysis = response['message']['content']
            
            # Create insight card
            insight = {
                'timestamp': datetime.now(),
                'analysis': analysis,
                'domains_analyzed': len(domains),
                'top_domain': top_domains[0][0] if top_domains else 'None'
            }
            
            self.insights.append(insight)
            
            return {
                'success': True,
                'insight': insight,
                'analysis': analysis
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def generate_profile(self):
        """
        Generate behavioral profile from all traffic
        
        Returns:
            dict: User profile
        """
        if not self.is_connected or not self.traffic_buffer:
            return None
        
        # Analyze patterns
        domains = [t['domain'] for t in self.traffic_buffer]
        timestamps = [t['timestamp'] for t in self.traffic_buffer]
        
        # Build profile prompt
        prompt = f"""Based on this network activity, create a brief behavioral profile:

Domains visited: {', '.join(set(domains[:20]))}
Total requests: {len(domains)}
Time range: {timestamps[0].strftime('%H:%M')} - {timestamps[-1].strftime('%H:%M')}

Provide:
1. User type (gamer, student, professional, etc.)
2. Current activity
3. Potential security vulnerabilities

Keep it under 150 words."""
        
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{
                    'role': 'system',
                    'content': 'You are a behavioral analyst. Be concise and specific.'
                }, {
                    'role': 'user',
                    'content': prompt
                }]
            )
            
            profile = response['message']['content']
            self.current_profile = profile
            
            return {
                'success': True,
                'profile': profile,
                'timestamp': datetime.now()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def generate_phishing_hook(self, target_domain):
        """
        Generate contextual phishing message
        
        Args:
            target_domain (str): Domain user just visited
            
        Returns:
            dict: Phishing message
        """
        if not self.is_connected:
            return None
        
        prompt = f"""The target just visited: {target_domain}

Generate a convincing phishing SMS message that:
- References this specific service
- Creates urgency
- Looks legitimate
- Is under 160 characters

Provide ONLY the message text, nothing else."""
        
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{
                    'role': 'system',
                    'content': 'You are a social engineering expert. Generate realistic phishing messages for security awareness training.'
                }, {
                    'role': 'user',
                    'content': prompt
                }]
            )
            
            message = response['message']['content'].strip()
            
            return {
                'success': True,
                'domain': target_domain,
                'message': message,
                'timestamp': datetime.now()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _build_analysis_prompt(self, top_domains, time_context):
        """Build analysis prompt"""
        domains_str = '\n'.join([f"- {domain} ({count} requests)" for domain, count in top_domains])
        
        return f"""Analyze this network traffic and provide insights:

Top domains visited:
{domains_str}

Time context: {time_context}

Provide a brief analysis (under 100 words):
1. What is the user doing?
2. User profile/type
3. Any security concerns

Be specific and insightful."""
    
    def _get_time_context(self, hour):
        """Get time of day context"""
        if 0 <= hour < 6:
            return "Late night (12 AM - 6 AM) - Unusual activity hours"
        elif 6 <= hour < 12:
            return "Morning (6 AM - 12 PM)"
        elif 12 <= hour < 18:
            return "Afternoon (12 PM - 6 PM)"
        else:
            return "Evening (6 PM - 12 AM)"
    
    def clear_buffer(self):
        """Clear traffic buffer"""
        self.traffic_buffer = []
    
    def get_insights(self, limit=10):
        """Get recent insights"""
        return self.insights[-limit:]
