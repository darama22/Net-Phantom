# NET-PHANTOM

**Network Security Auditing Dashboard with AI-Powered Traffic Analysis**

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-Educational-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)

Net-Phantom is a comprehensive network security auditing tool designed for educational purposes and authorized security research. It provides a modern GUI for network reconnaissance, MITM attacks, packet sniffing, and AI-powered traffic analysis using Llama 3.

## Legal Disclaimer

**IMPORTANT:** This tool is designed exclusively for educational purposes and authorized security auditing.

- **Legal Use:** Testing on networks you own or have explicit written permission to audit
- **Illegal Use:** Unauthorized access to networks, intercepting communications without permission

**Unauthorized network analysis is illegal and punishable by law.** The developers assume no liability for misuse of this software.

## Features

### Network Analysis
- **Network Scanner:** Fast ARP-based device discovery with MAC vendor identification
- **Device Management:** Rename and track devices with persistent nicknames
- **MITM Attack:** ARP spoofing for traffic interception and analysis
- **Kill Switch:** Block internet access for targeted devices
- **Packet Sniffer:** Real-time traffic capture with intelligent filtering

### AI-Powered Analysis
- **Traffic Analysis:** AI-powered behavioral analysis using Llama 3
- **User Profiling:** Generate detailed profiles based on browsing patterns
- **Smart Filtering:** Automatic removal of CDNs, ads, telemetry, and noise
- **Target Isolation:** Filter traffic by device IP to avoid capturing host traffic

### User Interface
- **Modern GUI:** Built with CustomTkinter (dark-blue theme)
- **Real-Time Monitoring:** Live packet statistics and traffic feed
- **Visual Indicators:** Status indicators for MITM and sniffer states
- **Threaded Operations:** Non-blocking GUI with background processing

## Installation

### Prerequisites
- Python 3.8 or higher
- Administrator/Root privileges (required for network manipulation)
- Ollama with Llama 3 model (for AI analysis)

### Setup

1. Clone the repository
```bash
git clone https://github.com/darama22/Net-Phantom.git
cd Net-Phantom
```

2. Install dependencies
```bash
pip install -r requirements.txt
```

3. Install Ollama and Llama 3 (for AI features)
```bash
# Download Ollama from https://ollama.ai
ollama pull llama3
```

4. Run as administrator
```bash
# Windows
.\launch.bat

# Linux/macOS
sudo python main.py
```

## Usage

### Network Scanning
1. Navigate to **Network Scanner** page
2. Enter IP range (e.g., `192.168.1.0/24`)
3. Click **Scan Network**
4. View discovered devices with IP, MAC, and vendor information

### MITM Attack
1. Select a target device from scan results
2. Click **Start MITM**
3. Optionally start **Packet Sniffer** to capture traffic
4. Use **Kill Switch** to block target's internet access
5. Click **Stop** when finished

### AI Analysis
1. Navigate to **AI Analysis** page
2. Ensure sniffer has captured traffic
3. Click **Analyze Traffic** for behavioral analysis
4. Click **Generate Profile** for detailed user profiling

## Project Structure

```
Net-Phantom/
├── main.py                  # Entry point with privilege verification
├── launch.bat              # Windows launcher
├── requirements.txt        # Python dependencies
├── core/
│   ├── ai_analyzer.py      # AI traffic analysis with Llama 3
│   ├── device_nicknames.py # Device nickname management
│   ├── mitm.py             # ARP spoofing engine
│   ├── platform_utils.py   # OS-specific IP forwarding
│   ├── scanner.py          # Network device discovery
│   ├── sniffer.py          # Packet capture engine
│   └── traffic_filter.py   # Intelligent traffic filtering
└── gui/
    ├── app.py              # Main application window
    ├── logger.py           # Logging system
    ├── thread_manager.py   # Background operation handler
    └── pages/
        ├── ai_page.py      # AI analysis interface
        ├── dashboard.py    # Statistics dashboard
        └── scanner_page.py # Scanner and MITM controls
```

## Technical Details

### Technologies
- **Scapy:** Packet manipulation and network analysis
- **CustomTkinter:** Modern GUI framework
- **Ollama:** Local LLM inference for AI analysis
- **psutil:** System utilities
- **mac-vendor-lookup:** Device vendor identification

### Key Features
- **Thread-Safe Operations:** All network operations run in background threads
- **Intelligent Filtering:** Removes CDNs, ads, telemetry, local IPs, and proxy discovery
- **IP-Based Filtering:** Only captures traffic from targeted device
- **Memory Management:** Automatic buffer limits (100 UI entries, 500 AI buffer)
- **Cross-Platform:** Automatic IP forwarding for Windows, Linux, and macOS

### Traffic Filtering
The sniffer automatically filters out:
- Private IP addresses (192.168.x.x, 10.x.x.x, etc.)
- CDN domains (Akamai, Cloudflare, Azure Edge, etc.)
- Telemetry services (Google Analytics, Microsoft, Apple)
- Ad networks (DoubleClick, AdButler, etc.)
- Certificate validation (OCSP, CRL)
- mDNS and local discovery

## Safety Features

- **Automatic Cleanup:** ARP tables restored on exit
- **Emergency Restoration:** atexit handlers ensure cleanup on crash
- **IP Forwarding Management:** Automatically enabled/disabled per session
- **Target Isolation:** Sniffer only captures traffic from selected device

## Educational Value

This project demonstrates:
- **Network Protocols:** ARP, TCP/IP, DNS
- **Security Concepts:** MITM attacks, packet sniffing, traffic analysis
- **AI Integration:** Using LLMs for behavioral analysis
- **Software Engineering:** MVC architecture, threading, event-driven programming
- **Python Skills:** Scapy, GUI development, system-level programming

## Contributing

Contributions that enhance educational value are welcome:
- Bug fixes and improvements
- Documentation enhancements
- Additional security auditing features
- Cross-platform compatibility improvements

## License

This project is released for educational purposes only. Use responsibly and ethically.

## Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [CustomTkinter Documentation](https://customtkinter.tomschimansky.com/)
- [Ollama Documentation](https://ollama.ai)
- [ARP Protocol (RFC 826)](https://tools.ietf.org/html/rfc826)

## Author

Created as a portfolio project demonstrating network security knowledge, AI integration, and Python development skills.

---

**Remember:** With great power comes great responsibility. Use this tool ethically and legally.
