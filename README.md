# 🔒 NET-PHANTOM

**Professional Network Security Auditing Framework**

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-Educational-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

Net-Phantom is a comprehensive network security auditing tool designed for educational purposes and security research. It provides a modern graphical interface for performing ARP-based network analysis and Man-in-the-Middle (MITM) auditing.

## ⚠️ Legal Disclaimer

**IMPORTANT:** This tool is designed exclusively for educational purposes and authorized security auditing. 

- ✅ **Legal Use:** Testing on networks you own or have explicit written permission to audit
- ❌ **Illegal Use:** Unauthorized access to networks, intercepting communications without permission

**Unauthorized network analysis is illegal and punishable by law.** The developers assume no liability for misuse of this software.

## ✨ Features

### Core Capabilities
- **🔍 Network Discovery:** Fast ARP-based device scanning with vendor identification
- **🎯 MITM Auditing:** ARP spoofing for traffic analysis and security testing
- **🌐 Cross-Platform:** Full support for Windows, Linux, and macOS
- **🧵 Threaded Operations:** Non-blocking GUI with background network operations
- **🛡️ Safety Mechanisms:** Automatic ARP table restoration via `atexit` handlers

### User Interface
- **Modern GUI:** Built with CustomTkinter (dark-blue cyberpunk theme)
- **Real-Time Monitoring:** Live packet statistics and data counters
- **Visual Indicators:** Pulsing status indicator for active MITM sessions
- **Responsive Design:** Smooth navigation and threaded operations

## Installation

### Prerequisites
- **Python 3.8+**
- **Administrator/Root privileges** (required for network manipulation)
- **Windows 10/11** (for WinDivert support)

### Quick Setup

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/Net-Phantom.git
cd Net-Phantom
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

```

## 📖 Usage

### 1. Network Scanning
1. Navigate to **Network Scanner** page
2. Enter IP range (e.g., `192.168.1.0/24`)
3. Click **Scan Network**
4. View discovered devices with IP, MAC, and vendor information

### 2. MITM Auditing
1. Select a target device from the scan results
2. Click **Start MITM Audit**
3. Monitor traffic on the Dashboard
4. Click **Stop Audit** when finished

### Safety Features
- **Automatic Cleanup:** ARP tables are restored automatically on exit
- **Emergency Restoration:** `atexit` handlers ensure cleanup even on crash
- **IP Forwarding Management:** Automatically enabled/disabled per session

## 🏗️ Architecture

```
Net-Phantom/
├── main.py                 # Entry point with privilege verification
├── core/
│   ├── platform_utils.py   # OS-specific IP forwarding
│   ├── scanner.py          # ARP-based device discovery
│   └── mitm.py             # ARP spoofing engine
├── gui/
│   ├── app.py              # Main application window
│   ├── thread_manager.py   # Background operation handler
│   └── pages/
│       ├── dashboard.py    # Statistics and monitoring
│       └── scanner_page.py # Device discovery interface
└── requirements.txt
```

## 🎓 Educational Value

This project demonstrates:
- **Network Protocols:** ARP, TCP/IP stack manipulation
- **Security Concepts:** MITM attacks, packet sniffing, network reconnaissance
- **Software Engineering:** MVC architecture, threading, cross-platform development
- **Python Skills:** Scapy, CustomTkinter, system-level programming

## 🛠️ Technical Details

### Technologies Used
- **Scapy:** Packet manipulation and network analysis
- **CustomTkinter:** Modern GUI framework
- **psutil:** System utilities
- **mac-vendor-lookup:** Device vendor identification

### Key Features
- **Thread-Safe Operations:** All network operations run in background threads
- **Cross-Platform IP Forwarding:** Automatic detection and configuration for Windows (Registry), Linux (sysctl), and macOS
- **Robust Error Handling:** Graceful degradation and user feedback

## 📸 Screenshots

*Coming soon - Screenshots of the dashboard and scanner interface*

## 🤝 Contributing

This is an educational project. Contributions that enhance learning value are welcome:
- Bug fixes and improvements
- Documentation enhancements
- Additional security auditing features
- Cross-platform compatibility improvements

## 📝 License

This project is released for **educational purposes only**. Use responsibly and ethically.

## 🔗 Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [CustomTkinter Documentation](https://customtkinter.tomschimansky.com/)
- [ARP Protocol (RFC 826)](https://tools.ietf.org/html/rfc826)

## 👨‍💻 Author

Created as a portfolio project demonstrating network security knowledge and Python development skills.

---

**Remember:** With great power comes great responsibility. Use this tool ethically and legally.
