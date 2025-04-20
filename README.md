# Network Connection Monitor

![Application Screenshot](netapp.png) <!-- Add a screenshot if available -->

A Python-based GUI application that monitors network connections, allows blocking/unblocking IPs and applications, and logs connection data.

## Features

- Real-time monitoring of active network connections
- Display connection details (IP, port, PID, process name)
- Block/unblock specific IP addresses
- Block/unblock specific applications
- Copy connection information to clipboard
- Log connection data to CSV file
- System tray integration
- Multi-language support (English, Polish)
- Administrator privileges detection

## Requirements

- Python 3.7+
- Windows OS (for full functionality)

## Installation

1. Clone this repository:
   git clone https://github.com/yourusername/network-connection-monitor.git
   cd network-connection-monitor
2.Install the required dependencies:
   pip install -r requirements.txt
3.Run the application:
   python NetworkAppMonitor.py

Usage:
1.Start Monitoring: Click the "Start" button to begin monitoring network connections.
2.Adjust Interval: Set the refresh interval in seconds.
3.Block IPs/Apps: Right-click on a connection to block/unblock IPs or applications.
4.Logging: Enable logging to save connection data to a CSV file.
5.System Tray: Minimize to system tray for background monitoring.

Command Line Options:
Run the application with administrator privileges for full functionality (IP/application blocking).

Configuration:
1.Blocked IPs and applications are saved in blocked_ips.json and blocked_apps.json.
2.Language can be changed from the menu (English/Polish).

Troubleshooting:
1.If IP/application blocking doesn't work, ensure you're running as administrator.
2.Some features require Windows Firewall to be acttive

License
MIT License
