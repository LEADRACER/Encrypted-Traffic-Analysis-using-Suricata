# Encrypted Traffic Analysis Real-time Dashboard

An interactive real-time dashboard for monitoring both Suricata IDS/IPS events and live Wireshark traffic analysis.

## Features

- **Real-time monitoring** of Suricata eve.json logs (security events)
- **Live Wireshark traffic analysis** with protocol extraction
- **Combined statistics dashboard** showing events from both sources
- **Event timeline visualization** with per-minute aggregation
- **Protocol distribution charts** (TCP/UDP/HTTP/DNS/TLS)
- **Recent events feed** with source identification (Suricata 🛡️ vs Wireshark 📡)
- **Automatic updates** with connection status indicators
- **Source differentiation** in event listing

## Data Sources

1. **Suricata Logs**: `../../project_output/suricata_logs/eve.json`
   - Security events (alerts, DNS, HTTP, TLS)
   - Blocked/dropped packet information
   - JA3 TLS fingerprinting data

2. **Wireshark Analysis**: `../../project_output/wireshark_logs/realtime.json`
   - Live packet analysis from tshark
   - Protocol detection (TCP, UDP, HTTP, DNS, TLS)
   - IP/port extraction and basic protocol analysis

## Usage

### Method 1: Complete Pipeline (Recommended)
```bash
sudo ./run.sh [duration_seconds]
```
This will:
1. Start the real-time dashboard server
2. Launch Wireshark capture in real-time mode
3. Run Suricata analysis
4. Perform ML-based traffic analysis
5. Stop all components when finished

### Method 2: Dashboard Only
```bash
cd dashboard
python server.py
```
Then manually start your data sources:
- Wireshark: `python wireshark_capture.py --interface eth0 --realtime`
- Suricata: `python suricata_run.py --interface eth0 --duration 0 --realtime`

### Method 3: Individual Components
```bash
# Start dashboard
cd dashboard && python server.py &

# Start Wireshark real-time capture
python wireshark_capture.py --interface eth0 --realtime &

# Start Suricata in real-time mode  
python suricata_run.py --interface eth0 --duration 0 --realtime &
```

## Dashboard Components

### Statistics Panel
Shows real-time counters for:
- **Total Events**: Combined count from both sources
- **Alerts**: Suricata security alerts
- **DNS Queries**: DNS requests from both sources
- **HTTP Flows**: HTTP traffic detected
- **TLS Sessions**: TLS/SSL connections
- **Blocked IPs**: IPs blocked by Suricata (in IPS mode) or analysis module

### Events Panel
Displays recent events with:
- **Timestamp**: HH:MM:SS format
- **Source Icon**: 🛡️ for Suricata, 📡 for Wireshark
- **Event Type**: dns, http, tls, alert, ip, etc.
- **Event Details**: Context-specific information
- **Action**: alert, drop, blocked, etc. (when applicable)

### Charts Panel
- **Protocol Distribution**: Pie chart showing TCP/UDP/other protocol ratios
- **Events Timeline**: Line chart showing events per minute over last 30 minutes

## How It Works

### Wireshark Capture (`wireshark_capture.py`)
- Uses tshark with JSON output for structured data
- Extracts IP, port, and protocol information in real-time
- Classifies packets as DNS, HTTP, TLS, or generic IP traffic
- Outputs analysis results to `project_output/wireshark_logs/realtime.json`
- Supports both fixed-duration and infinite real-time modes

### Dashboard Updates
- Polls both data source files every second for new content
- Processes new JSON lines and updates statistics/events/charts
- Maintains connection status based on file accessibility
- Gracefully handles missing files (shows disconnected until available)

### Event Processing
- Events from both sources are combined in a single timeline
- Each event retains its source identifier for display
- Statistics are aggregated across both sources
- Timeline charts show events per minute for trend analysis

## Customization

You can modify the dashboard by editing:
- `index.html` - Structure and layout
- `style.css` - Visual styling and theme
- `script.js` - Dashboard logic, chart updates, and event processing

## Wireshark Capture Options

```bash
# Real-time infinite capture (for continuous monitoring)
python wireshark_capture.py --interface eth0 --realtime

# Fixed duration capture
python wireshark_capture.py --interface eth0 --duration 300

# Custom output location
python wireshark_capture.py --interface eth0 --realtime --output /tmp/wireshark.json

# Adjust flush frequency (seconds)
python wireshark_capture.py --interface eth0 --realtime --buffer-time 1
```

## Notes

- The dashboard assumes default file locations relative to the dashboard directory
- Wireshark capture requires sudo privileges for tshark access
- Both data sources use JSON lines format (one JSON object per line)
- Charts are powered by Chart.js (loaded from CDN)
- The system is designed to handle temporary file unavailability gracefully

## Example Output

When running, you'll see:
- Statistics updating in real-time as packets are captured
- Events appearing in the list with source icons
- Protocol chart showing live TCP/UDP distribution
- Timeline chart showing events per minute trends
- Connection status indicator showing data source health