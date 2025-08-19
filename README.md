# NetChecker

A network security monitoring tool that analyzes running processes and their network connections, with optional VirusTotal integration for malware detection and IP reputation checking.

## Features

- **Process Network Monitoring**: Identify processes with listening ports and established network connections
- **VirusTotal Integration**: Optional file hash checking against VirusTotal's malware database
- **IP Reputation Checking**: Check remote IP addresses against VirusTotal's IP reputation database
- **Intelligent Caching**: Cache VirusTotal results for files and IPs to minimize API calls and improve performance
- **Security Analysis**: Detect potentially malicious processes making network connections
- **Flexible Output**: View listening processes, established connections, or both

## Installation

1. Clone or download this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

Show established network connections (default):
```bash
python netchecker.py
```

Show listening processes:
```bash
python netchecker.py --listening
```

Show both listening processes and established connections:
```bash
python netchecker.py --listening --established
```

### VirusTotal Integration

To enable malware detection via VirusTotal, you'll need an API key:

1. Sign up for a free VirusTotal account at https://www.virustotal.com/
2. Get your API key from your account settings
3. Use the API key in one of two ways:

**Option 1: Command line argument**
```bash
python netchecker.py --virustotal --api-key YOUR_API_KEY
```

**Option 2: Environment variable**
```bash
export VT_API_KEY=YOUR_API_KEY
python netchecker.py --virustotal
```

### Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--listening` | `-l` | Show processes with listening network ports |
| `--established` | `-e` | Show established network connections (default) |
| `--virustotal` | `-vt` | Enable VirusTotal hash checking |
| `--api-key` | `-k` | VirusTotal API key |

## Output Format

### Listening Processes
```
Listening Processes:
  PID: 1234, Name: example.exe
    Executable: /path/to/example.exe
    Listening on: 127.0.0.1:8080
    (Family: AddressFamily.AF_INET, Type: SocketKind.SOCK_STREAM)
    File Hash: abc123...
    VirusTotal: 2/67 detections
    ⚠️  ALERT: 2 engines detected this file as malicious!
    Report: https://www.virustotal.com/...
    IP Reputation: Clean (0 detections)
```

### Established Connections
```
Established Network Connections and Associated Processes:
  PID: 5678, Process: browser.exe
    Executable: /path/to/browser.exe
    Local: 192.168.1.100:54321
    Remote: 93.184.216.34:443
    Status: CONN_ESTABLISHED
    File Hash: def456...
    VirusTotal: 0/67 detections
    IP Reputation: Clean (0 detections)
```

## Security Features

- **Malware Detection**: When VirusTotal integration is enabled, file hashes are checked against a database of known malware
- **IP Reputation Analysis**: Check remote IP addresses for malicious activity (skips private/local IPs)
- **Intelligent Caching**: Results are cached in memory to avoid redundant API calls during the same session
- **Rate Limiting**: Automatic rate limiting when querying VirusTotal API (0.25 second delays, only for new queries)
- **Process Monitoring**: Identifies all processes making network connections
- **Suspicious Activity Detection**: Alerts when processes with positive malware detections are found

## Requirements

- Python 3.6+
- psutil 7.0.0+
- requests 2.31.0+ (for VirusTotal integration)
- Internet connection (for VirusTotal features)

## Privacy and Security Notes

- This tool requires elevated privileges on some systems to access process information
- VirusTotal integration sends file hashes and IP addresses (not file contents) to VirusTotal's servers
- File hashes are calculated using SHA256
- Only public IP addresses are checked for reputation (private/local IPs are skipped)
- Results are cached in memory during execution to minimize API calls
- No sensitive data is transmitted beyond file hashes and public IP addresses when using VirusTotal

## Limitations

- Some processes may be inaccessible due to permission restrictions
- VirusTotal API has rate limits (500 requests per minute for free accounts)
- Requires network connectivity for VirusTotal features
- Process information may be limited on some operating systems
- Cache is only maintained during a single execution session (not persistent across runs)

## Use Cases

- **Security Monitoring**: Regular checks for suspicious network activity
- **Incident Response**: Identifying malicious processes during security investigations
- **System Administration**: Understanding which processes are using network resources
- **Malware Analysis**: Quick triage of potentially infected systems

## License

This tool is provided for defensive security purposes only. Use responsibly and in accordance with your organization's security policies.