import psutil
import hashlib
import requests
import argparse
import time
import os
import ipaddress

# Global caches for VirusTotal results to avoid duplicate API calls
_vt_hash_cache = {}
_vt_ip_cache = {}

def calculate_file_hash(file_path):
    """Calculate SHA256 hash of a file."""
    if not file_path or not os.path.exists(file_path):
        return None
    
    try:
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except (IOError, OSError):
        return None

def check_virustotal(file_hash, api_key):
    """Check file hash against VirusTotal API."""
    if not file_hash or not api_key:
        return None
    
    # Check cache first
    if file_hash in _vt_hash_cache:
        return _vt_hash_cache[file_hash]
    
    url = f"https://www.virustotal.com/vtapi/v2/file/report"
    params = {
        'apikey': api_key,
        'resource': file_hash
    }
    
    try:
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('response_code') == 1:
                result = {
                    'scan_date': data.get('scan_date'),
                    'positives': data.get('positives', 0),
                    'total': data.get('total', 0),
                    'permalink': data.get('permalink')
                }
                # Cache the result
                _vt_hash_cache[file_hash] = result
                return result
        # Cache negative results too
        _vt_hash_cache[file_hash] = None
        return None
    except (requests.RequestException, ValueError):
        # Don't cache errors
        return None

def is_private_ip(ip_str):
    """Check if an IP address is private/local."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return True

def is_suspicious_location(file_path):
    """Check if executable is in a suspicious location commonly used by malware."""
    if not file_path:
        return False, "No executable path"
    
    file_path = file_path.lower().replace('\\', '/')
    
    # Suspicious directories commonly used by malware
    suspicious_paths = [
        # Temp directories
        '/temp/',
        '/tmp/',
        '/windows/temp/',
        '/users/public/',
        '/programdata/',
        
        # User-writable locations that shouldn't contain executables
        '/appdata/local/temp/',
        '/appdata/roaming/',
        '/downloads/',
        '/desktop/',
        '/documents/',
        '/music/',
        '/pictures/',
        '/videos/',
        
        # System directories that malware sometimes abuses
        '/windows/system32/tasks/',
        '/windows/syswow64/tasks/',
        '/recycler/',
        '/recycle.bin/',
        
        # Hidden or unusual locations
        '/$recycle.bin/',
        '/system volume information/',
        
        # Browser cache/temp locations
        '/cache/',
        '/temporary internet files/',
        
        # Common malware hiding spots
        '/intel/',
        '/nvidia/',
        '/microsoft shared/',
    ]
    
    # Check for suspicious paths
    for suspicious_path in suspicious_paths:
        if suspicious_path in file_path:
            return True, f"Located in suspicious directory: {suspicious_path.strip('/')}"
    
    # Check for executables with suspicious names or patterns
    filename = file_path.split('/')[-1] if '/' in file_path else file_path
    
    # Suspicious filename patterns
    suspicious_patterns = [
        # Random character patterns
        len(filename) > 20 and filename.replace('.exe', '').replace('.', '').isalnum() and 
        sum(c.isdigit() for c in filename) > len(filename) * 0.3,  # >30% digits
        
        # Mimicking system files but in wrong location
        filename in ['svchost.exe', 'explorer.exe', 'winlogon.exe', 'csrss.exe'] and 
        '/windows/system32/' not in file_path and '/windows/syswow64/' not in file_path,
        
        # Double extensions
        '.exe.exe' in filename or '.scr.exe' in filename or '.pdf.exe' in filename,
        
        # Suspicious extensions masquerading as documents
        filename.endswith(('.pdf.exe', '.doc.exe', '.jpg.exe', '.txt.exe')),
    ]
    
    for i, pattern in enumerate(suspicious_patterns):
        if pattern:
            pattern_descriptions = [
                "Filename has suspicious random character pattern",
                "System process name in non-system location", 
                "Double file extension detected",
                "Document extension with executable"
            ]
            return True, pattern_descriptions[i]
    
    # Check if running from removable media (basic check)
    if file_path.startswith(('a:/', 'b:/', 'e:/', 'f:/', 'g:/', 'h:/', 'i:/', 'j:/', 'k:/')):
        return True, "Running from potential removable media"
    
    return False, "Location appears normal"

def check_virustotal_ip(ip_address, api_key):
    """Check IP address against VirusTotal API."""
    if not ip_address or not api_key or is_private_ip(ip_address):
        return None
    
    # Check cache first
    if ip_address in _vt_ip_cache:
        return _vt_ip_cache[ip_address]
    
    url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
    params = {
        'apikey': api_key,
        'ip': ip_address
    }
    
    try:
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('response_code') == 1:
                result = {
                    'detected_urls': data.get('detected_urls', []),
                    'detected_communicating_samples': data.get('detected_communicating_samples', []),
                    'detected_downloaded_samples': data.get('detected_downloaded_samples', []),
                    'undetected_urls': data.get('undetected_urls', []),
                    'country': data.get('country'),
                    'as_owner': data.get('as_owner'),
                    'asn': data.get('asn')
                }
                # Cache the result
                _vt_ip_cache[ip_address] = result
                return result
        # Cache negative results too
        _vt_ip_cache[ip_address] = None
        return None
    except (requests.RequestException, ValueError):
        # Don't cache errors
        return None

def check_internet():
    try:
        psutil.net_if_addrs()
        return True
    except:
        return False
    
def get_listening_processes(vt_api_key=None, check_vt=False):
    """
    Retrieves a list of processes and their associated listening network connections.
    """
    listening_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            connections = proc.net_connections(kind='inet')  # 'inet' for IPv4 and IPv6
            for conn in connections:
                if conn.status == psutil.CONN_LISTEN:
                    process_data = {
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'exe': proc.info['exe'],
                        'local_address': conn.laddr.ip,
                        'local_port': conn.laddr.port,
                        'family': conn.family,
                        'type': conn.type,
                    }
                    
                    # Check for suspicious executable location
                    if proc.info['exe']:
                        is_suspicious, reason = is_suspicious_location(proc.info['exe'])
                        process_data['suspicious_location'] = is_suspicious
                        process_data['location_reason'] = reason
                    
                    if check_vt and vt_api_key:
                        if proc.info['exe']:
                            file_hash = calculate_file_hash(proc.info['exe'])
                            if file_hash:
                                # Check if this hash was already cached to avoid unnecessary API calls
                                was_cached = file_hash in _vt_hash_cache
                                vt_result = check_virustotal(file_hash, vt_api_key)
                                process_data['file_hash'] = file_hash
                                process_data['virustotal'] = vt_result
                                # Only rate limit if we made an actual API call
                                if vt_result and not was_cached:
                                    time.sleep(0.25)  # Rate limiting
                        
                        # Check if this IP was already cached to avoid unnecessary API calls
                        was_ip_cached = conn.laddr.ip in _vt_ip_cache
                        ip_vt_result = check_virustotal_ip(conn.laddr.ip, vt_api_key)
                        if ip_vt_result:
                            process_data['ip_virustotal'] = ip_vt_result
                            # Only rate limit if we made an actual API call
                            if not was_ip_cached:
                                time.sleep(0.25)  # Rate limiting
                    
                    listening_processes.append(process_data)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Handle cases where a process might have terminated or access is denied
            pass
    return listening_processes

def get_established_connections_with_processes(vt_api_key=None, check_vt=False):
        connections_info = []
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                # Get network connections for the current process
                process_connections = proc.net_connections()
                for conn in process_connections:
                    if conn.status == psutil.CONN_ESTABLISHED:
                        connection_data = {
                            'pid': proc.info['pid'],
                            'process_name': proc.info['name'],
                            'exe': proc.info['exe'],
                            'local_address': conn.laddr,
                            'remote_address': conn.raddr,
                            'status': conn.status
                        }
                        
                        # Check for suspicious executable location
                        if proc.info['exe']:
                            is_suspicious, reason = is_suspicious_location(proc.info['exe'])
                            connection_data['suspicious_location'] = is_suspicious
                            connection_data['location_reason'] = reason
                        
                        if check_vt and vt_api_key:
                            if proc.info['exe']:
                                file_hash = calculate_file_hash(proc.info['exe'])
                                if file_hash:
                                    # Check if this hash was already cached to avoid unnecessary API calls
                                    was_cached = file_hash in _vt_hash_cache
                                    vt_result = check_virustotal(file_hash, vt_api_key)
                                    connection_data['file_hash'] = file_hash
                                    connection_data['virustotal'] = vt_result
                                    # Only rate limit if we made an actual API call
                                    if vt_result and not was_cached:
                                        time.sleep(0.25)  # Rate limiting
                            
                            if conn.raddr:
                                # Check if this IP was already cached to avoid unnecessary API calls
                                was_ip_cached = conn.raddr.ip in _vt_ip_cache
                                ip_vt_result = check_virustotal_ip(conn.raddr.ip, vt_api_key)
                                if ip_vt_result:
                                    connection_data['ip_virustotal'] = ip_vt_result
                                    # Only rate limit if we made an actual API call
                                    if not was_ip_cached:
                                        time.sleep(0.25)  # Rate limiting
                        
                        connections_info.append(connection_data)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Handle cases where a process might disappear or be inaccessible
                pass
        return connections_info

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Network process checker with optional VirusTotal integration')
    parser.add_argument('--virustotal', '-vt', action='store_true', 
                       help='Enable VirusTotal hash checking')
    parser.add_argument('--api-key', '-k', type=str,
                       help='VirusTotal API key (or set VT_API_KEY environment variable)')
    parser.add_argument('--listening', '-l', action='store_true',
                       help='Show listening processes')
    parser.add_argument('--established', '-e', action='store_true', default=True,
                       help='Show established connections (default)')
    
    args = parser.parse_args()
    
    # Get API key from argument or environment variable
    vt_api_key = args.api_key or os.environ.get('VT_API_KEY')
    
    if args.virustotal and not vt_api_key:
        print("Error: VirusTotal API key required. Use --api-key or set VT_API_KEY environment variable.")
        exit(1)
    
    if args.listening:
        processes = get_listening_processes(vt_api_key, args.virustotal)
        if processes:
            print("Listening Processes:")
            for p in processes:
                print(f"  PID: {p['pid']}, Name: {p['name']}")
                print(f"    Executable: {p['exe']}")
                print(f"    Listening on: {p['local_address']}:{p['local_port']}")
                print(f"    (Family: {p['family']}, Type: {p['type']})")
                
                # Display suspicious location warning
                if p.get('suspicious_location'):
                    print(f"    *** SUSPICIOUS LOCATION: {p['location_reason']}")
                elif 'location_reason' in p:
                    print(f"    Location: {p['location_reason']}")
                
                if 'virustotal' in p and p['virustotal']:
                    vt = p['virustotal']
                    print(f"    VirusTotal: {vt['positives']}/{vt['total']} detections")
                    if vt['positives'] > 0:
                        print(f"    ⚠️  ALERT: {vt['positives']} engines detected this file as malicious!")
                        print(f"    Report: {vt['permalink']}")
                elif 'file_hash' in p:
                    print(f"    File Hash: {p['file_hash']}")
                    print(f"    VirusTotal: No results found")
                
                if 'ip_virustotal' in p and p['ip_virustotal']:
                    ip_vt = p['ip_virustotal']
                    detected_urls = len(ip_vt.get('detected_urls', []))
                    detected_samples = len(ip_vt.get('detected_communicating_samples', []))
                    print(f"    IP Reputation: {detected_urls} malicious URLs, {detected_samples} malicious samples")
                    if ip_vt.get('country'):
                        print(f"    IP Location: {ip_vt['country']}")
                    if ip_vt.get('as_owner'):
                        print(f"    AS Owner: {ip_vt['as_owner']}")
                    if detected_urls > 0 or detected_samples > 0:
                        print(f"    ⚠️  ALERT: IP has suspicious activity!")
                elif not is_private_ip(p['local_address']):
                    print(f"    IP Reputation: No VirusTotal data available")
                
                print("-" * 50)
        else:
            print("No listening processes found.")
    
    if args.established or not args.listening:
        established_conns = get_established_connections_with_processes(vt_api_key, args.virustotal)
        if established_conns:
            print("Established Network Connections and Associated Processes:")
            for conn_data in established_conns:
                print(f"  PID: {conn_data['pid']}, Process: {conn_data['process_name']}")
                print(f"    Executable: {conn_data['exe']}")
                print(f"    Local: {conn_data['local_address']}")
                print(f"    Remote: {conn_data['remote_address']}")
                print(f"    Status: {conn_data['status']}")
                
                # Display suspicious location warning
                if conn_data.get('suspicious_location'):
                    print(f"    *** SUSPICIOUS LOCATION: {conn_data['location_reason']}")
                elif 'location_reason' in conn_data:
                    print(f"    Location: {conn_data['location_reason']}")
                
                if 'virustotal' in conn_data and conn_data['virustotal']:
                    vt = conn_data['virustotal']
                    print(f"    VirusTotal: {vt['positives']}/{vt['total']} detections")
                    if vt['positives'] > 0:
                        print(f"    ⚠️  ALERT: {vt['positives']} engines detected this file as malicious!")
                        print(f"    Report: {vt['permalink']}")
                elif 'file_hash' in conn_data:
                    print(f"    File Hash: {conn_data['file_hash']}")
                    print(f"    VirusTotal: No results found")
                
                if 'ip_virustotal' in conn_data and conn_data['ip_virustotal']:
                    ip_vt = conn_data['ip_virustotal']
                    detected_urls = len(ip_vt.get('detected_urls', []))
                    detected_samples = len(ip_vt.get('detected_communicating_samples', []))
                    print(f"    IP Reputation: {detected_urls} malicious URLs, {detected_samples} malicious samples")
                    if ip_vt.get('country'):
                        print(f"    IP Location: {ip_vt['country']}")
                    if ip_vt.get('as_owner'):
                        print(f"    AS Owner: {ip_vt['as_owner']}")
                    if detected_urls > 0 or detected_samples > 0:
                        print(f"    ⚠️  ALERT: Remote IP has suspicious activity!")
                elif conn_data['remote_address'] and not is_private_ip(conn_data['remote_address'].ip):
                    print(f"    IP Reputation: No VirusTotal data available")
                
                print("-" * 50)
        else:
            print("No established connections found.")