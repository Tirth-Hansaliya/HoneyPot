import json
import re
from datetime import datetime

def parse_log_to_json(log_file_path, json_file_path):
    """Convert honeypot log file to JSON format"""
    
    entries = []
    
    with open(log_file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            entry = {
                'line_number': line_num,
                'raw': line
            }
            
            # Parse [TIME] [SYSTEM] messages
            system_match = re.match(r'\[(\d{1,2}:\d{2}:\d{2} [AP]M)\] \[SYSTEM\] (.+)', line)
            if system_match:
                entry['timestamp'] = system_match.group(1)
                entry['service'] = 'SYSTEM'
                entry['message'] = system_match.group(2)
                entry['type'] = 'system'
                entries.append(entry)
                continue
            
            # Parse [SERVICE] [DATE TIME] messages (HTTP/FTP/SSH)
            service_match = re.match(r'\[(HTTP|FTP|SSH)\] \[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] (.+)', line)
            if service_match:
                entry['service'] = service_match.group(1)
                entry['timestamp'] = service_match.group(2)
                entry['message'] = service_match.group(3)
                entry['type'] = 'honeypot'
                
                # Parse connection details
                if 'Connection from' in entry['message']:
                    conn_match = re.search(r'Connection from ([\d.]+):(\d+)', entry['message'])
                    if conn_match:
                        entry['source_ip'] = conn_match.group(1)
                        entry['source_port'] = int(conn_match.group(2))
                        entry['event'] = 'connection'
                
                # Parse request details
                elif 'Request from' in entry['message']:
                    req_match = re.search(r'Request from ([\d.]+): (.+)', entry['message'])
                    if req_match:
                        entry['source_ip'] = req_match.group(1)
                        entry['request'] = req_match.group(2).strip()
                        entry['event'] = 'request'
                
                # Parse service events
                elif 'Started on port' in entry['message']:
                    port_match = re.search(r'Started on port (\d+)', entry['message'])
                    if port_match:
                        entry['port'] = int(port_match.group(1))
                        entry['event'] = 'started'
                
                elif 'Stopped' in entry['message']:
                    entry['event'] = 'stopped'
                
                entries.append(entry)
                continue
            
            # If no pattern matched, store as unknown
            entry['type'] = 'unknown'
            entries.append(entry)
    
    # Create JSON structure
    json_data = {
        'generated_at': datetime.now().isoformat(),
        'total_entries': len(entries),
        'entries': entries,
        'statistics': {
            'system_events': len([e for e in entries if e.get('service') == 'SYSTEM']),
            'http_events': len([e for e in entries if e.get('service') == 'HTTP']),
            'ftp_events': len([e for e in entries if e.get('service') == 'FTP']),
            'ssh_events': len([e for e in entries if e.get('service') == 'SSH']),
            'connections': len([e for e in entries if e.get('event') == 'connection']),
            'requests': len([e for e in entries if e.get('event') == 'request'])
        }
    }
    
    # Write to JSON file
    with open(json_file_path, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    
    print(f"✓ Converted {len(entries)} log entries to JSON")
    print(f"✓ Output saved to: {json_file_path}")
    print(f"\nStatistics:")
    print(f"  - System events: {json_data['statistics']['system_events']}")
    print(f"  - HTTP events: {json_data['statistics']['http_events']}")
    print(f"  - FTP events: {json_data['statistics']['ftp_events']}")
    print(f"  - SSH events: {json_data['statistics']['ssh_events']}")
    print(f"  - Total connections: {json_data['statistics']['connections']}")
    print(f"  - Total requests: {json_data['statistics']['requests']}")

if __name__ == '__main__':
    log_file = 'honeypot_activity.log'
    json_file = 'honeypot_activity.json'
    
    parse_log_to_json(log_file, json_file)
