#!/usr/bin/env python3
"""
Honeypot Log Analyzer
Analyzes honeypot logs to extract threat intelligence and attack patterns.
"""

import json
import argparse
from collections import defaultdict, Counter
import re
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from typing import Dict, List, Tuple
import ipaddress

class HoneypotAnalyzer:
    """Analyzes honeypot logs for patterns and insights"""
    
    def __init__(self, log_file='honeypot_data.json'):
        self.log_file = log_file
        self.data = []
        self.load_data()
    
    def load_data(self):
        """Load JSON log data"""
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        self.data.append(entry)
                    except json.JSONDecodeError:
                        continue
            print(f"Loaded {len(self.data)} log entries")
        except FileNotFoundError:
            print(f"Log file {self.log_file} not found")
            self.data = []
    
    def get_ip_stats(self) -> Dict:
        """Get statistics about attacking IPs"""
        ip_counter = Counter()
        ip_services = defaultdict(set)
        ip_first_seen = {}
        ip_last_seen = {}
        
        for entry in self.data:
            ip = entry['client_ip']
            service = entry['service']
            timestamp = entry['timestamp']
            
            ip_counter[ip] += 1
            ip_services[ip].add(service)
            
            if ip not in ip_first_seen:
                ip_first_seen[ip] = timestamp
            ip_last_seen[ip] = timestamp
        
        return {
            'total_unique_ips': len(ip_counter),
            'top_attackers': ip_counter.most_common(10),
            'multi_service_attackers': {
                ip: list(services) for ip, services in ip_services.items() 
                if len(services) > 1
            },
            'ip_timeline': {ip: (ip_first_seen[ip], ip_last_seen[ip]) 
                           for ip in ip_counter.keys()}
        }
    
    def get_service_stats(self) -> Dict:
        """Get statistics about targeted services"""
        service_counter = Counter()
        service_timeline = defaultdict(list)
        
        for entry in self.data:
            service = entry['service']
            timestamp = entry['timestamp']
            
            service_counter[service] += 1
            service_timeline[service].append(timestamp)
        
        return {
            'service_popularity': dict(service_counter),
            'total_attempts': sum(service_counter.values()),
            'service_timeline': dict(service_timeline)
        }
    
    def analyze_credentials(self) -> Dict:
        """Analyze login attempts and credential patterns"""
        credentials = []
        common_usernames = Counter()
        common_passwords = Counter()
        
        for entry in self.data:
            data = entry.get('data', '')
            if not data:
                continue
            
            # Extract SSH/Telnet credentials
            if entry['service'] in ['SSH', 'Telnet']:
                if 'Username:' in data and 'Password:' in data:
                    parts = data.split(', ')
                    if len(parts) >= 2:
                        username = parts[0].replace('Username: ', '').strip()
                        password = parts[1].replace('Password: ', '').strip()
                        credentials.append((username, password))
                        common_usernames[username] += 1
                        common_passwords[password] += 1
            
            # Extract FTP credentials
            elif entry['service'] == 'FTP' and 'login attempt:' in data.lower():
                match = re.search(r'login attempt: (.+):(.+)', data)
                if match:
                    username, password = match.groups()
                    credentials.append((username, password))
                    common_usernames[username] += 1
                    common_passwords[password] += 1
        
        return {
            'total_credential_attempts': len(credentials),
            'unique_credentials': len(set(credentials)),
            'top_usernames': common_usernames.most_common(10),
            'top_passwords': common_passwords.most_common(10),
            'credential_pairs': Counter(credentials).most_common(10)
        }
    
    def analyze_http_attacks(self) -> Dict:
        """Analyze HTTP-specific attack patterns"""
        http_entries = [e for e in self.data if e['service'] == 'HTTP']
        
        attack_patterns = {
            'sqli': r'(union.*select|or.*1.*=.*1|\'.*or.*\')',
            'xss': r'<script|javascript:|alert\(|onerror=',
            'lfi': r'\.\.\/|\.\.\\|\/etc\/passwd|\/windows\/system32',
            'rce': r'(system\(|exec\(|eval\(|cmd=|shell_exec)',
            'scan': r'(nmap|nikto|sqlmap|dirb|gobuster)'
        }
        
        pattern_counts = Counter()
        suspicious_paths = Counter()
        user_agents = Counter()
        
        for entry in http_entries:
            data = entry.get('data', '')
            
            # Extract paths
            path_match = re.search(r'GET\s+([^\s]+)', data)
            if path_match:
                path = path_match.group(1)
                suspicious_paths[path] += 1
            
            # Extract User-Agent
            ua_match = re.search(r'User-Agent:\s*([^\r\n]+)', data)
            if ua_match:
                user_agent = ua_match.group(1)
                user_agents[user_agent] += 1
            
            # Check for attack patterns
            for attack_type, pattern in attack_patterns.items():
                if re.search(pattern, data, re.IGNORECASE):
                    pattern_counts[attack_type] += 1
        
        return {
            'total_http_requests': len(http_entries),
            'attack_patterns': dict(pattern_counts),
            'suspicious_paths': suspicious_paths.most_common(20),
            'user_agents': user_agents.most_common(10)
        }
    
    def get_geographic_insights(self) -> Dict:
        """Analyze geographic distribution of attacks (basic)"""
        # Note: This would require IP geolocation database in real implementation
        ip_ranges = defaultdict(int)
        
        for entry in self.data:
            ip = entry['client_ip']
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private:
                    ip_ranges['Private'] += 1
                elif ip_obj.is_loopback:
                    ip_ranges['Loopback'] += 1
                else:
                    # Simple classification by first octet
                    first_octet = int(ip.split('.')[0])
                    if first_octet < 64:
                        ip_ranges['Low Range (0-63)'] += 1
                    elif first_octet < 128:
                        ip_ranges['Mid Range (64-127)'] += 1
                    elif first_octet < 192:
                        ip_ranges['High Range (128-191)'] += 1
                    else:
                        ip_ranges['Top Range (192-255)'] += 1
            except ValueError:
                ip_ranges['Invalid IP'] += 1
        
        return dict(ip_ranges)
    
    def get_temporal_patterns(self) -> Dict:
        """Analyze attack timing patterns"""
        hourly_counts = defaultdict(int)
        daily_counts = defaultdict(int)
        
        for entry in self.data:
            try:
                dt = datetime.fromisoformat(entry['timestamp'])
                hourly_counts[dt.hour] += 1
                daily_counts[dt.strftime('%Y-%m-%d')] += 1
            except ValueError:
                continue
        
        return {
            'hourly_distribution': dict(hourly_counts),
            'daily_distribution': dict(daily_counts)
        }
    
    def generate_report(self) -> str:
        """Generate comprehensive analysis report"""
        if not self.data:
            return "No data available for analysis"
        
        ip_stats = self.get_ip_stats()
        service_stats = self.get_service_stats()
        cred_stats = self.analyze_credentials()
        http_stats = self.analyze_http_attacks()
        geo_stats = self.get_geographic_insights()
        temporal_stats = self.get_temporal_patterns()
        
        report = f"""
# Honeypot Analysis Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- Total log entries: {len(self.data)}
- Unique attacking IPs: {ip_stats['total_unique_ips']}
- Total attack attempts: {service_stats['total_attempts']}
- Services targeted: {len(service_stats['service_popularity'])}

## Top Attacking IPs
"""
        for ip, count in ip_stats['top_attackers']:
            report += f"- {ip}: {count} attempts\n"
        
        report += f"""
## Service Targeting
"""
        for service, count in service_stats['service_popularity'].items():
            percentage = (count / service_stats['total_attempts']) * 100
            report += f"- {service}: {count} attempts ({percentage:.1f}%)\n"
        
        report += f"""
## Credential Analysis
- Total credential attempts: {cred_stats['total_credential_attempts']}
- Unique credential pairs: {cred_stats['unique_credentials']}

### Most Common Usernames:
"""
        for username, count in cred_stats['top_usernames'][:5]:
            report += f"- {username}: {count} attempts\n"
        
        report += f"""
### Most Common Passwords:
"""
        for password, count in cred_stats['top_passwords'][:5]:
            report += f"- {password}: {count} attempts\n"
        
        if http_stats['total_http_requests'] > 0:
            report += f"""
## HTTP Attack Analysis
- Total HTTP requests: {http_stats['total_http_requests']}
- Attack patterns detected: {sum(http_stats['attack_patterns'].values())}

### Attack Types:
"""
            for attack_type, count in http_stats['attack_patterns'].items():
                report += f"- {attack_type.upper()}: {count} attempts\n"
        
        report += f"""
## Multi-Service Attackers
"""
        for ip, services in ip_stats['multi_service_attackers'].items():
            report += f"- {ip}: {', '.join(services)}\n"
        
        report += f"""
## Geographic Distribution
"""
        for region, count in geo_stats.items():
            report += f"- {region}: {count} attacks\n"
        
        report += f"""
## Recommendations
1. Monitor top attacking IPs: {', '.join([ip for ip, _ in ip_stats['top_attackers'][:3]])}
2. Most targeted service: {max(service_stats['service_popularity'], key=service_stats['service_popularity'].get)}
3. Consider blocking repeated credential attempts
4. Implement rate limiting for HTTP services
5. Monitor multi-service attackers for advanced persistent threats

## Next Steps
- Implement IP reputation checking
- Set up automated alerting for suspicious patterns
- Integrate with threat intelligence feeds
- Consider deploying additional honeypot services
"""
        
        return report
    
    def create_visualizations(self):
        """Create visualization charts"""
        if not self.data:
            print("No data available for visualization")
            return
        
        service_stats = self.get_service_stats()
        ip_stats = self.get_ip_stats()
        temporal_stats = self.get_temporal_patterns()
        
        # Create subplots
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        
        # Service popularity pie chart
        services = list(service_stats['service_popularity'].keys())
        counts = list(service_stats['service_popularity'].values())
        ax1.pie(counts, labels=services, autopct='%1.1f%%', startangle=90)
        ax1.set_title('Service Targeting Distribution')
        
        # Top attacking IPs bar chart
        top_ips = ip_stats['top_attackers'][:10]
        ips = [ip for ip, _ in top_ips]
        ip_counts = [count for _, count in top_ips]
        ax2.bar(range(len(ips)), ip_counts)
        ax2.set_title('Top 10 Attacking IPs')
        ax2.set_xlabel('IP Address')
        ax2.set_ylabel('Attack Count')
        ax2.set_xticks(range(len(ips)))
        ax2.set_xticklabels(ips, rotation=45, ha='right')
        
        # Hourly attack pattern
        hourly_data = temporal_stats['hourly_distribution']
        hours = list(range(24))
        hourly_counts = [hourly_data.get(hour, 0) for hour in hours]
        ax3.plot(hours, hourly_counts, marker='o')
        ax3.set_title('Attacks by Hour of Day')
        ax3.set_xlabel('Hour (24h format)')
        ax3.set_ylabel('Attack Count')
        ax3.grid(True)
        
        # Daily attack timeline
        daily_data = temporal_stats['daily_distribution']
        if daily_data:
            dates = sorted(daily_data.keys())
            daily_counts = [daily_data[date] for date in dates]
            ax4.plot(dates, daily_counts, marker='o')
            ax4.set_title('Daily Attack Timeline')
            ax4.set_xlabel('Date')
            ax4.set_ylabel('Attack Count')
            ax4.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig('honeypot_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()
        print("Visualization saved as 'honeypot_analysis.png'")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Honeypot Log Analyzer')
    parser.add_argument('--log-file', default='honeypot_data.json', 
                       help='JSON log file to analyze')
    parser.add_argument('--report', action='store_true', 
                       help='Generate text report')
    parser.add_argument('--visualize', action='store_true', 
                       help='Create visualization charts')
    parser.add_argument('--output', default='honeypot_report.txt', 
                       help='Output file for report')
    
    args = parser.parse_args()
    
    analyzer = HoneypotAnalyzer(args.log_file)
    
    if args.report:
        report = analyzer.generate_report()
        
        # Save to file
        with open(args.output, 'w') as f:
            f.write(report)
        
        # Print to console
        print(report)
        print(f"\nReport saved to {args.output}")
    
    if args.visualize:
        try:
            analyzer.create_visualizations()
        except ImportError:
            print("Matplotlib not available. Install with: pip install matplotlib")
    
    if not args.report and not args.visualize:
        # Default: show basic stats
        ip_stats = analyzer.get_ip_stats()
        service_stats = analyzer.get_service_stats()
        
        print(f"Total entries: {len(analyzer.data)}")
        print(f"Unique IPs: {ip_stats['total_unique_ips']}")
        print(f"Total attempts: {service_stats['total_attempts']}")
        print("\nTop 5 attacking IPs:")
        for ip, count in ip_stats['top_attackers'][:5]:
            print(f"  {ip}: {count}")

if __name__ == "__main__":
    main()