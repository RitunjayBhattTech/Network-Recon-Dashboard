import argparse
import subprocess
import re
import sys
from datetime import datetime

def print_banner():
    print("""
    ================================================
         Automated Network Auditor & Mapper
    ================================================
    """)

def validate_target(target):
    """Validates if the input is an IPv4, CIDR, or Domain."""
    ipv4_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    cidr_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$"
    domain_regex = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?!-)[A-Za-z0-9-]{1,63}(?<!-)$"
    
    if re.match(ipv4_regex, target) or re.match(cidr_regex, target) or re.match(domain_regex, target):
        return True
    return False

def run_discovery(target):
    """Runs a ping sweep to find live hosts."""
    print(f"[*] Phase 1: Running Host Discovery on {target}...")
    try:
        # -sn: Ping Scan, -oG -: Grepable output to stdout
        result = subprocess.run(['nmap', '-sn', '-oG', '-', target], capture_output=True, text=True, check=True)
        live_hosts = []
        for line in result.stdout.split('\n'):
            if "Status: Up" in line:
                ip = line.split(' ')[1]
                live_hosts.append(ip)
        return live_hosts
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running discovery scan: {e}")
        sys.exit(1)

def run_port_scan(hosts, mode):
    """Runs port and service scans on live hosts."""
    print(f"[*] Phase 2: Running {mode.upper()} scan on {len(hosts)} live host(s)...")
    scan_results = {}
    
    for ip in hosts:
        print(f"    -> Scanning {ip}...")
        try:
            if mode == 'quick':
                # Fast scan, top 100 ports
                cmd = ['nmap', '-F', ip]
            else:
                # Intense scan: All ports, Service Version, OS Detection
                cmd = ['nmap', '-p-', '-sV', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            scan_results[ip] = result.stdout
        except subprocess.CalledProcessError as e:
            print(f"[!] Error scanning {ip}: {e}")
            scan_results[ip] = "Error during scan."
            
    return scan_results

def generate_markdown_report(target, mode, hosts, scan_data, output_file):
    """Parses raw data and builds a clean Markdown report."""
    print(f"[*] Phase 3: Generating Markdown Report -> {output_file}")
    
    with open(output_file, 'w') as f:
        f.write("# Network Security Audit Report\n\n")
        f.write("## Executive Summary\n")
        f.write(f"- **Date/Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **Target Network/IP:** `{target}`\n")
        f.write(f"- **Scan Profile:** `{mode.capitalize()}`\n")
        f.write(f"- **Total Live Hosts:** {len(hosts)}\n\n")
        
        f.write("## Live Hosts Discovered\n")
        if not hosts:
            f.write("*No live hosts detected.*\n\n")
        for ip in hosts:
            f.write(f"- `{ip}`\n")
        f.write("\n---\n\n")
        
        f.write("## Detailed Host Analysis\n\n")
        for ip, raw_output in scan_data.items():
            f.write(f"### Target: {ip}\n")
            f.write("```text\n")
            # Extracting just the interesting port/OS lines to keep it clean
            for line in raw_output.split('\n'):
                if "/tcp" in line or "/udp" in line or "OS details" in line or "Service Info" in line:
                    f.write(line + "\n")
            f.write("```\n\n")

def main():
    parser = argparse.ArgumentParser(description="Automated Network Auditor via Nmap")
    parser.add_argument("-t", "--target", required=True, help="Target IP, Domain, or CIDR (e.g., 192.168.1.0/24)")
    parser.add_argument("-m", "--mode", choices=['quick', 'intense'], default='quick', help="Scan mode: 'quick' (Top 100 ports) or 'intense' (All ports + OS/Service detection)")
    parser.add_argument("-o", "--output", default="recon_report.md", help="Output Markdown file name")
    
    args = parser.parse_args()

    # 1. Validation
    if not validate_target(args.target):
        print("[!] Invalid target format. Please provide a valid IP, CIDR, or Domain.")
        sys.exit(1)
        
    print_banner()
    
    # 2. Discovery
    live_hosts = run_discovery(args.target)
    if not live_hosts:
        print("[-] No live hosts found. Exiting.")
        sys.exit(0)
        
    print(f"[+] Found {len(live_hosts)} live host(s): {', '.join(live_hosts)}")
    
    # 3. Scanning
    scan_data = run_port_scan(live_hosts, args.mode)
    
    # 4. Reporting
    generate_markdown_report(args.target, args.mode, live_hosts, scan_data, args.output)
    print(f"[+] Audit complete. Review your findings in {args.output}")

if __name__ == "__main__":
    main()
