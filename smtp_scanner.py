#!/usr/bin/env python3

import nmap
import argparse
from datetime import datetime

def scan_smtp_ports(target):
    """
    Scan for open SMTP ports on the target host
    """
    open_ports = []
    smtp_ports = "25,587,465,2525"
    
    print(f"\n[*] Starting SMTP port scan on {target} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        # Initialize the port scanner
        nm = nmap.PortScanner()
        
        # Scan the target with timing template T4 (aggressive)
        nm.scan(hosts=target, ports=smtp_ports, arguments='-T4 -sV --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -v')
        
        # Check if host is up
        if not nm.all_hosts():
            print(f"[!] Host {target} seems to be down or not responding")
            return None
        
        # Process scan results
        for host in nm.all_hosts():
            print(f"\n[+] Scan results for {host}:")
            print(f"Host Status: {nm[host].state()}")
            
            for proto in nm[host].all_protocols():
                print(f"\nProtocol: {proto}")
                ports = nm[host][proto].keys()
                
                for port in sorted(ports):
                    port_info = nm[host][proto][port]
                    if port_info['state'] == 'open':
                        print(f"\nPort {port} is {port_info['state']}")
                        print(f"Service: {port_info['name']} {port_info['product']} {port_info['version']}")
                        print(f"Extra info: {port_info['extrainfo']}")
                        
                        # Store open ports
                        open_ports.append(port)
                        
                        # Check for Nmap script results
                        if 'script' in port_info:
                            print("\nNmap Script Results:")
                            for script, output in port_info['script'].items():
                                print(f"{script}:")
                                print(output)
                    else:
                        print(f"Port {port} is {port_info['state']}")
        
        return open_ports
    
    except nmap.PortScannerError as e:
        print(f"[!] Nmap scan error: {str(e)}")
        return None
    except Exception as e:
        print(f"[!] Unexpected error: {str(e)}")
        return None

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='SMTP Port Scanner and Enumerator')
    parser.add_argument('target', help='Target IP address or hostname')
    args = parser.parse_args()
    
    # Run the scan
    open_ports = scan_smtp_ports(args.target)
    
    if open_ports:
        print(f"\n[+] Scan completed. Open SMTP ports found: {', '.join(map(str, open_ports))}")
    else:
        print("\n[-] No open SMTP ports found or scan failed.")

if __name__ == "__main__":
    main()
