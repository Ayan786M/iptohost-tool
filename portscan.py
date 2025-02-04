#!/usr/bin/env python3

import socket
import argparse
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor

VERSION = "2.1"

# Colors for output
BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
ORANGE = "\033[33m"
ENDC = "\033[0m"

# Global variables for progress tracking
progress_lock = threading.Lock()
progress_counter = 0
total_ips = 0

def display_banner():
    banner = rf"""
{BLUE}
    ________            _______   ________                    
   /  _____/_____ ___  __\   _  \  \_____  \                   
  /   \  ___\__  \\  \/  /  /_\  \  /   |   \                  
  \    \_\  \/ __ \\   /    |    \/    |    \                 
   \______  (____  /\_/ \____|__  /\_______  /                 
          \/     \/             \/         \/                  
{ENDC}
   Port Scanner v{VERSION} - Scan Critical Ports
"""
    print(banner)

def create_socket(ip, port, timeout):
    try:
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        return sock
    except Exception:
        return None

def get_service_banner(sock):
    try:
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors='ignore').strip()
        return banner
    except Exception:
        return "No banner retrieved"
    finally:
        sock.close()

def scan_ip(ip, ports, timeout, results):
    """Scan an IP for open ports and gather results."""
    global progress_counter

    ip_results = []
    for port in ports:
        sock = create_socket(ip, port, timeout)
        if sock:
            banner = get_service_banner(sock)
            ip_results.append((port, banner))
    with progress_lock:
        results[ip] = ip_results
        progress_counter += 1
        print(f"\r{GREEN}Progress: {progress_counter}/{total_ips} IPs checked{ENDC}", end="")

def process_ip_list(ip_list_file):
    """Process a file containing a list of IPs or CIDR ranges."""
    ips = []
    try:
        with open(ip_list_file, 'r') as file:
            for line in file:
                target = line.strip()
                if '/' in target:
                    try:
                        network = ipaddress.ip_network(target, strict=False)
                        ips.extend([str(ip) for ip in network.hosts()])
                    except ValueError:
                        print(f"{RED}[-] Invalid CIDR notation: {target}{ENDC}")
                else:
                    ips.append(target)
    except IOError:
        print(f"{RED}[-] Could not read file: {ip_list_file}{ENDC}")
    return ips

def main():
    global total_ips
    display_banner()

    parser = argparse.ArgumentParser(description="Port Scanner for important services.")
    parser.add_argument(
        "targets", nargs='*', help="IP addresses, domain names, or CIDR networks to scan."
    )
    parser.add_argument(
        "-p", "--ports", type=str, default="21,22,23,25,53,80,110,139,443,3306",
        help="Comma-separated list of port numbers to scan (default: 21,22,23,25,53,80,110,139,443,3306) or use '-p-' to scan all ports."
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=1.0, help="Connection timeout in seconds (default: 1 second)."
    )
    parser.add_argument(
        "-l", "--list", help="File containing a list of IP addresses or CIDR networks."
    )
    parser.add_argument(
        "-o", "--output", help="File to save scan results."
    )

    args = parser.parse_args()
    if args.ports == '-':
        ports = range(1, 65536)  # Scan all ports
    else:
        ports = [int(p) for p in args.ports.split(',')]
    timeout = args.timeout

    # Process targets
    ips = set()
    if args.list:
        ips.update(process_ip_list(args.list))
    for target in args.targets:
        if '/' in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                ips.update([str(ip) for ip in network.hosts()])
            except ValueError:
                print(f"{RED}[-] Invalid CIDR notation: {target}{ENDC}")
        else:
            ips.add(target.strip())

    if not ips:
        print(f"{RED}[-] No valid targets specified!{ENDC}")
        return

    ips = list(ips)
    total_ips = len(ips)

    results = {}
    with ThreadPoolExecutor(max_workers=100) as executor:
        for ip in ips:
            executor.submit(scan_ip, ip, ports, timeout, results)

    executor.shutdown(wait=True)

    # Display results
    if results:
        print(f"\n{GREEN}Scan Results:{ENDC}")
        for ip, ip_results in results.items():
            print(f"{BLUE}{'=' * 40}{ENDC}")
            print(f"{GREEN}[+] IP: {ip}{ENDC}")
            if ip_results:
                for port, banner in ip_results:
                    print(f"    {GREEN}Port {port}{ENDC}: {banner}")
            else:
                print(f"    {ORANGE}[!] No open ports found{ENDC}")
            print(f"{BLUE}{'=' * 40}{ENDC}")
    else:
        print(f"{RED}[!] No results found{ENDC}")

    # Save results to a file if specified
    if args.output:
        with open(args.output, 'w') as file:
            for ip, ip_results in results.items():
                file.write(f"IP: {ip}\n")
                if ip_results:
                    for port, banner in ip_results:
                        file.write(f"  Port {port}: {banner}\n")
                else:
                    file.write(f"  No open ports found\n")
                file.write("=" * 40 + "\n")
        print(f"{GREEN}[+] Results saved to {args.output}{ENDC}")

if __name__ == "__main__":
    main()
