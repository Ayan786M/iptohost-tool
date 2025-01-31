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
   Server Version Scanner v{VERSION} - Scan Port 443
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

def get_server_version(sock):
    try:
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors='ignore').strip()
        # Extract server version from the banner
        for line in banner.splitlines():
            if line.startswith("Server:"):
                return line.split("Server: ")[1]
    except Exception:
        return None
    finally:
        sock.close()

def scan_ip(ip, port, timeout, results):
    """Scan an IP for server version on port 443."""
    global progress_counter

    sock = create_socket(ip, port, timeout)
    if sock:
        server_version = get_server_version(sock)
        if server_version:  # Only store results if server version is found
            with progress_lock:
                results[ip] = server_version
    with progress_lock:
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

    parser = argparse.ArgumentParser(description="Server Version Scanner for port 443.")
    parser.add_argument(
        "targets", nargs='*', help="IP addresses, domain names, or CIDR networks to scan."
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
    port = 443  # Only scan port 443
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
            executor.submit(scan_ip, ip, port, timeout, results)

    executor.shutdown(wait=True)

    # Display results
    if results:
        print(f"\n{GREEN}Servers Found:{ENDC}")
        for ip, version in results.items():
            print(f"{GREEN}[+] IP: {ip}{ENDC} - {version}")
    else:
        print(f"{RED}[!] No servers found{ENDC}")

    # Save results to a file if specified
    if args.output:
        with open(args.output, 'w') as file:
            for ip, version in results.items():
                file.write(f"IP: {ip} - {version}\n")
        print(f"{GREEN}[+] Results saved to {args.output}{ENDC}")

if __name__ == "__main__":
    main()
