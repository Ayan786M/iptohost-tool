#!/usr/bin/env python3
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import os

# Colors for output
GREEN = "\033[92m"
ENDC = "\033[0m"

def check_ftp_service(ip, timeout=1):
    """Check if FTP service is running on port 21 and retrieve the banner."""
    try:
        # Create a socket and connect to port 21
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, 21))
        if result == 0:
            # Attempt to retrieve the FTP banner
            banner = sock.recv(1024).decode(errors="ignore").strip()
            sock.close()
            return ip, banner
        sock.close()
    except Exception:
        pass
    return ip, None

def read_ips_from_file(file_path):
    """Read IPs from a file."""
    with open(file_path, "r") as file:
        return [line.strip() for line in file if line.strip()]

def main():
    parser = argparse.ArgumentParser(description="Fast and lightweight FTP service scanner.")
    parser.add_argument("ip_or_file", nargs="?", help="Single IP or file containing IPs.")
    parser.add_argument("-o", "--output", help="Output file to save results.")
    args = parser.parse_args()

    # Read IPs
    if args.ip_or_file and os.path.isfile(args.ip_or_file):
        ips = read_ips_from_file(args.ip_or_file)
    elif args.ip_or_file:
        ips = [args.ip_or_file]
    else:
        print("Error: Please provide an IP or a file containing IPs.")
        return

    # Scan IPs concurrently
    results = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_ip = {executor.submit(check_ftp_service, ip): ip for ip in ips}
        for future in as_completed(future_to_ip):
            ip, banner = future.result()
            if banner:  # Only display positive results
                results.append((ip, banner))
                print(f"{GREEN}[+] {ip} - {banner}{ENDC}")

    # Save results to file
    if args.output and results:
        with open(args.output, "w") as file:
            for ip, banner in results:
                file.write(f"{ip} - {banner}\n")
        print(f"\nResults saved to {args.output}")

if __name__ == "__main__":
    main()
