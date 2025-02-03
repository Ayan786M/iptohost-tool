#!/usr/bin/env python3
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import os

# Colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
BLUE = "\033[94m"
ENDC = "\033[0m"
VERSION = "1.0"

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
   Ftp Scanner v{VERSION} - Scan Port 21
    """
    print(banner)

def check_ftp_service(ip, timeout=1):
    """
    Check if FTP service is running on port 21 and retrieve the banner.
    
    Args:
        ip (str): The IP address to check.
        timeout (int): Connection timeout in seconds.
    
    Returns:
        tuple: (ip, banner) if FTP service is running, otherwise (ip, None).
    """
    try:
        # Create a socket and connect to port 21
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, 21))
        
        if result == 0:  # Connection successful
            # Attempt to retrieve the FTP banner
            banner = sock.recv(1024).decode(errors="ignore").strip()
            sock.close()
            return ip, banner
        sock.close()
    except Exception as e:
        # Handle any exceptions (e.g., connection errors)
        pass
    return ip, None

def read_ips_from_file(file_path):
    """
    Read IP addresses from a file.
    
    Args:
        file_path (str): Path to the file containing IP addresses.
    
    Returns:
        list: List of IP addresses.
    """
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        sys.exit(1)
    
    with open(file_path, "r") as file:
        return [line.strip() for line in file if line.strip()]

def main():
    # Display banner
    display_banner()

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Fast and lightweight FTP service scanner.")
    parser.add_argument("ip_or_file", nargs="?", help="Single IP or file containing IPs.")
    parser.add_argument("-o", "--output", help="Output file to save results.")
    args = parser.parse_args()

    # Read IP addresses
    if args.ip_or_file and os.path.isfile(args.ip_or_file):
        ips = read_ips_from_file(args.ip_or_file)
    elif args.ip_or_file:
        ips = [args.ip_or_file]
    else:
        print("Error: Please provide an IP or a file containing IPs.")
        return

    # Scan IPs concurrently
    results = []
    total_ips = len(ips)
    completed = 0

    with ThreadPoolExecutor(max_workers=100) as executor:
        # Submit tasks for concurrent execution
        future_to_ip = {executor.submit(check_ftp_service, ip): ip for ip in ips}
        
        # Process results as they complete
        for future in as_completed(future_to_ip):
            completed += 1
            ip, banner = future.result()
            
            if banner:  # FTP service is running
                results.append((ip, banner))
                print(f"{GREEN}[+] {ip} - {banner}{ENDC}")
            
            # Display progress
            print(f"\rProgress: {completed}/{total_ips} IPs checked", end="", flush=True)

    # Save results to file if output file is specified
    if args.output and results:
        with open(args.output, "w") as file:
            for ip, banner in results:
                file.write(f"{ip} - {banner}\n")
        print(f"\nResults saved to {args.output}")

if __name__ == "__main__":
    main()
