import socket
import requests
import subprocess
import re


common_ports = [21, 22, 23, 25, 80, 110, 143, 443, 3389]


def scan_open_ports(target):
    open_ports = []
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports


def check_outdated_software(url):
    outdated = []
    try:
        response = requests.get(url)
        server_header = response.headers.get('Server', '')
        if server_header:
            # This is a very basic check for outdated Apache versions
            if 'Apache' in server_header:
                match = re.search(r'Apache/(\d+\.\d+\.\d+)', server_header)
                if match:
                    version = match.group(1)
                    if version < '2.4.49':  # Example threshold version
                        outdated.append(f"Apache version {version} is outdated")
    except requests.RequestException as e:
        outdated.append(f"Error accessing {url}: {e}")
    return outdated


def check_misconfigurations(url):
    misconfigurations = []
    try:
        response = requests.get(url)
        if 'Index of /' in response.text:
            misconfigurations.append("Directory listing is enabled")
    except requests.RequestException as e:
        misconfigurations.append(f"Error accessing {url}: {e}")
    return misconfigurations


def vulnerability_scan(target):
    print(f"Scanning {target} for vulnerabilities...")

    
    open_ports = scan_open_ports(target)
    if open_ports:
        print(f"Open Ports: {open_ports}")
    else:
        print("No common open ports found")

    
    url = f"http://{target}"
    outdated_software = check_outdated_software(url)
    if outdated_software:
        print("Outdated Software:")
        for item in outdated_software:
            print(f" - {item}")
    else:
        print("No outdated software found")

    
    misconfigurations = check_misconfigurations(url)
    if misconfigurations:
        print("Misconfigurations:")
        for item in misconfigurations:
            print(f" - {item}")
    else:
        print("No misconfigurations found")

if __name__ == "__main__":
    target = input("Enter the IP address or website URL to scan: ")
    if target.startswith('http://') or target.startswith('https://'):
        target = target.split('//')[1]
    vulnerability_scan(target)
