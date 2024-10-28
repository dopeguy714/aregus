import os
import sys
import nmap
from rich.console import Console
from rich.table import Table
from colorama import Fore, init

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

init(autoreset=True)
console = Console()

def banner():
    console.print(Fore.GREEN + """
    =============================================
              Argus - Open Ports Scanning
    =============================================
    """)

def scan_ports(ip):
    nm = nmap.PortScanner()
    try:
        # Scanning ports in the range of 1-1024
        nm.scan(ip, '1-1024')
        open_ports_info = []
        
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    port_state = nm[host][proto][port]['state']
                    service_name = nm[host][proto][port]['name']
                    banner_info = nm[host][proto][port].get('product', '')  # Product or banner information if available
                    
                    open_ports_info.append({
                        'port': port,
                        'state': port_state,
                        'service': service_name,
                        'banner': banner_info or "N/A"
                    })
        return open_ports_info
    except Exception as e:
        console.print(Fore.RED + f"[!] Error scanning ports: {e}")
        return None

def display_ports(open_ports_info):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Port", style="cyan", justify="left")
    table.add_column("State", style="green", justify="left")
    table.add_column("Service", style="yellow", justify="left")
    table.add_column("Banner", style="white", justify="left")

    for info in open_ports_info:
        table.add_row(str(info['port']), info['state'], info['service'], info['banner'])

    console.print(table)

def main(target):
    banner()
    console.print(Fore.WHITE + f"[*] Scanning open ports for: {target}")
    open_ports_info = scan_ports(target)
    if open_ports_info:
        display_ports(open_ports_info)
    else:
        console.print(Fore.RED + "[!] No open ports found.")
    console.print(Fore.WHITE + "[*] Open ports scanning completed.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        try:
            main(target)
        except KeyboardInterrupt:
            console.print(Fore.RED + "\n[!] Process interrupted by user.")
            sys.exit(1)
    else:
        console.print(Fore.RED + "[!] No target provided. Please pass an IP address.")
        sys.exit(1)
