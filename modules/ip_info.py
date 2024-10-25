import os
import sys
import requests
from rich.console import Console
from rich.table import Table

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import DEFAULT_TIMEOUT  

console = Console()

def banner():
    console.print("""
[green]=============================================
          Argus - Enhanced IP Information
=============================================[/green]
""")

def get_ip_info(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=DEFAULT_TIMEOUT)
        data = response.json()
        if response.status_code == 200 and data.get('status') == 'success':
            # Additional data fields
            lat = data.get('lat')
            lon = data.get('lon')
            if lat and lon:
                data['map_link'] = f"https://www.google.com/maps?q={lat},{lon}"
            data['city'] = data.get('city', 'N/A')
            data['region'] = data.get('regionName', 'N/A')
            data['country'] = data.get('country', 'N/A')
            data['timezone'] = data.get('timezone', 'N/A')
            data['isp'] = data.get('isp', 'N/A')
            data['org'] = data.get('org', 'N/A')
            return data
        else:
            console.print("[red][!] Failed to retrieve IP information.[/red]")
            return None
    except requests.RequestException as e:
        console.print(f"[red][!] Error retrieving IP information: {e}[/red]")
        return None

def display_ip_info(ip_info):
    table = Table(show_header=True, header_style="bold white")
    table.add_column("Key", style="white", justify="left", min_width=15)
    table.add_column("Value", style="white", justify="left", min_width=50)

    for key, value in ip_info.items():
        table.add_row(str(key), str(value))

    console.print(table)
    
    if 'map_link' in ip_info:
        console.print(f"\n[yellow][+] View location on map: {ip_info['map_link']}[/yellow]")

def main(target):
    banner()
    console.print(f"[*] Fetching IP info for: {target}")

    ip = target  
    ip_info = get_ip_info(ip)

    if ip_info:
        display_ip_info(ip_info)
    else:
        console.print("[red][!] No IP information found.[/red]")

    console.print("[cyan][*] IP info retrieval completed.[/cyan]")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        main(target)
    else:
        console.print("[red][!] No target provided. Please pass a domain, URL, or IP address.[/red]")
        sys.exit(1)
