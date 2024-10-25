import os
import sys
import requests
import dns.resolver  # You need to install dnspython with `pip install dnspython`
from colorama import Fore, init
from rich.console import Console
from rich.table import Table


init(autoreset=True)
console = Console()

def banner():
    console.print(Fore.GREEN + """
    =============================================
          Argus - Subdomain Enumeration (crt.sh)
    =============================================
    """)

def fetch_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            subdomains = set()
            for entry in response.json():
                subdomains.add(entry['name_value'])
            return list(subdomains)
        else:
            console.print(Fore.RED + f"[!] Error fetching data from crt.sh: {response.status_code}")
            return []
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error fetching subdomains: {e}")
        return []

def enum_subdomains(domain):
    subdomains = set()
    try:
        # Use dnspython to perform DNS queries
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            subdomains.add(domain)
            console.print(Fore.WHITE + f"[+] Found subdomain: {domain} -> {rdata}")
    except dns.resolver.NoAnswer:
        console.print(Fore.YELLOW + f"[!] No DNS records found for: {domain}")
    except dns.resolver.NXDOMAIN:
        console.print(Fore.RED + f"[!] Domain does not exist: {domain}")
    except Exception as e:
        console.print(Fore.RED + f"[!] DNS query error for {domain}: {e}")

    return list(subdomains)

def display_subdomains(subdomains):
    if not subdomains:
        console.print(Fore.YELLOW + "[!] No subdomains found.")
    else:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Subdomains", style="cyan", justify="left")
        for sub in subdomains:
            table.add_row(sub)
        console.print(table)

def main(domain):
    banner()
    console.print(Fore.WHITE + f"[*] Fetching subdomains for: {domain}")
    
    # Fetch subdomains from crt.sh
    subdomains = fetch_subdomains(domain)
    
    # Enumerate additional subdomains using DNS queries
    dns_subdomains = enum_subdomains(domain)
    
    # Combine results and remove duplicates
    all_subdomains = list(set(subdomains + dns_subdomains))
    
    display_subdomains(all_subdomains)
    console.print(Fore.WHITE + "[*] Subdomain enumeration completed.")

if len(sys.argv) > 1:
    target_domain = sys.argv[1]
    try:
        main(target_domain)
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
else:
    console.print(Fore.RED + "[!] No domain provided. Please pass a domain.")
    sys.exit(1)
