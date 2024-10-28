# GNU GENERAL PUBLIC LICENSE 
# Version 3, 29 June 2007
# Copyright © 2007 Free Software Foundation, Inc. <http://fsf.org/>
import os
import sys
import requests
import dns.resolver  
from colorama import Fore, init
from rich.console import Console
from rich.table import Table

# Initialize colorama and rich console
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
        # Check for different HTTP status codes
        if response.status_code == 200:
            subdomains = set()
            for entry in response.json():
                subdomains.add(entry['name_value'])
            return list(subdomains)
        elif response.status_code == 301:
            console.print(Fore.YELLOW + f"[!] Redirected (301): The domain {domain} was redirected.")
            return []
        elif response.status_code == 401:
            console.print(Fore.RED + f"[!] Unauthorized (401): Access denied for {domain}.")
            return []
        elif response.status_code == 403:
            console.print(Fore.RED + f"[!] Forbidden (403): Access forbidden for {domain}.")
            return []
        elif response.status_code == 404:
            console.print(Fore.RED + f"[!] Not Found (404): No data for domain {domain}.")
            return []
        else:
            console.print(Fore.RED + f"[!] Unexpected error from crt.sh: HTTP {response.status_code}")
            return []
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error fetching subdomains: {e}")
        return []

def check_subdomain_status(subdomain):
    url = f"http://{subdomain}"
    try:
        response = requests.get(url, timeout=5)
        return response.status_code
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error checking status for {subdomain}: {e}")
        return None

def enum_subdomains(domain):
    subdomains = set()
    try:
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
        table.add_column("Subdomain", style="cyan", justify="left")
        table.add_column("Status Code", style="green", justify="center")
        for sub in subdomains:
            status_code = check_subdomain_status(sub)
            table.add_row(sub, str(status_code) if status_code else "Error")
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
