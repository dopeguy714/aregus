import os
import sys
import dns.resolver
from rich.console import Console
from rich.table import Table
from colorama import Fore, init


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input, validate_domain  


init(autoreset=True)
console = Console()

def banner():
    print(Fore.GREEN + """
    =============================================
               Argus - DNS Records Check
    =============================================
    """)

def get_dns_records(domain):
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    try:
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                console.print(f"[!] No {record_type} records found for {domain}." , style="WHITE")
            except dns.resolver.NXDOMAIN:
                console.print(f"[!] Domain {domain} does not exist.",style="BLUE")
                return None
            except dns.exception.DNSException as e:
                console.print(f"[!] Error retrieving {record_type} records: {e}",style="RED")
        return records
    except dns.exception.DNSException as e:
        console.print(f"[!] Error retrieving DNS records for {domain}: {e}",style="RED")
        return None

def display_dns_records(records):
    if records:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Record Type", style="cyan", justify="left")
        table.add_column("Record Value", style="green")

        for record_type, record_data in records.items():
            table.add_row(record_type, "\n".join(record_data))

        console.print(table)
    else:
        console.print(Fore.RED + "[!] No DNS records to display.")

def main(target):
    banner()

    
    domain = clean_domain_input(target)

    if not validate_domain(domain):
        console.print("[!] Invalid domain format. Please check the domain and try again.",style="RED")
        return

    console.print(f"[*] Fetching DNS records for: {domain}",style="WHITE")
    dns_records = get_dns_records(domain)

    if dns_records:
        display_dns_records(dns_records)
    else:
        console.print(Fore.RED + "[!] No DNS records found.")

    console.print("[*] DNS records retrieval completed.",style="WHITE")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        main(target)
    else:
        console.print("[!] No target provided. Please pass a domain.",style="RED")
        sys.exit(1)
