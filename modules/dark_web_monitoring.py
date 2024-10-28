# GNU GENERAL PUBLIC LICENSE 
# Version 3, 29 June 2007
# Copyright © 2007 Free Software Foundation, Inc. <http://fsf.org/>
import sys
import requests
from rich.console import Console
from rich.table import Table
from colorama import Fore, init

init(autoreset=True)
console = Console()

def banner():
    print(Fore.WHITE + """
    =============================================
           Argus - Dark Web Monitoring
    =============================================
    """)

def monitor_scylla(query):
    try:
        # Scylla API endpoint
        url = f"https://scylla.sh/search?q=email:*@{query}&size=100"
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()  # Raise an error for bad responses
        results = response.json()
        return results
    except requests.RequestException as e:
        print(Fore.RED + f"[!] Error querying Scylla: {e}")
        return []

def monitor_pastebin(query):
    try:
        # Pastebin Search (through a public scraping API)
        url = f"https://psbdmp.ws/api/v3/search/{query}"
        response = requests.get(url, timeout=30)
        data = response.json()

        # Debug: Print the raw response data
        print(Fore.YELLOW + f"[*] Raw Pastebin response: {data}")

        # Check if response is a list
        if isinstance(data, list):
            return data  # Directly return the list if that's the case
        else:
            results = data.get('data', [])
            return results
    except requests.RequestException as e:
        print(Fore.RED + f"[!] Error querying Pastebin dumps: {e}")
        return []

def display_scylla_results(results):
    if not results:
        console.print(Fore.RED + "[!] No data found on Scylla.")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Email", style="cyan", justify="left")
    table.add_column("Password", style="green")
    table.add_column("Source", style="white")

    for result in results:
        email = result.get("email", "N/A")
        password = result.get("password", "N/A")
        source = result.get("source", "N/A")
        table.add_row(email, password, source)

    console.print(table)

def display_pastebin_results(results):
    if not results:
        console.print(Fore.RED + "[!] No data found on Pastebin.")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("ID", style="cyan", justify="left")
    table.add_column("Title", style="green")
    table.add_column("Date", style="white")

    for result in results:
        # Adjust based on the structure of each result in the list
        paste_id = result.get("id", "N/A")  # Adjust if necessary
        title = result.get("title", "N/A")  # Adjust if necessary
        date = result.get("date", "N/A")    # Adjust if necessary
        table.add_row(paste_id, title, date)

    console.print(table)

def main(target):
    banner()
    print(Fore.WHITE + f"[*] Monitoring for domain: {target}")

    # Monitor Scylla
    console.print(Fore.YELLOW + "[*] Querying Scylla.sh...")
    scylla_results = monitor_scylla(target)

    # Monitor Pastebin Dumps
    console.print(Fore.YELLOW + "[*] Querying Pastebin Dumps...")
    pastebin_results = monitor_pastebin(target)

    if scylla_results:
        console.print(Fore.GREEN + "[+] Data found on Scylla:")
        display_scylla_results(scylla_results)
    else:
        console.print(Fore.RED + "[!] No data found on Scylla.")

    if pastebin_results:
        console.print(Fore.GREEN + "[+] Data found on Pastebin:")
        display_pastebin_results(pastebin_results)
    else:
        console.print(Fore.RED + "[!] No data found on Pastebin.")

    print(Fore.CYAN + "[*] Monitoring completed.")

if __name__ == "__main__":
    try:
        target = input("Enter the domain to monitor: ")
        main(target)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
