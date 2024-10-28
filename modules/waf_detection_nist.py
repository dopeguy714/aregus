# GNU GENERAL PUBLIC LICENSE 
# Version 3, 29 June 2007
# Copyright © 2007 Free Software Foundation, Inc. <http://fsf.org/>
import sys
import os
import requests
from colorama import Fore, Style, init
from rich.console import Console
from rich.table import Table

# Add parent directory to sys.path for module imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input
from config.settings import DEFAULT_TIMEOUT

init(autoreset=True)
console = Console()

def banner():
    console.print(Fore.GREEN + """
    =============================================
           Argus - WAF Detection NIST
    =============================================
    """)

def check_nist_compliance(domain):
    """
    Checks if a web application is protected by a WAF and complies with NIST SP 800-53 standards
    :param domain: The domain name of the web application to check (e.g., example.com)
    :return: A message showing the WAF status and NIST compliance
    """
    url = f"http://{domain}"
    https_url = f"https://{domain}"  # Check for HTTPS as well
    detected_controls = []
    missing_controls = []

    try:
        # Send HTTP request to the specified URL and follow redirects
        response = requests.get(url, allow_redirects=True)

        # Define NIST controls with additional headers
        nist_controls = {
            "Access Control": ["X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy"],
            "Audit and Accountability": ["X-Content-Type-Options", "X-XSS-Protection", "Strict-Transport-Security"],
            "Incident Response": ["X-Content-Type-Options", "X-XSS-Protection"],
            "System and Communications Protection": ["Content-Security-Policy", "Strict-Transport-Security"],
            "Configuration Management": ["X-Permitted-Cross-Domain-Policies", "Public-Key-Pins"],
            "Identification and Authentication": ["WWW-Authenticate", "Authorization", "X-Frame-Options"],
            "Risk Assessment": ["X-Content-Type-Options"],
            "Media Protection": ["X-Content-Type-Options"],
            "Physical Protection": ["X-Content-Type-Options"],
            "System and Information Integrity": ["X-XSS-Protection", "X-Content-Type-Options", "Referrer-Policy"],
        }

        # Check headers for NIST compliance
        for control, indicators in nist_controls.items():
            for indicator in indicators:
                if indicator in response.headers:
                    detected_controls.append(f"{control}: {indicator} - {response.headers[indicator]}")
                else:
                    missing_controls.append(f"{control}: {indicator} - Missing")

        # Check HTTPS support
        try:
            https_response = requests.get(https_url, allow_redirects=True, timeout=DEFAULT_TIMEOUT)
            if https_response.status_code == 200:
                detected_controls.append("HTTPS: Supported")
            else:
                missing_controls.append("HTTPS: Not supported")
        except requests.RequestException:
            missing_controls.append("HTTPS: Not supported")

        # Check for common WAF headers (this list can be extended)
        waf_indicators = ["Server", "X-Sec", "X-WAF", "X-Content-Type-Options"]
        waf_detected = any(indicator in response.headers for indicator in waf_indicators)
        
        if waf_detected:
            detected_controls.append("WAF: Detected")
        else:
            missing_controls.append("WAF: Not detected")

        return detected_controls, missing_controls

    except requests.RequestException as e:
        return [f"Error while connecting to {url}: {e}"], []

def display_nist_compliance_results(results):
    detected_controls, missing_controls = results

    console.print("\n[cyan][*] NIST SP 800-53 Compliance Check Results:[/cyan]")
    console.print(Fore.GREEN + "[*] Detected Controls:")
    
    if detected_controls:
        table = Table(show_header=True, header_style="bold white", style="green")
        table.add_column("Control Category", justify="center", min_width=25)
        table.add_column("Header", justify="left", min_width=60)

        for result in detected_controls:
            control, header_info = result.split(": ", 1)
            table.add_row(control, header_info)

        console.print(table)
    else:
        console.print(Fore.YELLOW + "[!] No controls detected.")

    console.print(Fore.RED + "[*] Missing Controls:")
    
    if missing_controls:
        for missing in missing_controls:
            console.print(f"[yellow]* {missing}")
    else:
        console.print(Fore.GREEN + "[!] All recommended controls are present.")

    console.print("\n[cyan][*] NIST compliance check completed.[/cyan]")

def main(target):
    banner()
    console.print(f"[cyan][*] Checking WAF compliance for domain: {target}[/cyan]")
    compliance_results = check_nist_compliance(target)
    display_nist_compliance_results(compliance_results)

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
