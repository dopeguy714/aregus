import os
import sys
import requests
from rich.console import Console
from rich.table import Table
from colorama import Fore, init
import time
from bs4 import BeautifulSoup

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input  
from config.settings import DEFAULT_TIMEOUT  

init(autoreset=True)
console = Console()

def banner():
    console.print(Fore.GREEN + """
    =============================================
           Argus - Advanced Firewall Detection
    =============================================
    """)

def clean_url(url):
    cleaned_url = url.replace("http://", "").replace("https://", "").strip('/')
    if not cleaned_url.startswith(('http://', 'https://')):
        cleaned_url = 'http://' + cleaned_url
    return cleaned_url

def send_request(url, method='GET', headers=None):
    try:
        if headers:
            response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        else:
            response = requests.request(method, url, timeout=DEFAULT_TIMEOUT)
        return response
    except requests.Timeout:
        console.print(Fore.YELLOW + "[!] Request timed out.")
        return None
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error retrieving information: {e}")
        return None

def detect_firewall(url):
    detection_results = set()

    # Basic response analysis
    response = send_request(url)
    if not response:
        return None

    headers = response.headers
    status_code = response.status_code
    response_body = response.text

    # Firewall detection based on headers
    firewall_signatures = {
        "Cloudflare": "cloudflare",
        "Akamai": "X-Akamai",
        "Sucuri": "x-sucuri-id",
        "AWS Shield": ["x-amz-cf-id", "x-amz-request-id"],
        "Imperva": "x-cdn",
        "Incapsula": "X-CDN",
        "F5 BIG-IP": ["X-Proxy-Id", "X-Proxy-Security"],
        "BunnyCDN": "X-Cache",
        "Palo Alto": "X-Powered-By",
        "F5 Networks": "Server",
        "Barracuda": "Server",
        "Wallarm": ["X-WAF", "X-Wallarm"],
        "Fortinet": ["Server", "X-Fortigate"],
        "Radware": "X-Radware-Id",
        "Cloudbric": "X-Cloudbric",
        "StackPath": "X-StackPath",
        "WebKnight": "X-WebKnight",
        "ModSecurity": "X-ModSecurity"
    }

    # Header-based detection
    for name, signature in firewall_signatures.items():
        if isinstance(signature, list):
            if any(key in headers for key in signature):
                detection_results.add(f"{name} Detected")
        elif signature in headers and signature.lower() in headers[signature].lower():
            detection_results.add(f"{name} Detected")

    # Check for specific status codes and response characteristics
    if status_code == 403:
        detection_results.add("Possible WAF Detected - Received 403 Forbidden")
    elif status_code == 401:
        detection_results.add("Unauthorized Access - Possible WAF or Authentication Layer")
    elif status_code == 429:
        detection_results.add("Too Many Requests - Possible Rate Limiting Detected")
    
    if response.elapsed.total_seconds() > 5:
        detection_results.add("Possible Rate Limiting Detected - WAF Protection")
    if 'captcha' in response_body.lower() or 'access denied' in response_body.lower():
        detection_results.add("Possible CAPTCHA Detected - WAF Protection")
    if '<title>Access Denied</title>' in response_body:
        detection_results.add("Access Denied Page Detected - Possible WAF")
    
    # Check for JavaScript challenge
    soup = BeautifulSoup(response_body, 'html.parser')
    if soup.find('div', {'id': 'challenge'}):
        detection_results.add("JavaScript Challenge Detected - Possible Cloudflare or Similar WAF")

    # Probing unusual paths
    unusual_paths = ["/admin", "/login", "/phpmyadmin", "/wp-admin", "/uploads", "/config", "/dashboard"]
    for path in unusual_paths:
        probe_url = f"{url.rstrip('/')}{path}"
        probe_response = send_request(probe_url)
        if probe_response and (probe_response.status_code == 403 or 'forbidden' in probe_response.text.lower()):
            detection_results.add(f"Potential WAF Blocking Access to Sensitive Path ({path})")

    # Using various HTTP methods
    http_methods = ["OPTIONS", "TRACE", "PUT", "POST", "DELETE", "PATCH"]
    for method in http_methods:
        probe_response = send_request(url, method)
        if probe_response and probe_response.status_code in [405, 501]:
            detection_results.add(f"{method} Method Blocked - Possible WAF Behavior")

    # Analyzing responses for content alterations or challenges
    altered_headers = {'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'}
    altered_response = send_request(url, headers=altered_headers)
    if altered_response and altered_response.status_code != status_code:
        detection_results.add("Different Response with Altered Headers - Possible WAF Behavior")
    if altered_response and 'challenge' in altered_response.text.lower():
        detection_results.add("Possible Challenge Detected with Altered Headers")

    # New Firewall Checks
    if 'X-Frame-Options' in headers and headers['X-Frame-Options'] == 'DENY':
        detection_results.add("X-Frame-Options Deny - Possible Protection Layer")
    if 'Content-Security-Policy' in headers:
        detection_results.add("Content Security Policy Detected - Possible Firewall")

    time.sleep(1)

    return ", ".join(detection_results) if detection_results else "No Recognized Firewall Detected"

def display_firewall_detection(firewall_info, status_code):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Firewall Status", style="cyan", justify="left")
    table.add_column("Details", style="green", justify="left")
    table.add_column("Status Code", style="green", justify="left")
    
    # Display the detected firewall info and corresponding status code
    table.add_row(firewall_info, "Detected through HTTP headers, response behavior, non-standard methods, and content analysis", str(status_code))
    console.print(table)

def main(target):
    banner()
    target = clean_domain_input(target)
    target = clean_url(target)  
    console.print(Fore.WHITE + f"[*] Detecting firewall for: {target}")

    firewall_info = detect_firewall(target)
    if firewall_info:
        # Get the status code to pass to the display function
        status_code = send_request(target).status_code  # Get the status code of the original request
        display_firewall_detection(firewall_info, status_code)  # Pass the status code
    else:
        console.print(Fore.RED + "[!] No firewall information found.")
    
    console.print(Fore.WHITE + "[*] Firewall detection completed.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            target = sys.argv[1]
            main(target)
        except KeyboardInterrupt:
            console.print(Fore.RED + "\n[!] Process interrupted by user.")
            
    else:
        console.print(Fore.RED + "[!] No target provided. Please pass a domain or URL.")
        sys.exit(1)
