# GNU GENERAL PUBLIC LICENSE 
# Version 3, 29 June 2007
# Copyright © 2007 Free Software Foundation, Inc. <http://fsf.org/>
import sys
import os
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
import json
import re

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input, clean_url, ensure_url_format

console = Console()

def banner():
    console.print("""
    =============================================
           Argus - Advanced HTTP Security Headers Check
    =============================================
    """, style="bold red")

def get_headers(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.headers, response.text
    except requests.RequestException as e:
        console.print(f"[!] Error retrieving headers: {e}", style="bold red")
        return None, None

def display_headers(headers):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Header", style="cyan", justify="left")
    table.add_column("Value", style="green")
    for header, value in headers.items():
        table.add_row(header, value)
    console.print(table)

def analyze_security_headers(headers):
    security_headers = {
        "Content-Security-Policy": "Not Set",
        "Strict-Transport-Security": "Not Set",
        "X-Content-Type-Options": "Not Set",
        "X-Frame-Options": "Not Set",
        "X-XSS-Protection": "Not Set",
        "Referrer-Policy": "Not Set",
        "Permissions-Policy": "Not Set"
    }
    for header in security_headers:
        if header in headers:
            security_headers[header] = "Configured"
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Security Header", style="cyan", justify="left")
    table.add_column("Status", style="green")
    for header, status in security_headers.items():
        table.add_row(header, status)
    console.print(table)
    missing = [header for header, status in security_headers.items() if status == "Not Set"]
    if missing:
        console.print(f"[!] Missing Security Headers: {', '.join(missing)}", style="bold yellow")
    else:
        console.print("[+] All critical security headers are properly configured.", style="bold blue")

def identify_server_technology(headers):
    server = headers.get("Server", "Unknown")
    technology = "Unknown"
    if "nginx" in server.lower():
        technology = "Nginx Web Server"
    elif "apache" in server.lower():
        technology = "Apache Web Server"
    elif "iis" in server.lower():
        technology = "Microsoft IIS"
    elif "cloudflare" in server.lower():
        technology = "Cloudflare CDN"
    console.print("[*] Detecting server technology...", style="yellow")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Server", style="cyan", justify="left")
    table.add_column("Detected Technology", style="green")
    table.add_row(server, technology)
    console.print(table)

def scan_vulnerabilities(headers):
    vulnerabilities = []
    if headers.get("X-Content-Type-Options", "").lower() != "nosniff":
        vulnerabilities.append("X-Content-Type-Options is not set to 'nosniff'")
    if "Strict-Transport-Security" in headers:
        if "max-age=0" in headers["Strict-Transport-Security"]:
            vulnerabilities.append("Strict-Transport-Security max-age is set to 0")
    if "Content-Security-Policy" in headers:
        if "default-src 'self'" not in headers["Content-Security-Policy"]:
            vulnerabilities.append("Content-Security-Policy is not restrictive enough")
    if headers.get("X-Frame-Options", "").upper() not in ["DENY", "SAMEORIGIN"]:
        vulnerabilities.append("X-Frame-Options is not set to 'DENY' or 'SAMEORIGIN'")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Vulnerability", style="cyan", justify="left")
    table.add_column("Issue", style="red")
    for vuln in vulnerabilities:
        table.add_row("Security Issue", vuln)
    if vulnerabilities:
        console.print(table)
    else:
        console.print("[+] No vulnerabilities detected based on HTTP headers.", style="bold green")

def analyze_cookies(headers):
    cookies = headers.get("Set-Cookie")
    if not cookies:
        console.print("[!] No cookies found.", style="yellow")
        return
    console.print("[*] Analyzing cookies for security flags...", style="yellow")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Cookie", style="cyan", justify="left")
    table.add_column("Attributes", style="green")
    cookies = cookies.split(',')
    for cookie in cookies:
        cookie = cookie.strip()
        parts = cookie.split(';')
        name_value = parts[0]
        attributes = [attr.strip() for attr in parts[1:]]
        security_flags = []
        for attr in attributes:
            if attr.lower() == "secure":
                security_flags.append("Secure")
            if attr.lower() == "httponly":
                security_flags.append("HttpOnly")
            if attr.lower().startswith("samesite"):
                security_flags.append(attr)
        table.add_row(name_value, ", ".join(security_flags) if security_flags else "None")
    console.print(table)

def detect_frameworks(response_text):
    frameworks = {
        "WordPress": "wp-content",
        "Joomla": "Joomla!",
        "Drupal": "Drupal.settings",
        "Django": "csrftoken",
        "Ruby on Rails": "Rails",
        "Laravel": "laravel_session"
    }
    detected = []
    for framework, signature in frameworks.items():
        if signature in response_text:
            detected.append(framework)
    if detected:
        console.print(f"[+] Detected Frameworks: {', '.join(detected)}", style="bold green")
    else:
        console.print("[!] No common frameworks detected.", style="yellow")

def check_redirects(url):
    """Check if there are any redirects for the provided URL"""
    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        if response.history:
            console.print(f"[!] Redirects detected for {url}", style="yellow")
            for resp in response.history:
                console.print(f"[*] Redirected to {resp.url} with status code {resp.status_code}", style="cyan")
            console.print(f"[+] Final destination: {response.url}", style="green")
        else:
            console.print(f"[+] No redirects for {url}", style="green")
    except requests.RequestException as e:
        console.print(f"[!] Error checking redirects: {e}", style="bold red")

def analyze_status_code(headers):
    """Analyze HTTP status code to check for issues"""
    status_code = headers.get("Status-Code")
    if status_code:
        if 400 <= status_code < 500:
            console.print(f"[!] Client error detected with status code {status_code}", style="bold yellow")
        elif 500 <= status_code < 600:
            console.print(f"[!] Server error detected with status code {status_code}", style="bold red")
        else:
            console.print(f"[+] Status code {status_code} indicates no error", style="green")
    else:
        console.print("[!] Status code not found in headers", style="bold yellow")

def check_x_powered_by(headers):
    """Check for the presence of the X-Powered-By header, which might reveal the backend technology"""
    x_powered_by = headers.get("X-Powered-By", "Not Set")
    if x_powered_by != "Not Set":
        console.print(f"[!] X-Powered-By header found: {x_powered_by}", style="bold yellow")
    else:
        console.print("[+] X-Powered-By header not set, which is recommended for security.", style="green")

def check_cors_policy(headers):
    """Analyze the CORS policy header"""
    cors_policy = headers.get("Access-Control-Allow-Origin", "Not Set")
    if cors_policy == "*":
        console.print("[!] CORS policy allows access from all origins. This might be risky.", style="bold red")
    elif cors_policy == "Not Set":
        console.print("[!] No CORS policy set.", style="bold yellow")
    else:
        console.print(f"[+] CORS policy restricts access to: {cors_policy}", style="green")

def main(target):
    banner()
    target = clean_url(clean_domain_input(target))
    console.print(f"[*] Fetching HTTP headers for: {target}", style="white")
    headers, response_text = get_headers(target)
    
    # New functionality added here
    check_redirects(target)  # Check redirects
    analyze_status_code(headers)  # Check status code
    check_x_powered_by(headers)  # Check X-Powered-By header
    check_cors_policy(headers)  # Check CORS policy

    # Existing functionality follows
    if headers:
        console.print("[*] Displaying HTTP headers...", style="yellow")
        display_headers(headers)
        console.print("[*] Analyzing security headers...", style="yellow")
        analyze_security_headers(headers)
        identify_server_technology(headers)
        console.print("[*] Scanning for vulnerabilities based on headers...", style="yellow")
        scan_vulnerabilities(headers)
        console.print("[*] Analyzing cookies for security flags...", style="yellow")
        analyze_cookies(headers)
        console.print("[*] Detecting frameworks based on response content...", style="yellow")
        detect_frameworks(response_text)
    else:
        console.print("[!] No headers found.", style="bold red")
    console.print("[*] HTTP header analysis completed.", style="white")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[!] Please provide a target URL.", style="bold red")
    else:
        main(ensure_url_format(sys.argv[1]))
