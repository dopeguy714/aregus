# GNU GENERAL PUBLIC LICENSE 
# Version 3, 29 June 2007
# Copyright © 2007 Free Software Foundation, Inc. <http://fsf.org/>
import sys
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from rich.console import Console
from rich.table import Table
import ssl
import socket
import time
import subprocess
import os
import re

console = Console()

def banner():
    console.print("""
    =============================================
              Argus - Network Design Checker
    =============================================
    """, style="green")

class WebsiteChecker:
    def __init__(self, url):
        if url.startswith("http://"):
            url = url[7:]  
        elif url.startswith("https://"):
            url = url[8:] 
        
        self.url = "https://" + url 
        self.status_code = None
        self.title = None
        self.meta_description = None
        self.meta_keywords = None
        self.response_time = None
        self.page_size = None
        self.ssl_info = None
        self.latency = None
        self.packet_loss = None
        self.open_ports = []

    def check_website(self):
        try:
            response = requests.get(self.url)
            self.status_code = response.status_code
            self.response_time = response.elapsed.total_seconds()
            self.page_size = len(response.content)
            
            if self.status_code == 200:
                self.parse_html(response.text)
                console.print(f"Website '{self.url}' is accessible.", style="green")
                self.check_ssl()
            else:
                console.print(f"Website '{self.url}' returned status code: {self.status_code}", style="yellow")
        
        except requests.exceptions.RequestException as e:
            console.print(f"Error accessing '{self.url}': {e}", style="red")

    def parse_html(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        title_tag = soup.find('title')
        self.title = title_tag.text if title_tag else "No title found"
        description_tag = soup.find('meta', attrs={'name': 'description'})
        self.meta_description = description_tag['content'] if description_tag else "No meta description found"
        keywords_tag = soup.find('meta', attrs={'name': 'keywords'})
        self.meta_keywords = keywords_tag['content'] if keywords_tag else "No meta keywords found"

    def check_ssl(self):
        hostname = self.url[8:]  
        context = ssl.create_default_context()
        try:
            with context.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.connect((hostname, 443))
                cert = s.getpeercert()
                self.ssl_info = cert
                console.print("SSL Certificate is valid.", style="green")
                console.print(f"Expiration Date: {datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')}", style="green")
        except Exception as e:
            console.print(f"SSL Certificate error: {e}", style="red")

    def check_latency(self):
        start_time = time.time()
        try:
            response = requests.get(self.url, timeout=2)
            self.latency = time.time() - start_time
        except requests.exceptions.RequestException:
            self.latency = None

    def check_packet_loss(self):
        hostname = self.url[8:]  
        ping_command = ['ping', '-c', '10', hostname] if os.name != 'nt' else ['ping', '-n', '10', hostname]
        completed_process = subprocess.run(ping_command, capture_output=True, text=True)
        output = completed_process.stdout

        # Debugging output to see the result of the ping command
        console.print(f"Ping output:\n{output}")

        if "100% loss" in output:
            self.packet_loss = 100
        else:
            # Extract packet loss percentage from the output using regex
            loss_line = [line for line in output.splitlines() if 'loss' in line]
            if loss_line:
                try:
                    # Use regex to find the percentage of packet loss
                    loss_percentage = re.search(r'(\d+)% packet loss', loss_line[0])
                    if loss_percentage:
                        self.packet_loss = int(loss_percentage.group(1))  # Convert to int
                    else:
                        self.packet_loss = None  # No percentage found
                except (IndexError, ValueError) as e:
                    console.print(f"Error parsing packet loss: {e}", style="red")
                    self.packet_loss = None

    def check_ports(self, ports):
        self.open_ports = []
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((self.url[8:], port))
                if result == 0:
                    self.open_ports.append(port)

    def check_connectivity(self):
        try:
            response = requests.get(self.url, timeout=5)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def display_results(self):
        table = Table(title="Website Report")
        
        table.add_column("Property", justify="left", style="cyan", no_wrap=True)
        table.add_column("Value", justify="left", style="magenta")

        # Populate table with results
        table.add_row("URL", self.url)
        table.add_row("Status Code", str(self.status_code))
        table.add_row("Response Time", f"{self.response_time:.4f} seconds")
        table.add_row("Page Size", f"{self.page_size} bytes")
        table.add_row("Title", self.title)
        table.add_row("Meta Description", self.meta_description)
        table.add_row("Meta Keywords", self.meta_keywords)
        table.add_row("Latency", f"{self.latency:.4f} seconds" if self.latency is not None else "N/A")
        table.add_row("Packet Loss", f"{self.packet_loss}%" if self.packet_loss is not None else "N/A")
        table.add_row("Open Ports", ", ".join(map(str, self.open_ports)) if self.open_ports else "None")
        table.add_row("Connectivity", "Yes" if self.check_connectivity() else "No")

        console.print(table)

def main(target):
    banner()
    checker = WebsiteChecker(target)
    checker.check_website()
    checker.check_latency()
    checker.check_packet_loss()
    checker.check_ports([80, 443, 21, 22, 25])  # Example ports to check
    checker.display_results()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[!] Please provide a target host.", style="red")
        sys.exit(1)
    
    target_host = sys.argv[1]
    main(target_host)
