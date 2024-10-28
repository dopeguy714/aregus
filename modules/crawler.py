# GNU GENERAL PUBLIC LICENSE 
# Version 3, 29 June 2007
# Copyright © 2007 Free Software Foundation, Inc. <http://fsf.org/>
import sys
import threading
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from queue import Queue
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
import re
import os
import argparse
import time
import random
import urllib.robotparser

console = Console()

class Crawler:
    def __init__(self, base_url, max_threads=10, max_depth=3, timeout=5):
        self.base_url = self.sanitize_url(base_url)
        self.max_threads = max_threads
        self.max_depth = max_depth
        self.timeout = timeout
        self.visited = set()
        self.lock = threading.Lock()
        self.queue = Queue()
        self.queue.put((self.base_url, 0))  # URL and current depth
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console
        )
        self.task = self.progress.add_task("Crawling...", total=None)
        self.results = []
        self.output_file = self.generate_output_filename(base_url)
        self.headers = {'User-Agent': self.generate_user_agent()}
        self.rate_limit = 0.5  # seconds between requests to avoid overloading server
        self.domain_rate_limit = {}  # To track request timestamps per domain
        self.robots_parser = urllib.robotparser.RobotFileParser()
        self.robots_parser.set_url(urljoin(self.base_url, '/robots.txt'))
        self.robots_parser.read()

    def generate_user_agent(self):
        
        browsers = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; SM-G970F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 7.0; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
    "Mozilla/5.0 (Linux; Android 9; SM-A750F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 4.4.4; Nexus 5 Build/KRT16M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:80.0) Gecko/20100101 Firefox/80.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:74.0) Gecko/20100101 Firefox/74.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
]

        return random.choice(browsers)

    def sanitize_url(self, url):
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed_url = urlparse(url)
        sanitized_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        return sanitized_url.rstrip('/')

    def generate_output_filename(self, url):
        parsed_url = urlparse(url)
        sanitized_netloc = parsed_url.netloc
        sanitized_path = parsed_url.path.strip('/')

        # Combine netloc and path for the filename
        filename = f"{sanitized_netloc}_{sanitized_path}" if sanitized_path else sanitized_netloc

        # Remove any invalid characters from the filename
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)

        filename += "_web_crawler.txt"

        return os.path.join("results", filename)

    def save_results(self):
        if not os.path.exists("results"):
            os.makedirs("results")
        try:
            with open(self.output_file, 'w', encoding='utf-8') as file:
                for url, status, content_type in self.results:
                    file.write(f"{url} (Status: {status}) (Content-Type: {content_type})\n")
            console.print(f"[green][+][/green] Report saved to {self.output_file}")
        except Exception as e:
            console.print(f"[red][!] Error generating report: {e}[/red]")
            console.print_exception(show_locals=True)

    def crawl(self):
        while True:
            try:
                url, depth = self.queue.get(timeout=1)
            except:
                return
            with self.lock:
                if url in self.visited or depth > self.max_depth:
                    self.queue.task_done()
                    continue
                if not self.robots_parser.can_fetch(self.headers['User-Agent'], url):
                    console.print(f"[yellow][!] Skipping {url} due to robots.txt restrictions[/yellow]")
                    self.queue.task_done()
                    continue
                self.visited.add(url)
            self.progress.update(self.task, description=f"Crawling: {url}")
            try:
                domain = urlparse(url).netloc
                if domain not in self.domain_rate_limit:
                    self.domain_rate_limit[domain] = time.time()

                # Implement rate limiting based on domain
                time_since_last_request = time.time() - self.domain_rate_limit[domain]
                if time_since_last_request < self.rate_limit:
                    time.sleep(self.rate_limit - time_since_last_request)

                response = requests.get(url, timeout=self.timeout, headers=self.headers)
                self.domain_rate_limit[domain] = time.time()  # Update the timestamp for the domain
                
                status_code = response.status_code
                content_type = response.headers.get('Content-Type', '')
                console.print(f"[cyan][+][/] Found: {url} [green](Status: {status_code})[/] [yellow](Content-Type: {content_type})[/]")
                with self.lock:
                    self.results.append((url, status_code, content_type))
                if 'text/html' in content_type:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        href = link.get('href')
                        href = href.split('#')[0]  # Remove fragment
                        href = href.split('?')[0]  # Remove query parameters
                        full_url = urljoin(url, href)
                        parsed_base = urlparse(self.base_url)
                        parsed_full = urlparse(full_url)
                        if parsed_base.netloc == parsed_full.netloc:
                            normalized_url = full_url.rstrip('/')
                            with self.lock:
                                if normalized_url not in self.visited:
                                    self.queue.put((normalized_url, depth + 1))
            except requests.RequestException as e:
                console.print(f"[red][!][/] Error: {url} - {e}")
                with self.lock:
                    self.results.append((url, 'Error', str(e)))
            except Exception as e:
                console.print(f"[red][!] Unexpected error while crawling {url}: {e}[/red]")
                console.print_exception(show_locals=True)
            finally:
                self.queue.task_done()

    def run(self):
        with self.progress:
            threads = []
            for _ in range(self.max_threads):
                t = threading.Thread(target=self.crawl)
                t.daemon = True
                t.start()
                threads.append(t)
            self.queue.join()
            for t in threads:
                t.join()
        self.save_results()

def banner():
    console.print("""
==============================================
       Argus - Advanced Web Crawler
==============================================
""")

def main():
    banner()
    parser = argparse.ArgumentParser(description='Argus - Advanced Web Crawler')
    parser.add_argument('url', help='Starting URL or domain to crawl')
    parser.add_argument('--threads', type=int, default=10, help='Number of concurrent threads (default: 10)')
    parser.add_argument('--depth', type=int, default=3, help='Maximum crawl depth (default: 3)')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')
    args = parser.parse_args()

    base_url = args.url.strip()
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'http://' + base_url

    crawler = Crawler(base_url, max_threads=args.threads, max_depth=args.depth, timeout=args.timeout)
    try:
        crawler.run()
    except KeyboardInterrupt:
        console.print("\n[!] Interrupted by user. Exiting.")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red][!] Error running crawler: {e}[/red]")
        console.print_exception(show_locals=True)

if __name__ == "__main__":
    main()
