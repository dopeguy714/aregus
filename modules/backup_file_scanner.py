import requests
import argparse
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
import sys

console = Console()

file_names = [
    "backup", "lastbackup", "2017backup", "2018backup", "2019backup", "2020backup", "2021backup", "2022backup",
    "last_backup", "2017_backup", "2018_backup", "2019_backup", "2020_backup", "2021_backup", "2022_backup",
    "last-backup", "2017-backup", "2018-backup", "2019-backup", "2020-backup", "2021-backup", "2022-backup",
    "archive", ".backup", "!backup", "www", "root", "data", "admin", "alpha", "beta", "prod", "production",
    "test", "testing", "main", "old", "content", "database", "release", "template", "vip", "upfile", "wwwroot"
]

extensions = [
    ".zip", ".tar.gz", ".bzip", ".rar", ".gzip", ".7z", ".bak", ".backup", ".old", ".original", ".orig", ".save",
    ".sql", ".tmp", ".gho"
]

folders = [
    "backup_file", "backup_index", "backup", "backups", "_backup", "__backup", "2017backup", "2018backup",
    "2019backup", "2020backup", "2021backup", "2022backup", "systembackup", "system_backup", "SYSTEMBACKUP",
    "prod", "qa", "stage", "beta", "alpha", "archive", "test", "testing"
]

vulnerable_extensions = [
    ".env", ".config", ".json", ".xml", ".log", ".txt", ".ini"
]

# Function to get HTTP status code with minimal logging and basic headers
def get_status_code(url):
    try:
        response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"})
        return str(response.status_code)
    except requests.RequestException:
        return "Error"

# Scans and prints file paths based on folder paths that return a valid response
def scan_files(hostname, paths):
    for path in paths:
        print(f"\n************* Starting Scan for Backup Files in PATH: {path} *************\n")
        for file_name, extension in ((f, e) for f in file_names for e in extensions):
            url = f"{path}/{file_name}{extension}"
            status_code = get_status_code(url)
            message = f"{url} | Response Code: {status_code}"
            if status_code in {"200", "301", "302", "304", "307", "403"}:
                print(f"* Found: {message}")
            else:
                print(f"Checking: {message}")
        print(f"\n************* Scan Completed for PATH: {path} *************\n")

# Scan for vulnerable files
def scan_vulnerable_files(hostname, paths):
    print("\n************* Starting Vulnerable File Scan *************\n")
    for path in paths:
        for file_name in file_names:
            for ext in vulnerable_extensions:
                url = f"{path}/{file_name}{ext}"
                status_code = get_status_code(url)
                message = f"{url} | Response Code: {status_code}"
                if status_code in {"200", "301", "302", "304", "307", "403"}:
                    print(f"* Found Vulnerable File: {message}")
                else:
                    print(f"Checking: {message}")
    print("\n[+] Vulnerable File Scanning Ended.")

# Initial scan to find valid backup folders
def scan_paths(hostname):
    valid_paths = set()
    print("\n************* Starting Backup Paths Scan *************\n")
    for folder in folders:
        url = f"{hostname}/{folder}"
        status_code = get_status_code(url)
        message = f"{url} | Response Code: {status_code}"
        if status_code in {"200", "301", "302", "304", "307", "403"}:
            print(f"* Found: {message}")
            valid_paths.add(url)
        else:
            print(f"Checking: {message}")
    print("\n[+] Path Scanning Ended.")
    
    scan_files(hostname, valid_paths)
    scan_vulnerable_files(hostname, valid_paths)  # Scan for vulnerable files

# Main entry function with argparse
def main(target):
    print(r"""
    =============================================
              Argus - Backup File Scanner
    =============================================
    Backup Directories & Backup Files Scanner.
    Credit : https://github.com/tismayil
    Continue to develop with : https://github.com/ThemeHackers
    Host : {}
    """.format(target))

    scan_paths(target)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[!] Please provide a target host.", style="red")
        sys.exit(1)
    
    target_host = sys.argv[1]
    main(target_host)
