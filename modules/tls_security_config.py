# GNU GENERAL PUBLIC LICENSE 
# Version 3, 29 June 2007
# Copyright © 2007 Free Software Foundation, Inc. <http://fsf.org/>
import sys
import ssl
import socket
import argparse
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich import box
from colorama import init
import concurrent.futures
from datetime import datetime

# Initialize Colorama
init(autoreset=True)

# Create a console instance for Rich
console = Console()

DEFAULT_TIMEOUT = 5

def banner():
    console.print("""
    =============================================
           Argus - TLS Security Configuration Analyzer
    =============================================
    """, style="bold green")

def clean_domain_input(domain: str) -> str:
    domain = domain.strip()
    if domain.startswith(('http://', 'https://')):
        parsed = urlparse(domain)
        return parsed.hostname
    else:
        return domain.split('/')[0]

def get_tls_security_config(domain: str, ip: str = None, port: int = 443):
    results = []
    target = ip if ip else domain

    try:
        context = ssl.create_default_context()
        context.set_ciphers('ALL:@SECLEVEL=0')
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target, port), timeout=DEFAULT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                protocol_version = tls_sock.version()
                cipher = tls_sock.cipher()
                cert = tls_sock.getpeercert()
                supported_tls_versions = get_supported_tls_versions(domain, ip, port)
                supported_ciphers = get_supported_ciphers(domain, ip, port)
                results.append({
                    "protocol_version": protocol_version,
                    "cipher": cipher,
                    "cert": cert,
                    "supported_tls_versions": supported_tls_versions,
                    "supported_ciphers": supported_ciphers
                })
    except Exception as e:
        console.print(f"[!] Error retrieving TLS security configuration for {domain}: {e}", style="bold red")
        return None

    return results

def get_supported_tls_versions(domain: str, ip: str, port: int = 443):
    tls_versions = {
        'TLSv1': ssl.TLSVersion.TLSv1,
        'TLSv1.1': ssl.TLSVersion.TLSv1_1,
        'TLSv1.2': ssl.TLSVersion.TLSv1_2,
        'TLSv1.3': ssl.TLSVersion.TLSv1_3,
    }
    supported_versions = []

    for name, version in tls_versions.items():
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = version
            context.maximum_version = version
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((ip if ip else domain, port), timeout=DEFAULT_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                    supported_versions.append(name)
        except Exception:
            pass  # Ignore exceptions; version not supported
    return supported_versions

def get_supported_ciphers(domain: str, ip: str, port: int):
    context = ssl.create_default_context()
    context.set_ciphers('ALL:@SECLEVEL=0')
    ciphers = context.get_ciphers()
    cipher_names = [cipher['name'] for cipher in ciphers if 'name' in cipher]

    supported_ciphers = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_cipher = {
            executor.submit(test_cipher, domain, ip, port, cipher): cipher for cipher in cipher_names
        }
        for future in concurrent.futures.as_completed(future_to_cipher):
            cipher = future_to_cipher[future]
            if future.result():
                supported_ciphers.append(cipher)
    return supported_ciphers

def test_cipher(domain: str, ip: str, port: int, cipher: str):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.set_ciphers(cipher)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip if ip else domain, port), timeout=DEFAULT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                return True
    except Exception:
        return False

def extract_cert_info(cert):
    subject = dict(x[0] for x in cert.get('subject', []))
    issuer = dict(x[0] for x in cert.get('issuer', []))
    valid_from = cert.get('notBefore')
    valid_to = cert.get('notAfter')
    serial_number = cert.get('serialNumber')
    san = cert.get('subjectAltName', [])
    return {
        "Subject": subject,
        "Issuer": issuer,
        "Valid From": valid_from,
        "Valid To": valid_to,
        "Serial Number": serial_number,
        "SAN": san
    }

def analyze_tls_security(config):
    issues = []
    
    # Check for weak TLS versions
    weak_tls_versions = {'TLSv1', 'TLSv1.1'}
    supported_versions = set(config.get('supported_tls_versions', []))
    if supported_versions & weak_tls_versions:
        issues.append("Weak TLS versions supported: " + ", ".join(supported_versions & weak_tls_versions))

    # Check for weak ciphers
    weak_ciphers = []
    for cipher in config.get('supported_ciphers', []):
        if any(weak in cipher.upper() for weak in ['RC4', '3DES', 'DES', 'MD5', 'NULL', 'EXP', 'RC2', 'IDEA', 'SEED', 'CAMELLIA', 'ANON', 'CBC', 'SHA1']):
            weak_ciphers.append(cipher)
    if weak_ciphers:
        issues.append("Weak cipher suites supported: " + ", ".join(weak_ciphers))

    # Check for weak key exchange methods
    weak_key_exchange = []
    for cipher in config.get('supported_ciphers', []):
        if 'RSA' in cipher and 'ECDHE' not in cipher:
            weak_key_exchange.append(cipher)
    if weak_key_exchange:
        issues.append("Weak key exchange methods used: " + ", ".join(weak_key_exchange))

    # Check for weak elliptic curves
    weak_curves = {'secp192r1', 'secp224r1', 'secp256k1'}
    supported_curves = set(config.get('supported_curves', []))
    if supported_curves & weak_curves:
        issues.append("Weak elliptic curves supported: " + ", ".join(supported_curves & weak_curves))

    # Check for PFS support
    pfs_ciphers = [cipher for cipher in config.get('supported_ciphers', []) if 'ECDHE' in cipher or 'DHE' in cipher]
    if not pfs_ciphers:
        issues.append("No cipher suites with Perfect Forward Secrecy (PFS) are supported")

    # Check for weak certificate signature algorithms
    cert_info = extract_cert_info(config.get('cert', {}))
    if cert_info.get('Signature Algorithm', '').upper() in ['SHA1', 'MD5']:
        issues.append("Weak certificate signature algorithm: " + cert_info['Signature Algorithm'])

    # Check certificate expiration
    if cert_info.get('Valid To'):
        valid_to = datetime.strptime(cert_info['Valid To'], '%b %d %H:%M:%S %Y %Z')
        days_left = (valid_to - datetime.utcnow()).days
        if days_left < 30:
            issues.append(f"Certificate expires in less than 30 days ({days_left} days left)")

    # Check if TLS compression is enabled
    if config.get('compression_enabled', False):
        issues.append("TLS compression is enabled, which is vulnerable to CRIME attacks")

    # Check for TLS downgrade prevention
    if not config.get('tls_fallback_scsv', False):
        issues.append("TLS_FALLBACK_SCSV not supported, vulnerable to downgrade attacks")

    # Check for session resumption support
    if not config.get('session_tickets_enabled', False):
        issues.append("Session tickets are not enabled, reducing session resumption performance")

    # Check for minimum RSA key size
    key_size = cert_info.get('Key Size')
    if key_size is None:
        issues.append("Key size information is missing from the certificate")
    elif key_size < 2048:
        issues.append(f"RSA key size is too small: {key_size} bits")

    return issues

def display_tls_security_config(domain: str, ip: str, configs):
    if not configs:
        console.print(f"[!] Unable to retrieve TLS security configuration for {domain}.", style="bold red")
        return

    for config in configs:
        protocol_version = config.get('protocol_version', 'N/A')
        cipher_suite = config.get('cipher', ('N/A', 'N/A', 'N/A'))
        cert = config.get('cert', {})
        supported_tls_versions = config.get('supported_tls_versions', [])
        supported_ciphers = config.get('supported_ciphers', [])

        table = Table(title=f"TLS Security Configuration for {domain} ({ip or 'Resolved IP'})",
                      show_header=False, box=box.SIMPLE)
        table.add_row("Negotiated Protocol Version:", protocol_version)
        table.add_row("Negotiated Cipher Suite:", cipher_suite[0])
        table.add_row("Cipher Protocol:", cipher_suite[1])
        table.add_row("Cipher Bits:", str(cipher_suite[2]))
        table.add_row("Supported TLS Versions:", ", ".join(supported_tls_versions))
        table.add_row("Number of Supported Ciphers:", str(len(supported_ciphers)))

        cert_info = extract_cert_info(cert)
        table.add_row("Certificate Subject:", str(cert_info.get("Subject", {})))
        table.add_row("Certificate Issuer:", str(cert_info.get("Issuer", {})))
        table.add_row("Valid From:", cert_info.get("Valid From", 'N/A'))
        table.add_row("Valid To:", cert_info.get("Valid To", 'N/A'))
        table.add_row("Serial Number:", cert_info.get("Serial Number", 'N/A'))
        table.add_row("Subject Alternative Names:", ', '.join(f"{typ}:{val}" for typ, val in cert_info.get("SAN", [])))

        console.print(table)

        # Analyze and display security issues
        issues = analyze_tls_security(config)
        if issues:
            console.print("[!] Security Issues Found:", style="bold yellow")
            for issue in issues:
                console.print(f"    - {issue}", style="bold yellow")
        else:
            console.print("[+] No security issues detected.", style="bold green")

def main():
    parser = argparse.ArgumentParser(description='Argus - TLS Security Configuration Analyzer')
    parser.add_argument('targets', nargs='+', help='Target domains or IPs (domain[:ip])')
    parser.add_argument('--port', type=int, default=443, help='Port to connect to (default: 443)')
    parser.add_argument('--threads', type=int, default=10, help='Number of concurrent threads (default: 10)')

    args = parser.parse_args()
    banner()

    targets = []
    for target in args.targets:
        if ':' in target:
            domain_part, ip_part = target.split(':', 1)
            domain = clean_domain_input(domain_part)
            ip = ip_part
        else:
            domain = clean_domain_input(target)
            ip = None
        targets.append((domain, ip))

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_target = {
            executor.submit(get_tls_security_config, domain, ip, args.port): (domain, ip)
            for domain, ip in targets
        }
        for future in concurrent.futures.as_completed(future_to_target):
            domain, ip = future_to_target[future]
            configs = future.result()
            display_tls_security_config(domain, ip, configs)

    console.print("[*] TLS security configuration analysis completed.", style="bold cyan")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[!] Process interrupted by user.", style="bold red")
        sys.exit(1)
