import os
import sys
import socket
import requests
import ssl
from colorama import Fore, init
from rich.console import Console
from rich.table import Table

init(autoreset=True)
console = Console()

def banner():
    console.print(Fore.GREEN + """
    =============================================   
        Argus - Server Misconfiguration Checker
    =============================================
    """)

def check_open_ports(host, ports):
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((host, port)) == 0:
                open_ports.append(port)
    return open_ports

def check_permissions(file_paths):
    permissions_status = {}
    for file_path in file_paths:
        if not os.path.exists(file_path):
            permissions_status[file_path] = "404 - File not found"
        elif os.access(file_path, os.R_OK | os.W_OK):
            permissions_status[file_path] = "Read and Write access"
        elif os.access(file_path, os.R_OK):
            permissions_status[file_path] = "Read-only access"
        else:
            permissions_status[file_path] = "No access"

    return permissions_status

def check_services(services):
    running_services = []
    for service in services:
        output = os.popen(f'systemctl is-active {service}').read()
        if 'active' in output:
            running_services.append(service)
    return running_services

def check_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                ssock.getpeercert()
        return "SSL Certificate is valid"
    except ssl.SSLError as e:
        return f"SSL Certificate error: {e}"

def check_http_headers(domain):
    url = f"http://{domain}"
    try:
        response = requests.get(url)
        headers_to_check = [
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy",
            "X-XSS-Protection"
        ]
        missing_headers = [header for header in headers_to_check if header not in response.headers]
        status_code = response.status_code
        if status_code != 200:
            return f"HTTP Status Code: {status_code}, Missing security headers: {', '.join(missing_headers)}" \
                if missing_headers else f"HTTP Status Code: {status_code}, All headers present"
        
        if missing_headers:
            return f"HTTP Status Code: 200, Missing security headers: {', '.join(missing_headers)}"
        return "HTTP Status Code: 200, All recommended security headers are present"
    except requests.RequestException as e:
        return f"Error fetching headers: {e}"

def check_for_vulnerabilities(domain):
    potential_vulnerabilities = []
    unauthorized_access = []
    wordlist = [
    'admin', 'login', 'test', 'config', 'debug', 'info', 'uploads', 'api',
    'manager', 'wp-admin', 'phpmyadmin', 'install', 'setup', 'dev',
    'secret', 'webconfig', 'webadmin', 'cms', 'xmlrpc', 'user',
    'dashboard', 'sql', 'data', 'backup', 'scripts', 'access', 'files',
    'cgi-bin', 'docs', 'secure', 'monitor', 'cache', 'private',
    'assets', 'public', 'images', 'media', 'services', 'files',
    'tests', 'sandbox', 'logs', 'tmp', 'tmpfs', 'repository',
    'source', 'version', 'configuration', 'environment', 'local',
    'staging', 'development', 'prod', 'application', 'content',
    'api', 'config', 'db', 'configurations', 'settings', 'versions',
    'test', 'demo', 'public_html', 'cgi', 'bin', 'www', 'static',
    'private_html', 'vhosts', 'backups', 'old', 'archive', 'scripts',
    'scripts', 'lib', 'var', 'database', 'mysql', 'sqlite', 'env',
    'jwt', 'access_logs', 'error_logs', 'readme', 'changelog', 
    'status', 'health', 'service', 'properties', 'web', 'portal',
    'content', 'data', 'local', 'api_key', 'uploads', 'uploads', 
    'testimonials', 'samples', 'sandbox', 'demo', 'api', 
    'login', 'auth', 'authentication', 'oauth', 'user', 'profile',
    'member', 'directory', 'wp-includes', 'js', 'css', 
    'wordpress', 'site', 'webroot', 'img', 'files', 'cache', 
    'uploads', 'pictures', 'photos', 'virtual', 'folder', 
    'content', 'webmail', 'mail', 'mailbox', 'inbox', 
    'outbox', 'smtp', 'smtp_config', 'pop3', 'database', 
    'database_backup', 'json', 'xml', 'http', 'https', 
    'ftp', 'ftps', 'sftp', 'bypass', 'soft', 'config_files',
    's3', 'bucket', 'vault', 'secret', 'environment', 
    'secrets', 'keystore', 'configurations', 'git', 'repository',
    'configuration', 'config', 'system', 'install', 'installer', 
    'setup', 'update', 'updates', 'module', 'modules', 
    'plugins', 'plugin', 'theme', 'themes', 'widgets', 
    'tools', 'settings', 'preference', 'configuration', 
    'ui', 'visual', 'meta', 'config', 'theme', 
    'front', 'backend', 'test', 'temporary', 'control', 
    'project', 'projects', 'workspace', 'dev', 'development', 
    'testing', 'new', 'draft', 'release', 'version', 
    'staging', 'staging_area', 'production', 'prod', 'main',
    'main_site', 'assets', 'content', 'files', 'downloads',
    'download', 'ftp_upload', 'doc', 'documentation', 'api',
    'api_access', 'cloud', 'cloud_storage', 'token', 
    'credential', 'secret', 'keys', 'tokens', 'data', 
    'reports', 'report', 'reporting', 'report_logs', 
    'monitoring', 'monitor', 'cron', 'crontab', 
    'process', 'worker', 'run', 'runs', 'update', 
    'updates', 'health_check', 'connect', 'connections', 
    'endpoint', 'entry', 'file', 'management', 'settings',
    'administration', 'admin', 'operator', 'operator_logs',
    'access', 'logs', 'tracking', 'auditing', 'audit', 
    'performance', 'trace', 'trace_logs', 'info_logs', 
    'debug_logs', 'console', 'errors', 'error', 
    'debug', 'variables', 'system', 'parameters', 'vars', 
    'options', 'criteria', 'defaults', 'default', 
    'routing', 'routing', 'urls', 'url', 'endpoints', 
    'paths', 'path', 'query', 'search', 'searches', 
    'query_string', 'post', 'posts', 'result', 'results', 
    'content', 'items', 'lists', 'collections', 'data', 
    'backend', 'front', 'gateway', 'oauth', 'openid', 
    'public', 'private', 'hidden', 'visible', 'show', 
    'visible', 'view', 'views', 'directory', 'direct',
    'path', 'request', 'requests', 'list', 'listing', 
    'navigation', 'search', 'find', 'lookup', 'finder', 
    'results', 'detail', 'details', 'summary', 'summaries', 
    'exports', 'import', 'imports', 'download', 'upload', 
    'upload_logs', 'stats', 'statistics', 'metric', 
    'metrics', 'performance', 'kpi', 'analysis', 
    'analyses', 'business', 'strategy', 'strategies', 
    'work', 'workspace', 'workspace', 'client', 
    'client_logs', 'remote', 'server', 'servers', 
    'communication', 'protocol', 'connection', 'transfer',
    'sync', 'synchronize', 'sync_logs', 'notify', 
    'notification', 'alert', 'alerts', 'feedback', 
    'reports', 'reporting', 'tickets', 'ticket', 
    'issues', 'issue', 'tracker', 'trackers', 
    'monitoring', 'resource', 'resources', 'license', 
    'license_keys', 'tokens', 'secret', 'secret_keys'
]


    urls_to_check = [f"http://{domain}/{word}" for word in wordlist]

    for url in urls_to_check:
        try:
            response = requests.get(url)
            if response.status_code == 200:
                if "redirect" in response.text.lower():
                    potential_vulnerabilities.append(f"Open Redirect found: {url}")
                if "debug" in response.text.lower():
                    potential_vulnerabilities.append(f"Debug info exposed: {url}")
            elif response.status_code in [401, 403, 404]:
                unauthorized_access.append(f"Unauthorized access attempt: {url} (Status code: {response.status_code})")
        except requests.RequestException:
            continue

    return potential_vulnerabilities, unauthorized_access

def display_results(open_ports, permissions_status, running_services, ssl_status, headers_status, vulnerabilities, unauthorized_access):
    table = Table(show_header=True, header_style="bold white", style="white")
    table.add_column("Check Type", justify="center", min_width=25)
    table.add_column("Details", justify="left", min_width=60)

    open_ports_status = ", ".join(map(str, open_ports)) if open_ports else "No open ports found"
    table.add_row("Open Ports", open_ports_status)

    if permissions_status:
        permissions_detail = "\n".join(f"{file}: {status}" for file, status in permissions_status.items())
    else:
        permissions_detail = "File permissions are secure"
    table.add_row("File Permissions", permissions_detail)
    running_services_status = ", ".join(running_services) if running_services else "No insecure services running"
    table.add_row("Running Services", running_services_status)
    table.add_row("SSL Certificate", ssl_status)
    table.add_row("HTTP Headers & Status Code", headers_status)
    vulnerabilities_status = "\n".join(vulnerabilities) if vulnerabilities else "No vulnerabilities found"
    table.add_row("Potential Vulnerabilities", vulnerabilities_status)
    unauthorized_status = "\n".join(unauthorized_access) if unauthorized_access else "No unauthorized access attempts found"
    table.add_row("Unauthorized Access Attempts", unauthorized_status)
    console.print(table)
    console.print("\n[cyan][*] Misconfiguration check completed.[/cyan]")

def main(target):
    host = target
    ports = [21, 22, 25, 80, 443, 3389,8080, 8443]
    services = [
        'telnet', 'ftp', 'http', 'https', 'ssh', 'smtp', 
        'pop3', 'imap', 'dns', 'mysql', 'postgresql', 
        'mongodb', 'redis', 'rmi', 'rpc', 'nginx', 
        'apache2', 'lighttpd', 'iis', 'mysql', 'cassandra', 
        'memcached', 'ftp', 'ftps', 'sftp', 'vnc',
        'http_proxy', 'https_proxy', 'db2', 'oracle', 
        'webmin', 'pma', 'dovecot', 'openvpn', 'git',
        'docker', 'kubernetes', 'k8s', 'rabbitmq', 'zookeeper',
        'solr', 'elasticsearch', 'couchdb', 'cockroachdb', 
        'apache_kafka', 'redis', 'nfs', 'samba', 'smb', 
        'ldap', 'radius', 'tftp', 'netbios', 'snmp', 
        'sqlserver', 'hadoop', 'zookeeper', 'lxc', 'apache',
        'phpmyadmin', 'webdav', 'tacacs', 'wan', 'lan'
    ]
    
    banner()
    console.print(f"[cyan][*] Checking misconfigurations for host: {host}[/cyan]")

    critical_files = [
        '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow', '/etc/hosts',
        '/etc/hostname', '/etc/fstab', '/etc/crontab', '/etc/issue', '/etc/issue.net',
        '/etc/resolv.conf', '/etc/sysctl.conf', '/etc/ssh/sshd_config', '/root/.bashrc',
        '/root/.bash_history', '/var/log/auth.log', '/var/log/secure', '/var/log/messages',
        '/var/log/syslog', '/var/log/wtmp', '/var/log/btmp', '/var/log/lastlog', 
        '/home/*/.ssh/authorized_keys', '/home/*/.bash_history', '/home/*/.bashrc', 
        '/etc/exports', '/etc/sudoers', '/etc/inetd.conf', '/etc/xinetd.conf',
        '/etc/apache2/sites-available/000-default.conf', '/etc/nginx/sites-available/default',
        '/etc/mysql/my.cnf', '/etc/php/7.4/fpm/php.ini', '/etc/php/7.4/apache2/php.ini',
        '/etc/postfix/main.cf', '/etc/ssh/sshd_config', '/etc/default/ufw', 
        '/etc/security/limits.conf', '/etc/pam.d/common-auth', '/etc/pam.d/common-password',
        '/etc/fail2ban/jail.conf', '/etc/fail2ban/jail.local', 
        '/etc/rsyslog.conf', '/etc/network/interfaces', '/etc/netplan/01-netcfg.yaml',
        '/etc/ntp.conf', '/etc/hosts.allow', '/etc/hosts.deny',
        '/var/www/html/index.php', '/etc/systemd/system/*.service', '/etc/systemd/system/multi-user.target.wants/*',
        '/etc/profile', '/etc/bash.bashrc', '/etc/shells', '/etc/init.d/*',
        '/var/lib/mysql/', '/etc/mysql/my.cnf', '/etc/dhcp/dhclient.conf',
        '/etc/ssl/openssl.cnf', '/etc/ssl/certs/ca-certificates.crt'
    ]

    open_ports = check_open_ports(host, ports)
    permissions_status = check_permissions(critical_files)
    running_services = check_services(services)
    ssl_status = check_ssl_certificate(host)
    headers_status = check_http_headers(host)
    vulnerabilities, unauthorized_access = check_for_vulnerabilities(host)

    display_results(open_ports, permissions_status, running_services, ssl_status, headers_status, vulnerabilities, unauthorized_access)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red][!] Please provide a target host.[/red]")
        sys.exit(1)
    
    target_host = sys.argv[1]
    main(target_host)
