import argparse
import re
import sys
import time
import asyncio
from collections import defaultdict
from urllib.parse import urljoin, urlparse
import aiohttp
import os
import pickle

from playwright.async_api import async_playwright, Error

from bs4 import BeautifulSoup, Comment
from colorama import Fore, Style, init

init(autoreset=True)

# --- MAPS & RULES ---
CLASSIFICATION_MAP = { 
    'login': "Access Point (Admin/Login)", 
    'upload': "Potential Upload Vector", 
    'api': "API Endpoint", 'config': "Config/Backup File", 
    'id_param': "ID Parameter in URL", 
    'register': "Registration Form", 
    'download_link': "Data Package (Link)", 
    'download_file': "Data Package (File)", 
    'js': "JavaScript File", 
    'css': "Stylesheet", 
    'generic': "Generic Link", 
    'media': "Media File" 
}
COLOR_MAP = { 
    'login': Fore.RED + Style.BRIGHT, 
    'upload': Fore.YELLOW + Style.BRIGHT, 
    'api': Fore.BLUE + Style.BRIGHT, 
    'config': Fore.MAGENTA + Style.BRIGHT, 
    'id_param': Fore.CYAN + Style.BRIGHT, 
    'register': Fore.MAGENTA, 
    'download_link': Fore.GREEN, 
    'download_file': Fore.GREEN, 
    'js': Fore.WHITE, 
    'css': Fore.WHITE, 
    'generic': Style.DIM + Fore.WHITE, 
    'media': Style.DIM + Fore.WHITE 
}
CLASSIFICATION_RULES = [ 
    ('config', re.compile(r'\.(bak|config|sql|env|ini|old)$', re.I)), 
    ('login', re.compile(r'login|signin|auth|account|credential|session', re.I)), 
    ('upload', re.compile(r'upload|post|submit|new', re.I)), 
    ('id_param', re.compile(r'[?&](id|user|item|page|file|path)=[0-9a-zA-Z_-]+', re.I)), 
    ('api', re.compile(r'/api/v[0-9]+|rest/|/json/?$', re.I)), 
    ('register', re.compile(r'register|signup', re.I)), 
    ('download_file', re.compile(r'\.(pdf|zip|rar|docx|exe|tar\.gz)$', re.I)), 
    ('download_link', re.compile(r'download|export|get', re.I)), 
    ('js', re.compile(r'\.js')), ('css', re.compile(r'\.css')), 
    ('media', re.compile(r'\.(png|jpg|jpeg|gif|svg|mp4|webm)$', re.I)), 
]
JS_FINGERPRINTS = [
    {'name': 'jquery', 'pattern': re.compile(r"jQuery v?([0-9]+\.[0-9]+\.[0-9]+)")},
    {'name': 'handlebars', 'pattern': re.compile(r"Handlebars\.VERSION = \"([0-9]+\.[0-9]+\.[0-9]+)\"")},
]


def classify_link(url, anchor_text):
    full_string_to_check = url.lower() + " " + anchor_text.lower()
    for slug, pattern in CLASSIFICATION_RULES:
        if pattern.search(full_string_to_check): return slug
    return 'generic'

async def check_js_vulnerabilities(found_js, session):
    vulnerabilities = []
    for lib_name, version, url in found_js:
        query = {"version": version, "package": {"name": lib_name, "ecosystem": "npm"}}
        try:
            async with session.post("https://api.osv.dev/v1/query", json=query) as response:
                if response.status == 200:
                    results = await response.json()
                    if "vulns" in results:
                        for vuln in results["vulns"]:
                            vuln_id = vuln.get("aliases", [vuln.get("id", "N/A")])[0]
                            vulnerabilities.append((lib_name, version, url, vuln_id))
        except Exception: continue
    return vulnerabilities

async def scrape_page(page, url, main_domain):
    reportable_links, internal_urls_to_crawl, found_subdomains, found_js_versions = set(), set(), set(), set()
    try:
        await page.goto(url, wait_until='domcontentloaded', timeout=15000)
        html = await page.content()
        soup = BeautifulSoup(html, 'html.parser')
        current_netloc = urlparse(url).netloc
        def process_url(path, text, source):
            if not path or path.startswith(('#', 'javascript:', 'mailto:')): return
            absolute_url = urljoin(url, path); parsed_url = urlparse(absolute_url); link_netloc = parsed_url.netloc
            if link_netloc.endswith(main_domain) and link_netloc != main_domain and link_netloc != current_netloc:
                found_subdomains.add(link_netloc)
            reportable_links.add((absolute_url, text, source))
            if link_netloc == current_netloc: internal_urls_to_crawl.add(absolute_url)
        for a in soup.find_all('a', href=True): process_url(a.get('href'), a.get_text(strip=True), "Anchor Tag")
        for form in soup.find_all('form', action=True): process_url(form.get('action'), "N/A - Form", "Form Action")
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            for path in re.findall(r'[\'"](/[^ \'"]+?)[\'"]', comment): process_url(path, "N/A - Comment", "HTML Comment")
        for tag in soup.find_all(['img', 'script'], src=True):
            process_url(tag['src'], "N/A - src", f"{tag.name} (src)")
        for tag in soup.find_all('link', href=True):
            process_url(tag['href'], "N/A - href", f"{tag.name} (href)")
        for script in soup.find_all('script'):
            if not script.get('src') and script.string:
                for fingerprint in JS_FINGERPRINTS:
                    if (match := fingerprint['pattern'].search(script.string)):
                        found_js_versions.add((fingerprint['name'], match.group(1), url))
    except Error as e:
        print(f"{Fore.YELLOW}  -> Playwright error on {url}: {e.message.splitlines()[0]}{Style.RESET_ALL}")
    return reportable_links, internal_urls_to_crawl, found_subdomains, found_js_versions

async def worker(context, url, main_domain, session):
    page = await context.new_page()
    try:
        print(f"{Fore.CYAN}Crawling:{Style.RESET_ALL} {url}")
        report_links_tuples, new_urls, subdomains, js_versions = await scrape_page(page, url, main_domain)
        final_report_links = set()
        for found_url, anchor_text, source in report_links_tuples:
            status_code = "ERR"; content_type = "N/A"
            try:
                async with session.head(found_url, timeout=5, allow_redirects=True) as response:
                    status_code = response.status; content_type = response.headers.get('Content-Type', 'N/A').split(';')[0]
            except Exception: pass
            final_report_links.add((found_url, anchor_text, source, status_code, content_type))
        return final_report_links, new_urls, subdomains, js_versions
    finally:
        await page.close()

async def crawler(start_url, max_depth, concurrency, output_file, filters, html_report_file, cookies, session_file):
    if session_file and os.path.exists(session_file):
        print(f"{Fore.YELLOW}Resuming session from {session_file}...{Style.RESET_ALL}")
        with open(session_file, 'rb') as f:
            saved_state = pickle.load(f)
            urls_to_visit = saved_state.get('urls_to_visit', {start_url})
            visited_urls = saved_state.get('visited_urls', set())
            found_links_info = saved_state.get('found_links_info', set())
            discovered_subdomains = saved_state.get('discovered_subdomains', set())
            found_js_versions = saved_state.get('found_js_versions', set())
    else:
        urls_to_visit, visited_urls, found_links_info, discovered_subdomains, found_js_versions = {start_url}, set(), set(), set(), set()

    try:
        main_domain = '.'.join(urlparse(start_url).netloc.split('.')[-2:])
    except IndexError:
        print(f"{Fore.RED}Invalid start URL: '{start_url}'"); return
    
    async with async_playwright() as p, aiohttp.ClientSession() as session:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        if cookies:
            cookie_list = [{'name': c.split('=', 1)[0], 'value': c.split('=', 1)[1], 'url': start_url} for c in cookies]
            await context.add_cookies(cookie_list)
        
        for depth in range(max_depth + 1):
            if not urls_to_visit: break
            print(f"\n{Fore.YELLOW}--- Starting Crawl at Depth {depth} ({len(urls_to_visit)} URLs) using {concurrency} concurrent tasks ---")
            tasks = [worker(context, url, main_domain, session) for url in urls_to_visit]
            visited_urls.update(urls_to_visit)
            next_level_urls = set()
            for future in asyncio.as_completed(tasks):
                report_links, new_urls, subdomains, js_from_page = await future
                found_links_info.update(report_links); next_level_urls.update(new_urls); discovered_subdomains.update(subdomains); found_js_versions.update(js_from_page)
            urls_to_visit = next_level_urls - visited_urls
            if session_file:
                with open(session_file, 'wb') as f:
                    pickle.dump({'urls_to_visit': urls_to_visit, 'visited_urls': visited_urls, 'found_links_info': found_links_info, 'discovered_subdomains': discovered_subdomains, 'found_js_versions': found_js_versions}, f)
                print(f"{Fore.GREEN}  -> Progress saved to {session_file}{Style.RESET_ALL}")
        
        js_from_src = set()
        version_regex = re.compile(r"([a-zA-Z0-9.-]+?)[-_.]v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)")
        for url, text, source, status, content_type in found_links_info:
            if classify_link(url, text) == 'js':
                if match := version_regex.search(urlparse(url).path.split('/')[-1]):
                    lib_name, version = match.groups(); lib_name = lib_name.lower().replace('.min', '').strip('.-_')
                    if 'bootstrap' in lib_name: lib_name = 'bootstrap'
                    js_from_src.add((lib_name, version, url))
        
        all_found_js = js_from_src.union(found_js_versions)
        found_vulnerabilities = []
        if all_found_js:
            print(f"\n{Fore.CYAN}Checking {len(all_found_js)} discovered JavaScript libraries via OSV API...{Style.RESET_ALL}")
            found_vulnerabilities = await check_js_vulnerabilities(all_found_js, session)
        
        await browser.close()
    
    grouped_links = defaultdict(list)
    for url, text, source, status, content_type in found_links_info:
        grouped_links[classify_link(url, text)].append((text, url, source, status, content_type))
    
    print(f"\n{Fore.YELLOW}Generating Crawl Report...")
    if found_vulnerabilities:
        print(f"\n--- [ {Fore.RED + Style.BRIGHT}VULNERABILITIES FOUND{Style.RESET_ALL} ] ---")
        for lib, version, url, cve in found_vulnerabilities:
            print(f"  -> {Fore.YELLOW}Library:{Style.RESET_ALL} {lib} @ {version}\n     {Fore.RED}ID:{Style.RESET_ALL} {cve}\n     {Fore.GREEN}URL:{Style.RESET_ALL} {url}")
    
    for slug in sorted(grouped_links.keys()):
        header_text = CLASSIFICATION_MAP.get(slug, "Unknown Category"); header_color = COLOR_MAP.get(slug, Fore.WHITE)
        print(f"\n--- [ {header_color}{header_text}{Style.RESET_ALL} ] ---")
        for text, url, source, status, content_type in sorted(grouped_links[slug], key=lambda item: item[1]):
            status_color = Fore.GREEN if status == 200 else (Fore.YELLOW if str(status).startswith('3') else Fore.RED)
            print(f"  -> [{status_color}{status}{Style.RESET_ALL}] Type: {content_type} | Source: {source} | Text: '{text}'\n       {Fore.GREEN}URL: {url}{Style.RESET_ALL}")
    
    if discovered_subdomains:
        print(f"\n--- [ {Fore.CYAN + Style.BRIGHT}Discovered Subdomains{Style.RESET_ALL} ] ---")
        for subdomain in sorted(list(discovered_subdomains)): print(f"  -> {subdomain}")
            
    if output_file and filters:
        urls_to_save = [url for url, *rest in sorted(list(found_links_info))] if 'all' in filters else sorted(list(set(url for slug in filters for text, url, *rest in grouped_links.get(slug, []))))
        try:
            with open(output_file, 'w', encoding='utf-8') as f: f.write('\n'.join(urls_to_save))
            print(f"\n\n{Fore.GREEN}Filtered URLs successfully saved to {output_file}")
        except IOError as e: print(f"\n\n{Fore.RED}Error writing to file {output_file}: {e}", file=sys.stderr)

    if html_report_file:
        generate_html_report(found_links_info, discovered_subdomains, found_vulnerabilities, start_url, html_report_file)

def generate_html_report(found_links_info, discovered_subdomains, found_vulnerabilities, start_url, filename):
    
    print(f"{Fore.YELLOW}Generating HTML report...")
    
    vulnerabilities_html = ""
    if found_vulnerabilities:
        vulnerabilities_html = "<h2>Vulnerabilities Found</h2><table>"
        vulnerabilities_html += "<thead><tr><th>Library</th><th>Version</th><th>Vulnerability ID</th><th>URL</th></tr></thead><tbody>"
        for lib, version, url, cve in sorted(found_vulnerabilities):
            vulnerabilities_html += f'<tr><td>{lib}</td><td>{version}</td><td>{cve}</td><td><a href="{url}" target="_blank">{url}</a></td></tr>'
        vulnerabilities_html += "</tbody></table>"

    subdomain_html = ""
    if discovered_subdomains:
        subdomain_html = "<h2>Discovered Subdomains</h2><ul>"
        for subdomain in sorted(list(discovered_subdomains)):
            subdomain_html += f"<li><a href='http://{subdomain}' target='_blank'>{subdomain}</a></li>"
        subdomain_html += "</ul>"
    
    grouped_links = defaultdict(list)
    for url, text, source, status, content_type in found_links_info:
        grouped_links[classify_link(url, text)].append((text, url, source, status, content_type))
    
    report_body = ""
    color_slugs = { 'login': 'color-login', 'upload': 'color-upload', 'api': 'color-api', 'config': 'color-config', 'id_param': 'color-id_param', 'register': 'color-register', 'generic': 'color-generic', 'js': 'color-js', 'css': 'color-css', 'media': 'color-media', 'download_link': 'color-download', 'download_file': 'color-download' }
    
    for slug in sorted(grouped_links.keys()):
        header_text = CLASSIFICATION_MAP.get(slug, "Unknown Category")
        color_class = color_slugs.get(slug, "")
        table_id = re.sub(r'[^a-zA-Z0-9]', '', header_text)
        
        report_body += f'<h2 class="{color_class}">{header_text}</h2><table id="{table_id}">'
        report_body += f'<thead><tr><th onclick="sortTable(0, \'{table_id}\')">Status</th><th onclick="sortTable(1, \'{table_id}\')">Content-Type</th><th onclick="sortTable(2, \'{table_id}\')">Source</th><th onclick="sortTable(3, \'{table_id}\')">Anchor Text</th><th onclick="sortTable(4, \'{table_id}\')">URL</th></tr></thead><tbody>'
        for text, url, source, status, content_type in sorted(grouped_links[slug], key=lambda item: item[1]):
            status_class = "status-ok" if status == 200 else ("status-redirect" if str(status).startswith('3') else "status-error")
            report_body += f'<tr><td class="{status_class}">{status}</td><td>{content_type}</td><td>{source}</td><td>{text}</td><td><a href="{url}" target="_blank">{url}</a></td></tr>'
        report_body += '</tbody></table>'

    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Gambit Crawl Report</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; background-color: #1a1a1a; color: #e0e0e0; margin: 0; padding: 20px; }}
            h1 {{ color: #00aaff; border-bottom: 2px solid #00aaff; padding-bottom: 10px; }}
            h2 {{ color: #e0e0e0; background-color: #333; padding: 10px; border-left: 5px solid; margin-top: 40px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 0.9em; }}
            th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #444; word-break: break-all; }}
            th {{ background-color: #00aaff; color: #1a1a1a; cursor: pointer; }}
            tr:nth-child(even) {{ background-color: #2a2a2a; }}
            a {{ color: #61dafb; text-decoration: none; }} a:hover {{ text-decoration: underline; }}
            .search-bar {{ width: 100%; padding: 10px; margin-bottom: 20px; background-color: #333; border: 1px solid #555; color: #e0e0e0; font-size: 1.2em; }}
            ul {{ list-style-type: none; padding-left: 0; }} li {{ background-color: #2a2a2a; padding: 10px; border-left: 3px solid #61dafb; margin-bottom: 5px; }}
            .status-ok {{ color: #77dd77; }} .status-redirect {{ color: #fdfd96; }} .status-error {{ color: #ff6961; }}
            .color-login {{ border-color: #ff6961; }} .color-upload {{ border-color: #fdfd96; }} .color-api {{ border-color: #80bfff; }}
            .color-config {{ border-color: #ff80ff; }} .color-id_param {{ border-color: #4dd2ff; }} .color-register {{ border-color: #ff80ff; }}
            .color-generic, .color-js, .color-css, .color-media {{ border-color: #888; }} .color-download {{ border-color: #77dd77; }}
        </style>
    </head>
    <body>
        <h1>Gambit Crawl Report</h1>
        <p><strong>Target:</strong> <a href="{start_url}" target="_blank">{start_url}</a></p>
        <p><strong>Generated on:</strong> {report_date}</p>
        <input type="text" id="searchInput" class="search-bar" onkeyup="filterTable()" placeholder="Search for anything...">

        {vulnerabilities_section}
        {subdomain_section}
        {report_body}

        <script>
            function filterTable() {{
                let input = document.getElementById("searchInput"); let filter = input.value.toUpperCase();
                let tables = document.getElementsByTagName("table");
                for (let t = 0; t < tables.length; t++) {{
                    let tr = tables[t].getElementsByTagName("tr");
                    for (let i = 1; i < tr.length; i++) {{
                        let display = "none"; let td = tr[i].getElementsByTagName("td");
                        for (let j = 0; j < td.length; j++) {{ if (td[j] && td[j].innerText.toUpperCase().indexOf(filter) > -1) {{ display = ""; break; }} }}
                        tr[i].style.display = display;
                    }}
                }}
            }}
            function sortTable(n, tableId) {{
                let table = document.getElementById(tableId); let switching = true, shouldSwitch, i, dir = "asc", switchcount = 0;
                while (switching) {{
                    switching = false; let rows = table.rows;
                    for (i = 1; i < (rows.length - 1); i++) {{
                        shouldSwitch = false;
                        let x = rows[i].getElementsByTagName("TD")[n]; let y = rows[i + 1].getElementsByTagName("TD")[n];
                        if (dir == "asc") {{ if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {{ shouldSwitch = true; break; }}
                        }} else if (dir == "desc") {{ if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {{ shouldSwitch = true; break; }} }}
                    }}
                    if (shouldSwitch) {{
                        rows[i].parentNode.insertBefore(rows[i + 1], rows[i]); switching = true; switchcount++;
                    }} else {{ if (switchcount == 0 && dir == "asc") {{ dir = "desc"; switching = true; }} }}
                }}
            }}
        </script>
    </body>
    </html>
    """
    
    final_html = html_template.format(
        start_url=start_url,
        report_date=time.strftime("%Y-%m-%d %H:%M:%S"),
        vulnerabilities_section=vulnerabilities_html,
        subdomain_section=subdomain_html,
        report_body=report_body
    )
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(final_html)
        print(f"\n{Fore.GREEN}Interactive HTML report saved to {filename}")
    except IOError as e:
        print(f"\n{Fore.RED}Error writing HTML report: {e}", file=sys.stderr)

def main():
    banner = r"""
 ▄████  ▄▄▄       ███▄ ▄███▓ ▄▄▄▄    ██▓▄▄▄█████▓
 ██▒ ▀█▒▒████▄    ▓██▒▀█▀ ██▒▓█████▄ ▓██▒▓  ██▒ ▓▒
▒██░▄▄▄░▒██  ▀█▄  ▓██    ▓██░▒██▒ ▄██▒██▒▒ ▓██░ ▒░
░▓█  ██▓░██▄▄▄▄██ ▒██    ▒██ ▒██░█▀  ░██░░ ▓██▓ ░ 
░▒▓███▀▒ ▓█   ▓██▒▒██▒   ░██▒░▓█  ▀█▓░██░  ▒██▒ ░ 
 ░▒   ▒  ▒▒   ▓▒█░░ ▒░   ░  ░░▒▓███▀▒░▓    ▒ ░░   
  ░   ░   ▒   ▒▒ ░░  ░      ░▒░▒   ░  ▒ ░    ░    
░ ░   ░   ░   ▒   ░         ░  ░   ░  ▒ ░  ░      
      ░       ░  ░          ░      ░            
                                 ░              
    """
    print(Fore.CYAN + Style.BRIGHT + banner)
    print(f"{Fore.WHITE}A Link Reconnaissance Tool - Author https://github.com/R4d1ty404/Gambit\n")

    parser = argparse.ArgumentParser(
        description="A high-performance, JS-aware crawler to find and classify links.",
        epilog="Example: python gambit.py https://example.com -d 1 -c 55 -o urls.txt -f login api --html report.html --cookie 'sessionid=abc123xyz'"
    )
    available_filters = list(CLASSIFICATION_MAP.keys()) + ['all']
    help_choices_str = ", ".join(available_filters)
    parser.add_argument("url", help="The starting URL to crawl.")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Maximum crawl depth.")
    parser.add_argument("-o", "--output", help="Save the output to a specified file.")
    parser.add_argument("--html", help="Generate and save an interactive HTML report.")
    parser.add_argument("-c", "--concurrency", type=int, default=50, help="Number of concurrent tasks. Default is 50.")
    parser.add_argument("--session", help="Save and resume crawl state from a session file (e.g., scan.pkl).")
    parser.add_argument(
        "-f", "--filter",
        nargs='+',
        choices=available_filters,
        metavar='FILTER',
        help=f"Filter results to save. Use 'all' to save all URLs. "
             f"Available choices: {help_choices_str}"
    )
    parser.add_argument(
        "--cookie",
        nargs='+',
        help="Add session cookies for authentication. Format: 'name=value'. Can be used multiple times."
    )
    args = parser.parse_args()
    asyncio.run(crawler(args.url, args.depth, args.concurrency, args.output, args.filter, args.html, args.cookie, args.session))

if __name__ == "__main__":
    import os
    main()