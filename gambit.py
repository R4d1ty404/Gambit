import argparse
import re
import sys
import time
from collections import defaultdict
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By

from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)


CLASSIFICATION_MAP = {
    'login': "Access Point (Admin/Login)",
    'upload': "Potential Upload Vector",
    'api': "API Endpoint",
    'register': "Registration Form",
    'download_link': "Data Package (Link)",
    'download_file': "Data Package (File)",
    'js': "[JS] JavaScript File",
    'css': "[CSS] Stylesheet",
    'generic': "Generic Link",
    'config': "Config/Backup File",
    'id_param': "ID Parameter in URL",
}
COLOR_MAP = {
    'login': Fore.RED + Style.BRIGHT,
    'upload': Fore.YELLOW + Style.BRIGHT,
    'api': Fore.BLUE + Style.BRIGHT,
    'register': Fore.MAGENTA,
    'download_link': Fore.GREEN,
    'download_file': Fore.GREEN,
    'js': Fore.WHITE,
    'css': Fore.WHITE,
    'generic': Style.DIM + Fore.WHITE,
    'config': Fore.MAGENTA + Style.BRIGHT,
    'id_param': Fore.MAGENTA + Style.BRIGHT,
}

CLASSIFICATION_RULES = [
    ('login', re.compile(r'login|signin|auth|account|credential|session', re.I)),
    ('upload', re.compile(r'upload|post|submit|new', re.I)),
    ('api', re.compile(r'/api/v[0-9]+|rest/|/json/?$', re.I)),
    ('config', re.compile(r'\.(bak|config|sql|env|ini|old)$', re.I)),
    ('id_param', re.compile(r'[?&](id|user|item|page)=[0-9]+', re.I)),
    ('register', re.compile(r'register|signup', re.I)),
    ('download_file', re.compile(r'\.(pdf|zip|rar|docx|exe|tar\.gz)$', re.I)),
    ('download_link', re.compile(r'download|export|get', re.I)),
    ('js', re.compile(r'\.js$')),
    ('css', re.compile(r'\.css$')),
]


def classify_link(url, anchor_text):
    """Classifies a URL by matching it against a prioritized list of regex patterns."""
    full_string_to_check = url.lower() + " " + anchor_text.lower()
    
    for slug, pattern in CLASSIFICATION_RULES:
        if pattern.search(full_string_to_check):
            return slug
            
    return 'generic'


def setup_driver():
    """Initializes a headless Selenium WebDriver instance."""
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--log-level=3")  # Suppress console logs from Selenium
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
    try:
        # Use webdriver-manager to automatically handle the driver
        driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=chrome_options)
        return driver
    except Exception as e:
        print(f"{Fore.RED}Failed to initialize a WebDriver instance: {e}", file=sys.stderr)
        return None


def scrape_page(url, driver):
    """Scrapes a single page for links in <a> tags, comments, forms, and JS files."""
    reportable_links = set()
    internal_urls_to_crawl = set()
    try:
        driver.get(url)
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        html = driver.page_source
        soup = BeautifulSoup(html, 'html.parser')
        base_domain = urlparse(url).netloc

        links = soup.find_all('a', href=True)
        for link in links:
            href = link.get('href')
            anchor_text = link.get_text(strip=True)
            if not href or href.startswith('#') or href.startswith('javascript:'):
                continue
            absolute_url = urljoin(url, href)
            reportable_links.add((absolute_url, anchor_text, "Anchor Tag"))
            if urlparse(absolute_url).netloc == base_domain:
                internal_urls_to_crawl.add(absolute_url)

        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            # Regex to find things that look like paths or URLs in the comment text
            found_paths = re.findall(r'[\'"](/[^ \'"]+?)[\'"]', comment)
            for path in found_paths:
                absolute_url = urljoin(url, path.strip())
                reportable_links.add((absolute_url, "N/A - Comment", "HTML Comment"))

        forms = soup.find_all('form', action=True)
        for form in forms:
            action_path = form.get('action')
            absolute_url = urljoin(url, action_path.strip())
            reportable_links.add((absolute_url, "N/A - Form Action", "Form Action"))
            if urlparse(absolute_url).netloc == base_domain:
                internal_urls_to_crawl.add(absolute_url)
        
        js_links = [script.get('src') for script in soup.find_all('script') if script.get('src')]
        for js_link in js_links:
            absolute_js_url = urljoin(url, js_link)
            if urlparse(absolute_js_url).netloc == base_domain:
                try:
                    # Temporarily navigate to the JS file to get its content
                    driver.get(absolute_js_url)
                    js_content = driver.find_element(By.TAG_NAME, 'pre').text
                    # Regex for relative paths in JS: /path/to/endpoint
                    js_paths = re.findall(r'[\'"](/[^ \'"]+?)[\'"]', js_content)
                    for path in js_paths:
                        if path.endswith(('.js', '.css', '.png', '.jpg')): continue # Ignore assets
                        js_absolute_url = urljoin(url, path.strip())
                        reportable_links.add((js_absolute_url, "N/A - JS Content", "JavaScript File"))
                except Exception:
                    continue

    except Exception:
        pass
    return reportable_links, internal_urls_to_crawl


def worker(url):
    """A single worker that initializes a driver, scrapes a page, and quits."""
    print(f"{Fore.CYAN}Crawling:{Style.RESET_ALL} {url}")
    driver = setup_driver()
    if driver:
        try:
            report_links, new_urls = scrape_page(url, driver)
            return url, report_links, new_urls
        finally:
            driver.quit()
    return url, set(), set()


def crawler(start_url, max_depth, num_workers, output_file, filters, html_report_file):
    urls_to_visit = {start_url}
    visited_urls = set()
    found_links_info = set()
    
    for depth in range(max_depth + 1):
        if not urls_to_visit:
            break
            
        print(f"\n{Fore.YELLOW}--- Starting Crawl at Depth {depth} ({len(urls_to_visit)} URLs) ---")
        
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            future_to_url = {executor.submit(worker, url): url for url in urls_to_visit}
            
            next_level_urls = set()
            for future in as_completed(future_to_url):
                original_url, report_links, new_urls = future.result()
                visited_urls.add(original_url)
                found_links_info.update(report_links)
                next_level_urls.update(new_urls)
        
        urls_to_visit = next_level_urls - visited_urls

    grouped_links = defaultdict(list)
    for url, text, source in found_links_info:
        link_type_slug = classify_link(url, text)
        grouped_links[link_type_slug].append((text, url, source))

    print(f"\n{Fore.YELLOW}Generating Crawl Report...")
    for slug in sorted(grouped_links.keys()):
        header_text = CLASSIFICATION_MAP.get(slug, "Unknown Category")
        header_color = COLOR_MAP.get(slug, Fore.WHITE)
        print(f"\n--- [ {header_color}{header_text}{Style.RESET_ALL} ] ---")
        links_in_group = sorted(grouped_links[slug], key=lambda item: item[1])
        for text, url, source in links_in_group:
            print(f"  -> Source: {source} | Text: '{text}'\n     {Fore.GREEN}URL: {url}{Style.RESET_ALL}")
            
    if output_file and filters:
        urls_to_save = []
        if 'all' in filters:
            all_links = sorted(list(found_links_info))
            urls_to_save = [url for url, text, source in all_links]
        else:
            for slug in filters:
                links_in_group = grouped_links.get(slug, [])
                # THIS IS THE CORRECTED LINE:
                for text, url, source in links_in_group:
                    urls_to_save.append(url)
            urls_to_save = sorted(list(set(urls_to_save)))
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(urls_to_save))
            print(f"\n\n{Fore.GREEN}Filtered URLs successfully saved to {output_file}")
        except IOError as e:
            print(f"\n\n{Fore.RED}Error writing to file {output_file}: {e}", file=sys.stderr)

    if html_report_file:
        generate_html_report(found_links_info, start_url, html_report_file)

def generate_html_report(found_links_info, start_url, filename):
    """Generates an interactive HTML report with search and sort functionality."""
    
    print(f"{Fore.YELLOW}Generating HTML report...")
    
    grouped_links = defaultdict(list)
    for url, text, source in found_links_info:
        link_type_slug = classify_link(url, text)
        grouped_links[link_type_slug].append((text, url, source))

    # BUG FIX: Doubled up all curly braces in the <style> block to escape them
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Gambit Crawl Report</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; background-color: #1a1a1a; color: #e0e0e0; margin: 0; padding: 20px; }}
            h1 {{ color: #00aaff; border-bottom: 2px solid #00aaff; padding-bottom: 10px; }}
            h2 {{ color: #e0e0e0; background-color: #333; padding: 10px; border-left: 5px solid; margin-top: 40px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 0.9em; }}
            th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #444; word-break: break-all; }}
            th {{ background-color: #00aaff; color: #1a1a1a; cursor: pointer; }}
            tr:nth-child(even) {{ background-color: #2a2a2a; }}
            a {{ color: #61dafb; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
            .search-bar {{ width: 100%; padding: 10px; margin-bottom: 20px; background-color: #333; border: 1px solid #555; color: #e0e0e0; font-size: 1.2em; }}
            .color-login {{ border-color: #ff4d4d; }}
            .color-upload {{ border-color: #ffff66; }}
            .color-api {{ border-color: #66b3ff; }}
            .color-config {{ border-color: #ff80ff; }}
            .color-id_param {{ border-color: #4dd2ff; }}
            .color-register {{ border-color: #ff80ff; }}
            .color-generic {{ border-color: #888; }}
        </style>
    </head>
    <body>
        <h1>Gambit Crawl Report</h1>
        <p><strong>Target:</strong> <a href="{start_url}" target="_blank">{start_url}</a></p>
        <p><strong>Generated on:</strong> {report_date}</p>
        <input type="text" id="searchInput" class="search-bar" onkeyup="filterTable()" placeholder="Search for URLs, text, or source...">

        {report_body}

        <script>
            function filterTable() {{
                let input = document.getElementById("searchInput");
                let filter = input.value.toUpperCase();
                let tables = document.getElementsByTagName("table");
                for (let t = 0; t < tables.length; t++) {{
                    let tr = tables[t].getElementsByTagName("tr");
                    for (let i = 1; i < tr.length; i++) {{
                        let display = "none";
                        let td = tr[i].getElementsByTagName("td");
                        for (let j = 0; j < td.length; j++) {{
                            if (td[j]) {{
                                if (td[j].innerText.toUpperCase().indexOf(filter) > -1) {{
                                    display = "";
                                    break;
                                }}
                            }}
                        }}
                        tr[i].style.display = display;
                    }}
                }}
            }}
            function sortTable(n, tableId) {{
                let table = document.getElementById(tableId);
                let switching = true, shouldSwitch, i;
                let dir = "asc";
                let switchcount = 0;
                while (switching) {{
                    switching = false;
                    let rows = table.rows;
                    for (i = 1; i < (rows.length - 1); i++) {{
                        shouldSwitch = false;
                        let x = rows[i].getElementsByTagName("TD")[n];
                        let y = rows[i + 1].getElementsByTagName("TD")[n];
                        let xContent = x.innerHTML.toLowerCase();
                        let yContent = y.innerHTML.toLowerCase();
                        if (dir == "asc") {{
                            if (xContent > yContent) {{
                                shouldSwitch = true;
                                break;
                            }}
                        }} else if (dir == "desc") {{
                            if (xContent < yContent) {{
                                shouldSwitch = true;
                                break;
                            }}
                        }}
                    }}
                    if (shouldSwitch) {{
                        rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                        switching = true;
                        switchcount++;
                    }} else {{
                        if (switchcount == 0 && dir == "asc") {{
                            dir = "desc";
                            switching = true;
                        }}
                    }}
                }}
            }}
        </script>
    </body>
    </html>
    """
    
    report_body = ""
    color_slugs = {
        'login': 'color-login', 'upload': 'color-upload', 'api': 'color-api',
        'config': 'color-config', 'id_param': 'color-id_param', 'register': 'color-register',
        'generic': 'color-generic'
    }
    
    for slug in sorted(grouped_links.keys()):
        header_text = CLASSIFICATION_MAP.get(slug, "Unknown Category")
        color_class = color_slugs.get(slug, "")
        
        table_id = re.sub(r'[^a-zA-Z0-9]', '', header_text)
        
        report_body += f'<h2 class="{color_class}">{header_text}</h2>'
        report_body += f'<table id="{table_id}">'
        report_body += f'<thead><tr><th onclick="sortTable(0, \'{table_id}\')">Source</th><th onclick="sortTable(1, \'{table_id}\')">Anchor Text</th><th onclick="sortTable(2, \'{table_id}\')">URL</th></tr></thead><tbody>'
        
        links_in_group = sorted(grouped_links[slug], key=lambda item: item[1])
        for text, url, source in links_in_group:
            report_body += f'<tr><td>{source}</td><td>{text}</td><td><a href="{url}" target="_blank">{url}</a></td></tr>'
        
        report_body += '</tbody></table>'

    final_html = html_template.format(
        start_url=start_url,
        report_date=time.strftime("%Y-%m-%d %H:%M:%S"),
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
    print(f"{Fore.WHITE}      A Link Reconnaissance Tool - Author Raditya P Putra\n")

    parser = argparse.ArgumentParser(
        description="A high-performance, JS-aware crawler to find and classify links.",
        epilog="Example: python gambit.py https://example.com -d 1 -w 5 -o urls.txt -f login api --html report.html"
    )
    available_filters = list(CLASSIFICATION_MAP.keys()) + ['all']
    help_choices_str = ", ".join(available_filters)
    parser.add_argument("url", help="The starting URL to crawl.")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Maximum crawl depth.")
    parser.add_argument("-o", "--output", help="Save the output to a specified file.")
    parser.add_argument("--html", help="Generate and save an interactive HTML report.")
    parser.add_argument("-w", "--workers", type=int, default=4, help="Number of parallel threads.")
    parser.add_argument(
        "-f", "--filter",
        nargs='+',
        choices=available_filters,
        metavar='FILTER',
        help=f"Filter results to save. Use 'all' to save all URLs. "
             f"Available choices: {help_choices_str}"
    )
    args = parser.parse_args()
    crawler(args.url, args.depth, args.workers, args.output, args.filter, args.html)

if __name__ == "__main__":
    main()