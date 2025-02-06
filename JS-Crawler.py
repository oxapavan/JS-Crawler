import os
import re
import hashlib
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from time import sleep
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)

# Create a session to reuse connections for better performance
session = requests.Session()

def fetch_page(url, cookies=None, retries=3, delay=5):
    """Fetch the content of a webpage with retries."""
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"}
    
    session.headers.update(headers)
    session.cookies.update(cookies or {})
    
    for attempt in range(retries):
        try:
            print(Fore.YELLOW + f"Attempting to fetch {url} (Attempt {attempt + 1})...")
            response = session.get(url, timeout=30, allow_redirects=True)
            response.raise_for_status()
            print(Fore.GREEN + "Page fetched successfully!")
            return response.text
        except requests.Timeout:
            print(Fore.RED + f"Attempt {attempt + 1} timed out.")
        except requests.RequestException as e:
            print(Fore.RED + f"Attempt {attempt + 1} failed: {e}")
        
        if attempt < retries - 1:
            print(Fore.CYAN + f"Retrying in {delay} seconds...")
            sleep(delay)
        else:
            print(Fore.RED + "All retries failed.")
    return None

def extract_js_files(html, base_url):
    """Extract JavaScript file URLs from the HTML content."""
    soup = BeautifulSoup(html, 'html.parser')
    js_files = []

    for script_tag in soup.find_all('script', src=True):
        js_url = urljoin(base_url, script_tag['src'])
        js_files.append(js_url)

    return js_files

def sanitize_filename(url):
    """Create a safe and shortened filename from a URL."""
    hash_value = hashlib.md5(url.encode()).hexdigest()
    return f"{hash_value}.js"

def download_js_file(js_url, output_dir):
    """Download a single JavaScript file."""
    try:
        print(Fore.YELLOW + f"Downloading: {js_url}")
        response = session.get(js_url, timeout=30, allow_redirects=True)
        response.raise_for_status()

        filename = sanitize_filename(js_url)
        filepath = os.path.join(output_dir, filename)

        if os.path.exists(filepath):
            print(Fore.CYAN + f"File {filename} already exists, skipping download.")
            return

        # Save the JavaScript file with a comment containing the original URL
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"// Original URL: {js_url}\n\n")
            f.write(response.text)
        
        print(Fore.GREEN + f"Downloaded: {js_url} as {filename}")
        return filepath
    except requests.RequestException as e:
        print(Fore.RED + f"Failed to download {js_url}: {e}")
        return None

def download_js_files(js_files, output_dir):
    """Download JavaScript files in parallel."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    downloaded_files = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        # Use list comprehension to collect downloaded file paths
        downloaded_files = list(filter(None, list(executor.map(lambda url: download_js_file(url, output_dir), js_files))))
    
    return downloaded_files

def find_subdomains(domain):
    """Find all subdomains for a given domain using crt.sh."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        subdomains = set()
        for entry in data:
            subdomains.add(entry['name_value'].lower())
        return list(subdomains)
    except requests.RequestException as e:
        print(Fore.RED + f"Failed to fetch subdomains: {e}")
        return []

def scan_for_sensitive_keywords(directory):
    """
    Recursively scan JavaScript files for sensitive keywords and patterns.
    
    Args:
        directory (str): Path to the directory containing JavaScript files
    
    Returns:
        dict: A dictionary containing file paths and their matched sensitive patterns
    """
    # Comprehensive regex patterns inspired by the Go regex patterns
    sensitive_patterns = {
        'Cloud & API Credentials': [
            (r'AIza[0-9A-Za-z-_]{35}', 'Google API Key'),
            (r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', 'Firebase Token'),
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID'),
            (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe API Key'),
            (r'xoxb-[A-Za-z0-9-]{24,34}', 'Slack Bot Token'),
            (r'pk_live_[0-9a-zA-Z]{24}', 'Stripe Publishable Key'),
            (r'ya29\.[0-9A-Za-z\-_]+', 'Google OAuth Access Token'),
            (r'sq0csp-[0-9A-Za-z\-_]{43}', 'Square OAuth Secret'),
            (r'sq0atp-[0-9A-Za-z\-_]{22}', 'Square Access Token')
        ],
        'Authorization Tokens': [
            (r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}', 'Bearer Token'),
            (r'Basic [a-zA-Z0-9=:_\+\/-]{5,100}', 'Basic Auth Token'),
            (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token'),
            (r'glpat-[A-Za-z0-9\-]{20}', 'GitLab Personal Access Token'),
            (r'[hH]eroku[a-zA-Z0-9]{32}', 'Heroku API Key'),
            (r'\bghp_[a-zA-Z0-9]{36}\b', 'GitHub Token'),
            (r'xoxp-[A-Za-z0-9-]{24,34}', 'Slack User Token')
        ],
        'Private Keys': [
            (r'-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key'),
            (r'-----BEGIN OPENSSH PRIVATE KEY-----', 'OpenSSH Private Key'),
            (r'-----BEGIN EC PRIVATE KEY-----', 'EC Private Key'),
            (r'-----BEGIN DSA PRIVATE KEY-----', 'DSA Private Key'),
            (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP Private Key'),
            (r'PuTTY-User-Key-File-2.*?-----END', 'PuTTY Private Key')
        ],
        'Sensitive Information': [
            (r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Email Address'),
            (r'\b\+\d{9,14}\b', 'Phone Number'),
            (r'username=|password=', 'Potential Credential Indicators'),
            (r'[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["\'\s]', 'Credentials in URL')
        ],
        'Web Service Credentials': [
            (r'https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+', 'Slack Webhook'),
            (r'https://discord(?:app)?\.com/api/webhooks/[0-9]{18,20}/[A-Za-z0-9_-]{64,}', 'Discord Webhook'),
            (r'sq0atp-[0-9A-Za-z\-_]{22}', 'Square Access Token'),
            (r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}', 'SendGrid API Key'),
            (r'sk_[A-Za-z0-9]{32}', 'Segment Write Key')
        ],
        'OAuth & Client Secrets': [
            (r'"client_secret":"[a-zA-Z0-9-_]{24}"', 'OAuth Client Secret'),
            (r'\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b', 'Google OAuth Client'),
            (r'[A-Za-z0-9]{20,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{25,}', 'Atlassian Access Token')
        ],
        'Additional Token Types': [
            (r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}', 'Discord Bot Token'),
            (r'sk_live_[0-9a-z]{32}', 'Picatic API Key'),
            (r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}', 'PayPal Braintree Access Token'),
            (r'00[a-zA-Z0-9]{30}\.[a-zA-Z0-9\-_]{30,}\.[a-zA-Z0-9\-_]{30,}', 'Okta API Token')
        ]
    }
    
    # Results dictionary to store findings
    findings = {}
    
    # Compile regex patterns
    compiled_patterns = {
        category: [(re.compile(pattern, re.IGNORECASE), desc) 
                   for pattern, desc in patterns]
        for category, patterns in sensitive_patterns.items()
    }
    
    # Recursively scan files
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.js'):
                filepath = os.path.join(root, file)
                file_findings = {}
                
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    # Search through each category of patterns
                    for category, pattern_list in compiled_patterns.items():
                        matched_patterns = []
                        
                        for pattern, description in pattern_list:
                            matches = pattern.findall(content)
                            if matches:
                                matched_patterns.append((description, matches[:3]))  # Limit to first 3 matches
                        
                        # Only add category if patterns were found
                        if matched_patterns:
                            file_findings[category] = matched_patterns
                
                except Exception as e:
                    print(f"Error reading {filepath}: {e}")
                
                # Add to main findings if any patterns were found
                if file_findings:
                    findings[filepath] = file_findings
    
    return findings

def print_security_scan_results(findings):
    """
    Print security scan results in a user-friendly format.
    
    Args:
        findings (dict): Dictionary of security pattern findings
    """
    if not findings:
        print(Fore.GREEN + "\n🟢 No sensitive patterns detected in JavaScript files.")
        return
    
    print(Fore.RED + "\n⚠️ Potential Security Risks Detected:")
    for filepath, categories in findings.items():
        print(f"\nFile: {filepath}")
        for category, patterns in categories.items():
            print(f"  🔴 {category}:")
            for description, matches in patterns:
                print(f"    - {description}")
                for match in matches:
                    print(f"      • {match}")

def main():
    # Input the domain to find subdomains
    domain = input(Fore.CYAN + "Enter the domain to find subdomains: ").strip()
    cookie_str = input(Fore.CYAN + "Enter cookies (if any, in 'key=value; key2=value2' format, or press Enter to skip): ").strip()

    cookies = None
    if cookie_str:
        try:
            cookies = {key.strip(): value.strip() for key, value in (item.split('=') for item in cookie_str.split(';'))}
        except ValueError:
            print(Fore.RED + "Invalid cookie format. Please use 'key=value; key2=value2'.")
            return

    print(Fore.YELLOW + "\nFinding subdomains...")
    subdomains = find_subdomains(domain)
    if not subdomains:
        print(Fore.RED + "No subdomains found.")
        return

    print(Fore.GREEN + f"Found {len(subdomains)} subdomains.")
    output_folder = "output"  # Folder where the JS files will be saved

    all_js_files = []
    for subdomain in subdomains:
        print(Fore.YELLOW + f"\nFetching the webpage for subdomain: {subdomain}")
        html = fetch_page(f"http://{subdomain}", cookies=cookies)
        if not html:
            continue

        print(Fore.YELLOW + f"Extracting JavaScript files from {subdomain}...")
        js_files = extract_js_files(html, f"http://{subdomain}")
        print(Fore.GREEN + f"Found {len(js_files)} JavaScript files in {subdomain}.")
        all_js_files.extend(js_files)

    if all_js_files:
        print(Fore.YELLOW + "\nDownloading JavaScript files...")
        downloaded_files = download_js_files(all_js_files, output_dir=output_folder)
        
        if downloaded_files:
            print(Fore.GREEN + f"\nDownloaded {len(downloaded_files)} JavaScript files. Check the '{output_folder}' folder.")
            
            # Add security scanning
            print(Fore.YELLOW + "\nPerforming comprehensive security pattern scan...")
            security_findings = scan_for_sensitive_keywords(output_folder)
            print_security_scan_results(security_findings)
        else:
            print(Fore.RED + "No JavaScript files were successfully downloaded.")
    else:
        print(Fore.RED + "No JavaScript files found in any subdomains.")

if __name__ == "__main__":
    main()
