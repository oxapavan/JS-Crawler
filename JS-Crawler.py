import os
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
    except requests.RequestException as e:
        print(Fore.RED + f"Failed to download {js_url}: {e}")

def download_js_files(js_files, output_dir):
    """Download JavaScript files in parallel."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with ThreadPoolExecutor(max_workers=5) as executor:
        for js_url in js_files:
            executor.submit(download_js_file, js_url, output_dir)

def main():
    # Input the URL and optional cookies
    url = input(Fore.CYAN + "Enter the URL to crawl: ").strip()
    cookie_str = input(Fore.CYAN + "Enter cookies (if any, in 'key=value; key2=value2' format, or press Enter to skip): ").strip()

    cookies = None
    if cookie_str:
        try:
            cookies = {key.strip(): value.strip() for key, value in (item.split('=') for item in cookie_str.split(';'))}
        except ValueError:
            print(Fore.RED + "Invalid cookie format. Please use 'key=value; key2=value2'.")
            return

    print(Fore.YELLOW + "\nFetching the webpage...")
    html = fetch_page(url, cookies=cookies)
    if not html:
        print(Fore.RED + "Failed to fetch the webpage.")
        return

    print(Fore.YELLOW + "\nExtracting JavaScript files...")
    js_files = extract_js_files(html, url)
    print(Fore.GREEN + f"Found {len(js_files)} JavaScript files.")

    if js_files:
        print(Fore.YELLOW + "\nDownloading JavaScript files...")
        output_folder = "output"  # Folder where the JS files will be saved
        download_js_files(js_files, output_dir=output_folder)
        print(Fore.GREEN + f"\nDownloaded {len(js_files)} JavaScript files. Check the '{output_folder}' folder.")
    else:
        print(Fore.RED + "No JavaScript files found.")

if __name__ == "__main__":
    main()
