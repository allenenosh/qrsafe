import cv2
import requests
import re
import os
from pyzbar.pyzbar import decode
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

def display_banner():
    banner = """                                                              
                                            _|_|            
  _|_|_|  _|  _|_|    _|_|_|    _|_|_|    _|        _|_|    
_|    _|  _|_|      _|_|      _|    _|  _|_|_|_|  _|_|_|_|  
_|    _|  _|            _|_|  _|    _|    _|      _|        
  _|_|_|  _|        _|_|_|      _|_|_|    _|        _|_|_|  
      _|                                                    
      _|                                                    

    """
    print(banner)

def read_qr_codes_directory():
    qr_codes_dir = 'qrcodes'
    if not os.path.isdir(qr_codes_dir):
        print(f"Error: '{qr_codes_dir}' directory not found.")
        return []
    
    image_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.bmp']
    qr_codes = [f for f in os.listdir(qr_codes_dir) if os.path.splitext(f)[1].lower() in image_extensions]
    
    return [os.path.join(qr_codes_dir, f) for f in qr_codes]

def display_qr_code_list(qr_codes):
    print("\nAvailable QR codes:")
    for i, code in enumerate(qr_codes, 1):
        print(f"{i}. {os.path.basename(code)}")

def get_user_choice(qr_codes):
    while True:
        try:
            choice = input("\nEnter the number of the QR code to scan (or 'q' to quit): ")
            if choice.lower() == 'q':
                return None
            choice = int(choice)
            if 1 <= choice <= len(qr_codes):
                return qr_codes[choice - 1]
            else:
                print("Invalid choice. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number or 'q'.")

def decode_qr_code(image_path):
    img = cv2.imread(image_path)
    decoded_objects = decode(img)
    if not decoded_objects:
        return None
    return decoded_objects[0].data.decode('utf-8')

def analyze_qr_code_type(data):
    if is_valid_url(data):
        return "URL"
    elif data.isdigit():
        return "Numeric"
    elif data.isalnum():
        return "Alphanumeric"
    elif all(c in '0123456789ABCDEFabcdef' for c in data):
        return "Hexadecimal"
    else:
        return "Text"

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def unshorten_url(short_url):
    try:
        response = requests.head(short_url, allow_redirects=True, timeout=5)
        return response.url
    except requests.RequestException:
        return short_url

def check_url_safety(url):
    results = []
    with ThreadPoolExecutor(max_workers=3) as executor:
        future_blocklist = executor.submit(check_url_against_blocklist, url)
        future_ssl = executor.submit(check_ssl_certificate, url)
        future_suspicious = executor.submit(check_suspicious_elements, url)
        
        results.extend([
            future_blocklist.result(),
            future_ssl.result(),
            future_suspicious.result()
        ])
    
    return [result for result in results if result]

def check_url_against_blocklist(url):
    blocklist_url = "https://urlhaus.abuse.ch/downloads/text/"
    try:
        response = requests.get(blocklist_url, timeout=5)
        if url in response.text:
            return "URL found in abuse.ch blocklist"
    except requests.RequestException:
        pass
    return None

def check_ssl_certificate(url):
    try:
        response = requests.get(url, timeout=5)
        if response.url.startswith('https'):
            return "HTTPS connection established successfully"
        else:
            return "Warning: Site does not use HTTPS"
    except requests.RequestException:
        return "Warning: Unable to establish secure connection"

def check_suspicious_elements(url):
    suspicious_patterns = [
        r'password|creditcard|ssn|medicare|medicare card',  # Sensitive keywords
        r'\.(exe|dll|bat|cmd|msi)$',  # Suspicious file extensions
        r'(?<!/)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!/)',  # IP addresses
        r'data:',  # Data URLs
        r'javascript:',  # JavaScript URLs
    ]
    
    warnings = []
    for pattern in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            warnings.append(f"Warning: URL contains suspicious element matching pattern: {pattern}")
    
    return warnings if warnings else None

def main():
    display_banner()
    
    qr_codes = read_qr_codes_directory()
    if not qr_codes:
        print("No QR code images found in the 'qrcodes' directory.")
        return

    while True:
        display_qr_code_list(qr_codes)
        image_path = get_user_choice(qr_codes)
        
        if image_path is None:
            print("Thank you for using QRSafe. Goodbye!")
            break
        
        print(f"\nAnalyzing QR code: {os.path.basename(image_path)}")
        qr_data = decode_qr_code(image_path)
        
        if qr_data is None:
            print("No QR code found in the image.")
            continue

        qr_type = analyze_qr_code_type(qr_data)
        print(f"QR Code Type: {qr_type}")
        print(f"QR Code Content: {qr_data}")

        if qr_type == "URL":
            print("\nUnshortening URL...")
            long_url = unshorten_url(qr_data)
            print(f"Unshortened URL: {long_url}")

            print("\nChecking URL safety...")
            safety_results = check_url_safety(long_url)

            if safety_results:
                print("\nSafety Check Results:")
                for result in safety_results:
                    print(f"- {result}")
            else:
                print("\nNo immediate safety issues detected.")
            
            print("\nNote: This is a basic check. For comprehensive security analysis, consider using dedicated security services.")
        else:
            print("Not a URL, skipping safety checks.")
        
        print("\n" + "="*50)

if __name__ == "__main__":
    main()
