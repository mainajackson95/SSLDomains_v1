# coded by kaisec 2023-03-10
# https://kaisec.co.ke
# https://x.com/kais3c_42
# File crawls IP ranges defined in ips variable and extracts domain names from certificates
# It then checks each domain and logs the IP, Host, Status Code, and Headers delimited by "|"

import requests, urllib3, time, ssl, OpenSSL, argparse, concurrent.futures, ipaddress
from socket import *
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def parse_arguments():
    parser = argparse.ArgumentParser(description='Crawl IP ranges to extract domains from SSL certificates')
    parser.add_argument('-t', '--throttle', type=float, default=1.0, help='Seconds to delay requests for WAF (default: 1.0)')
    parser.add_argument('-o', '--timeout', type=float, default=1.0, help='Seconds before a request times out (default: 1.0)')
    parser.add_argument('-f', '--output', type=str, default='domains.csv', help='Output file (default: domains.csv)')
    parser.add_argument('-c', '--concurrent', type=int, default=1, help='Number of concurrent workers (default: 1)')
    parser.add_argument('-r', '--ranges', type=str, nargs='+', help='IP ranges to scan (e.g., 192.168.1. 10.0.0.)')
    return parser.parse_args()

def get_certificate_san(x509cert):
    san = ''
    ext_count = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            san = ext.__str__()
    return san

def checkSite(ip, host, timeout, output_file):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0',
            'Accept': "*/*",
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br'
        }
        
        r = requests.get(url=f"https://{host}", verify=False, headers=headers, timeout=timeout)
        sc = r.status_code
        print(f"{host}: {sc}")
        
        with open(output_file, 'a') as f:
            f.write(f"{ip}|{host}|{sc}|{r.headers}\n")
        
        return True
    except Exception as e:
        print(f"{host}: DOWN - {str(e)}")
        return False

def process_ip(ip, timeout, output_file):
    print(f"Checking {ip}")
    try:
        setdefaulttimeout(timeout)
        cert = ssl.get_server_certificate((ip, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        
        hostnames = []
        
        # Try to get Common Name
        try:
            cn = x509.get_subject().CN
            if cn:
                hostnames.append(cn)
                checkSite(ip, cn, timeout, output_file)
        except Exception:
            pass
            
        # Try to get Subject Alternative Names
        try:
            san_text = get_certificate_san(x509)
            if san_text:
                san_list = san_text.split(',')
                for san in san_list:
                    if 'DNS:' in san:
                        hostname = san.split('DNS:')[1].strip()
                        if hostname and hostname not in hostnames:
                            hostnames.append(hostname)
                            checkSite(ip, hostname, timeout, output_file)
        except Exception as e:
            print(f"Error extracting SANs: {e}")
            
        return hostnames
    except Exception as e:
        print(f"Error with {ip}: {e}")
        return []

def main():
    args = parse_arguments()
    
    # If no IP ranges specified, prompt user
    if not args.ranges:
        print("Enter IP ranges to scan (e.g., 192.168.1. 10.0.0.)")
        ip_input = input("> ")
        args.ranges = ip_input.split()
    
    # Initialize output file
    with open(args.output, 'w') as f:
        f.write("IP|Hostname|Status|Headers\n")
    
    all_ips = []
    for prefix in args.ranges:
        try:
            # Handle CIDR notation if provided
            if '/' in prefix:
                network = ipaddress.IPv4Network(prefix, strict=False)
                for ip in network:
                    all_ips.append(str(ip))
            else:
                # Traditional method with prefix ending in dot
                if not prefix.endswith('.'):
                    prefix += '.'
                for i in range(1, 255):
                    all_ips.append(f"{prefix}{i}")
        except Exception as e:
            print(f"Error processing range {prefix}: {e}")
    
    print(f"Prepared to scan {len(all_ips)} IP addresses")
    
    # Use concurrent execution if requested
    if args.concurrent > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrent) as executor:
            futures = []
            for ip in all_ips:
                # Add throttle delay between submissions
                time.sleep(args.throttle / args.concurrent)
                futures.append(executor.submit(process_ip, ip, args.timeout, args.output))
            
            for future in concurrent.futures.as_completed(futures):
                # Results handled within process_ip
                pass
    else:
        # Sequential execution
        for ip in all_ips:
            time.sleep(args.throttle)
            process_ip(ip, args.timeout, args.output)
    
    print(f"Scan complete. Results saved to {args.output}")

if __name__ == "__main__":
    main()