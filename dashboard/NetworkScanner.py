import socket
import sys
import os
import time
import requests
import re
import json
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import NVD_API_KEY

RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def probe_ports(target_ip, target_port, timeout=1.0):

    http_nudge = b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n"
    probe_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe_socket.settimeout(timeout)

    try:
        adress = (target_ip, target_port)
        result = probe_socket.connect_ex(adress)  
        if result != 0:
            return False, None
    except socket.error as e:
            print(f"Socket connection error: {e}")
            return False, None

    banner= None
    try:
        try:
            data = probe_socket.recv(1024)
        except (socket.timeout, socket.error):
            data = b''

        if data:
            try:
                banner= data.decode("UTF-8")
            except UnicodeDecodeError as e:
                print(f"Decoding ERROR : {e}")
                banner= None
        else:
            try:
                probe_socket.send(http_nudge)
                answer = probe_socket.recv(1024)
            except (socket.timeout, socket.error):
                answer = b''

            if answer:
                try:
                    banner = answer.decode("UTF-8")
                except UnicodeDecodeError as e:
                    print(f"Decoding ERROR : {e}")
                    banner = None
    finally:
        probe_socket.close()

    return True, banner

def scan_range(target_ip, start_port, ending_port, maximum_workers=100):
    if start_port> ending_port:
        print(f"Starting port cant be less than ending port.")
        return {}
    
    
    print(f"Scanning {target_ip} from starting from port: {start_port}, ending at port: {ending_port}")

    open_ports={}
    start_scan_time= time.time()
    
    chunksize= 1000

    #The pool automatically manages handing out work to whichever of its limited threads is currently free, queuing the rest until a slot opens up.
    with ThreadPoolExecutor(max_workers=maximum_workers) as executor:
        for current_start in range(start_port, ending_port+1, chunksize):
            
            current_end = min(current_start + chunksize - 1, ending_port)
            futures = {}

            for port in range(current_start, current_end + 1):#Sequential scan which wil take long 
                future= executor.submit(probe_ports, target_ip, port)
                futures[future]=port    

            for future in as_completed(futures):
                port= futures[future]
                is_open, banner = future.result()
                if is_open:
                    open_ports[port]= banner


    total_time_taken = time.time() - start_scan_time
    
    print(f"Scan DONE, Total time taken: {total_time_taken}")
    if len(open_ports)<16:
        print(f"OPEN Ports: {open_ports}")
    
    return open_ports
    
def query_NVD(software_name : str):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": software_name}
    headers = {"apiKey": NVD_API_KEY}   

    try:
        response = requests.get(url, params=params, headers=headers, timeout=10)#10 secs timeout
        if response.status_code == 200:
            return response.json()
        else:
            print(f"NVD request denied for {software_name} with status code: {response.status_code}")
            return None     
    except requests.exceptions.Timeout:
        print(f"NVD API request timed out for: {software_name}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"NVD API request failed for {software_name}: {e}")
        return None
        
def parse_cve_response(response_json):
    simplified_dict= []
    vulnerabilities= response_json["vulnerabilities"]

    for item in vulnerabilities:
        cve_id= item["cve"]["id"]
        
        description= item["cve"]["descriptions"][0]["value"]
        for desc in item["cve"]["descriptions"]:
            if desc["lang"]=="en":
                description= desc["value"]
                break

        metrics = item["cve"]["metrics"]
        v31 = metrics.get("cvssMetricV31")
        v30= metrics.get("cvssMetricV30")
        v2= metrics.get("cvssMetricV2")
        if v31:
            severity=v31[0]["cvssData"]["baseScore"]
        elif v30:
            severity=v30[0]["cvssData"]["baseScore"]
        elif v2:
            severity=v2[0]["cvssData"]["baseScore"]
        else:
            severity=None

        simplified_dict.append({
            "id": cve_id,
            "description": description,
            "severity": severity
        })

    return simplified_dict

def look_cve_data(software_name):
    response_json=query_NVD(software_name)
    if response_json is None:
        return []
    return parse_cve_response(response_json)

def extract_software_list(banner: str):
    # finds "name/version" (Apache/2.4.7) and "name_version" (OpenSSH_6.6.1p1) patterns
    matches = re.findall(r'([A-Za-z][\w\-]*)[/_]([\d][\w.\-]*)', banner)
    return matches  # returns a list of tuples: [("SimpleHTTP", "0.6"), ("Python", "3.14.4")]

def parse_arguments():
    parser = argparse.ArgumentParser(description="Network Scanner with CVE Lookup")
    parser.add_argument("target_ip", help="Target IP address to scan")
    parser.add_argument("start_port", type=int, help="Starting port number")
    parser.add_argument("end_port", type=int, help="Ending port number")
    parser.add_argument("--workers", type=int, default=0, help="Number of concurrent scan threads (default: 0 for auto scale)")
    return parser.parse_args()

def run_scan(target_ip, starting_port, ending_port, maximum_workers=0):
    if starting_port > ending_port:
        print("Starting port can't be greater than ending port.")
        return None

    if maximum_workers == 0:
        maximum_workers = min(500, (os.cpu_count() or 1) * 15)
        print(f"Auto-scaling threads: Using {maximum_workers} workers.")
    elif maximum_workers >= 500:
        print(f"Requested {maximum_workers} workers exceeds the safe limit — using 500 instead.")
        maximum_workers = 500
    elif maximum_workers < 0:
        print(f"Requested {maximum_workers} workers is invalid — auto-scaling instead.")
        maximum_workers = min(500, (os.cpu_count() or 1) * 15)

    cve_cache={}
    scan_report={"target_ip": target_ip, "results": {}}
    IGNORE_LIST = {"http", "https", "ftp", "ssh", "smtp", "pop3", "imap"}

    for port, banner in scan_range(target_ip, starting_port, ending_port, maximum_workers).items():
        if banner:
            print(f"Port: {port}: {banner.strip()}\n\n\n")
            software_list = extract_software_list(banner) 

            if not software_list:
                scan_report["results"][port] = [{
                    "software": "unknown (banner: " + banner.strip()[:60] + ")",
                    "cves_found": 0,
                    "cve_details": []
                }]  
            
            for name, version in software_list:
                if name.lower() in IGNORE_LIST:
                    continue
                search_query= f"{name} {version}"

                print(f"Checking vulnerabilities for: {search_query}")
                if search_query in cve_cache:
                    print("Found in Local cache, skipping API requst")
                    cve_data=cve_cache[search_query]
                else:
                    cve_data = look_cve_data(search_query)
                    cve_cache[search_query]=cve_data
                    time.sleep(3)#sleep some secs cuz of NVD API rate limit

                if port not in scan_report["results"]:
                    scan_report["results"][port] = []
                
                scan_report["results"][port].append({
                    "software": search_query,
                    "cves_found": len(cve_data) if cve_data else 0,
                    "cve_details": cve_data
                })

                if cve_data:
                    print(f"CVEs Found: {len(cve_data)}")
                    #limiting printing so that i dont get flooded
                    for cve in cve_data[:5]: 
                        full_desc = str(cve['description'])
                        short_desc = full_desc[:100] + "..." if len(full_desc) > 100 else full_desc
                        severity=cve["severity"]
                        
                        color=RESET
                        if severity is not None:
                            if float(severity) >= 9.0:
                                color = RED
                            elif float(severity) >= 7.0:
                                color = YELLOW

                        print(f"  {color}- {cve['id']} (Severity: {cve['severity']}){RESET}")
                        print(f"    Info: {short_desc}\n")
                else:
                    print("CVE: None found or query failed.")
                print("-" * 40)
                
        else:
            print(f"Port {port}: no banner received")
            scan_report["results"][port] = [{
                "software": "unknown (open port, no banner)",
                "cves_found": 0,
                "cve_details": []
            }]

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_filename = f"scan_report_({target_ip})_({starting_port}-{ending_port})_({timestamp}).json"
    with open(report_filename, "w") as outfile:
        json.dump(scan_report, outfile, indent=4)
    
    print(f"\nScan complete! Full results saved to {report_filename}")
    return report_filename


if __name__ == "__main__":
    args = parse_arguments()
    run_scan(args.target_ip, args.start_port, args.end_port, args.workers)