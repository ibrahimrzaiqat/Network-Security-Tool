import socket
import subprocess
import platform
import concurrent.futures
import ipaddress

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

def resolve_hostname(ip):
    """Attempts to resolve the human-readable name of the device via DNS."""
    try:
        # socket.gethostbyaddr queries the local network or router for the hostname
        hostname = socket.gethostbyaddr(ip)[0]
        # Clean up long domain suffixes if present (e.g., .lan or .home)
        return hostname.split('.')[0]
    except Exception:
        return None

def ping_host(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_flag = "-w" if platform.system().lower() == "windows" else "-W"
    timeout_val = "100" if platform.system().lower() == "windows" else "1"

    command = ["ping", param, "1", timeout_flag, timeout_val, str(ip)]
    
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            return str(ip)
    except Exception:
        pass
    return None

def discover_network(subnet="192.168.1.0/24"):
    active_devices = []
    my_ip = get_local_ip()
    
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        ip_list = [str(ip) for ip in net.hosts()]
    except Exception:
        ip_list = ["127.0.0.1"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=150) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in ip_list}
        
        for future in concurrent.futures.as_completed(futures):
            live_ip = future.result()
            if live_ip:
                is_self = (live_ip == my_ip)
                # Resolve hostname (with a quick fallback to IP if it fails)
                hostname = resolve_hostname(live_ip) or live_ip
                
                active_devices.append({
                    "ip": live_ip,
                    "name": hostname,
                    "is_self": is_self
                })

    return active_devices