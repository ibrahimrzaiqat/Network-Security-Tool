import socket
import subprocess
import platform
import concurrent.futures
import ipaddress

IS_WINDOWS = platform.system().lower() == "windows"


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def get_local_subnet():
    """Derives a /24 subnet from the machine's local IP, so discover_network()
    has a sensible default instead of a hardcoded 192.168.1.0/24 that silently
    finds nothing on any other network layout (10.x, 172.16.x, etc.)."""
    local_ip = get_local_ip()
    try:
        return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
    except Exception:
        return "192.168.1.0/24"


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
    param = "-n" if IS_WINDOWS else "-c"
    timeout_flag = "-w" if IS_WINDOWS else "-W"
    # 100ms was too tight and produced false "offline" results on anything
    # slightly slow to answer (e.g. wifi devices) — 500ms is more forgiving
    # while still keeping a full sweep fast.
    timeout_val = "500" if IS_WINDOWS else "1"

    command = ["ping", param, "1", timeout_flag, timeout_val, str(ip)]

    # On Windows, subprocess otherwise flashes a visible console window per
    # call — with up to 150 concurrent pings that's very noticeable and looks
    # broken in a packaged .exe with no terminal of its own.
    creationflags = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,  # safety net so a hung ping can't tie up a worker thread forever
            creationflags=creationflags,
        )
        if result.returncode == 0:
            return str(ip)
    except Exception:
        pass
    return None


def discover_network(subnet=None, max_workers=150):
    """Sweeps a subnet for live hosts and resolves their hostnames.

    subnet: CIDR string (e.g. "192.168.1.0/24"). If None, it's auto-derived
    from this machine's own IP so the common case just works without the
    caller having to know their own network range.
    """
    active_devices = []
    my_ip = get_local_ip()

    if subnet is None:
        subnet = get_local_subnet()

    try:
        net = ipaddress.ip_network(subnet, strict=False)
        ip_list = [str(ip) for ip in net.hosts()]
    except Exception:
        print(f"Couldn't parse subnet '{subnet}', falling back to 127.0.0.1 only.")
        ip_list = ["127.0.0.1"]

    print(f"Discovering devices on {subnet} ({len(ip_list)} addresses)...")

    live_ips = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in ip_list}

        for future in concurrent.futures.as_completed(futures):
            live_ip = future.result()
            if live_ip:
                live_ips.append(live_ip)

    print(f"Found {len(live_ips)} live host(s), resolving hostnames...")

    # Hostname resolution can be slow per-host (DNS/NetBIOS lookups with no
    # fast negative response) — run it through the pool too instead of doing
    # it one-by-one in the main thread after the ping sweep already finished.
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        hostname_futures = {executor.submit(resolve_hostname, ip): ip for ip in live_ips}

        for future in concurrent.futures.as_completed(hostname_futures):
            live_ip = hostname_futures[future]
            hostname = future.result() or live_ip
            active_devices.append({
                "ip": live_ip,
                "name": hostname,
                "is_self": live_ip == my_ip,
            })

    print(f"Discovery DONE. {len(active_devices)} device(s) found.")
    return active_devices


if __name__ == "__main__":
    for device in discover_network():
        marker = " (this machine)" if device["is_self"] else ""
        print(f"  {device['ip']:<16} {device['name']}{marker}")