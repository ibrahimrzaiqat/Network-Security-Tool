import socket
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# cd "desktop/ibrahim/projects/network security toolkit"
# python TCPscanner.py 127.0.0.1 1 1024


#if the user puts the pool num use it else max count is 100


def scan_ports(target_ip, target_port):
    try:
        scan_socket= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        address= (target_ip,target_port)
        scan_socket.settimeout(1)
        result= scan_socket.connect_ex(address)#connect_ex returns 0 if successful connection
        scan_socket.close()
        return result == 0

    except socket.error:

        return False
    
def scan_range(target_ip, start_port, ending_port, maximum_workers=100):
    if start_port> ending_port:
        print(f"Starting port cant be less than ending port.")
        return 
    
    
    print(f"Scanning {target_ip} from starting from port: {start_port}, ending at port: {ending_port}")

    open_ports=[]
    start_scan_time= time.time()
    futures={}

    #The pool automatically manages handing out work to whichever of its limited threads is currently free, queuing the rest until a slot opens up.
    with ThreadPoolExecutor(max_workers=maximum_workers) as executor:
        for port in range(start_port, ending_port+1):#Sequential scan which wil take long 
            future= executor.submit(scan_ports, target_ip, port)
            futures[future]=port
    
        for future in as_completed(futures):
            port= futures[future]
            is_open= future.result()
            if is_open:
                open_ports.append(port)


    total_time_taken = time.time() - start_scan_time
    
    print(f"Scan DONE, Total time taken: {total_time_taken}")
    if len(open_ports)<16:
        print(f"OPEN Ports: {open_ports}")
    
    return open_ports


if __name__ =="__main__":
    if len(sys.argv) < 4 or len(sys.argv) > 5:
        print("Usage: python scanner.py <target_ip> <start_port> <end_port> [max_workers]")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    starting_port = int(sys.argv[2])
    ending_port = int(sys.argv[3])


    maximum_workers=100
    if len(sys.argv) > 4:
        requested = int(sys.argv[4])
        if requested < 500:
            maximum_workers = requested

    scan_range(target_ip, starting_port, ending_port, maximum_workers)

#python scanner.py 192.168.1.10 1 1024
#sys.argv = ["scanner.py", "192.168.1.10", "1", "1024"]
