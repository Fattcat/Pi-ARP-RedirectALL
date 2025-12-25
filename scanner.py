# scanner.py
import scapy.all as scapy
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

def resolve_hostname(ip, timeout=1):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.timeout, OSError):
        return "N/A"

def scan_network(network="192.168.1.0/24", timeout=2, max_workers=50):
    print(f"[*] Skenovanie siete {network}...")
    
    # 1. ARP scan
    arp = scapy.ARP(pdst=network)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    ans, _ = scapy.srp(ether/arp, timeout=timeout, verbose=False)
    
    devices = []
    ips = [rcv[scapy.ARP].psrc for snd, rcv in ans]
    
    # 2. Paralelné zisťovanie hostname
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(resolve_hostname, ip): ip for ip in ips}
        hostnames = {}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                hostnames[ip] = future.result()
            except:
                hostnames[ip] = "timeout"
    
    # 3. Zostaviť výsledok
    for snd, rcv in ans:
        ip = rcv[scapy.ARP].psrc
        mac = rcv[scapy.ARP].hwsrc
        hostname = hostnames.get(ip, "N/A")
        devices.append({"ip": ip, "mac": mac, "hostname": hostname})
    
    return sorted(devices, key=lambda x: socket.inet_aton(x["ip"]))
