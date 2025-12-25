# utils.py
import platform
import os

def detect_os():
    system = platform.system().lower()
    if system == "windows":
        version = platform.version()
        # Windows 10: 10.0.19041+, Windows 11: 10.0.22000+
        major, minor, build = map(int, version.split('.'))
        if major == 10 and build >= 22000:
            return "windows11"
        elif major == 10:
            return "windows10"
        else:
            return "windows"
    elif system == "linux":
        return "linux"
    else:
        return "unknown"

def print_devices_table(devices):
    print("\n" + "="*80)
    print(f"{'IP':<16} {'MAC':<18} {'Hostname'}")
    print("-"*80)
    for d in devices:
        print(f"{d['ip']:<16} {d['mac']:<18} {d['hostname']}")
    print("="*80 + "\n")
