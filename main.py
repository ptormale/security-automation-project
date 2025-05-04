import json
import subprocess
import time
import logging
import os

# Config paths
EVE_LOG = "/var/log/suricata/eve.json"
LOG_FILE = "/var/log/suricata/block_log.txt"

# Set to track already-blocked IPs
BLOCKED_IPS = set()

# Setup logging
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

def block_ip(ip):
    if not ip or ip in BLOCKED_IPS:
        return
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        BLOCKED_IPS.add(ip)
        print(f"[+] Blocked suspicious IP: {ip}")
        logging.info(f"Blocked suspicious IP: {ip}")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to block IP {ip}: {e}")
        logging.error(f"Failed to block IP {ip}: {e}")

def monitor_log():
    try:
        with open(EVE_LOG, "r") as f:
            f.seek(0, 2)  # Move to the end of file
            print("[*] Monitoring Suricata logs for alerts...")
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                try:
                    data = json.loads(line)
                    if data.get("alert"):
                        src_ip = data.get("src_ip")
                        if src_ip:
                            block_ip(src_ip)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"[-] Could not find Suricata log file at: {EVE_LOG}")
    except PermissionError:
        print("[-] Permission denied while accessing the Suricata log. Try running the script with sudo.")

if __name__ == "__main__":
    monitor_log()
