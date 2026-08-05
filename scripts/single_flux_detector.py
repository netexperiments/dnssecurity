import os
import sys
import json
import time
import threading
from scapy.all import sniff, DNS, DNSRR, IP, UDP


MONITOR_INTERFACE = "eth0"
STATE_FILE = "/home/fast_flux_state.json"
IP_THRESHOLD = 3          # Alert if N or more unique IPs are seen for a domain
LOW_TTL_THRESHOLD = 300   # TTLs below this are considered suspicious (seconds)
STATE_TTL_SECONDS = 86400 # Forget IPs older than 24 hours
SAVE_INTERVAL = 60        # Save state to disk every N seconds


# Structure: { "client_ip": { "domain": [{"ip": "1.2.3.4", "seen_at": 1234567890, "ttl": 60}] } }
dns_history = {}
alerted_domains = set()  # Tracks (client_ip, domain) pairs already alerted
state_lock = threading.Lock()



def check_root():
    if os.geteuid() != 0:
        sys.exit("[!] This script must be run as root.")



def load_state():
    """Loads persisted history from JSON, skipping already-expired entries."""
    global dns_history
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                raw = json.load(f)
            # Prune expired entries on load
            now = time.time()
            for client_ip, domains in raw.items():
                dns_history[client_ip] = {}
                for domain, entries in domains.items():
                    valid = [e for e in entries if now - e["seen_at"] < STATE_TTL_SECONDS]
                    if valid:
                        dns_history[client_ip][domain] = valid
            print(f"[*] State loaded from {STATE_FILE}.")
        except Exception as e:
            print(f"[!] Error loading state file: {e}. Starting fresh.")
            dns_history = {}


def save_state():
    """Saves the current history to disk (called from background thread)."""
    with state_lock:
        snapshot = json.loads(json.dumps(dns_history))  # Deep copy under lock
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(snapshot, f, indent=4)
    except Exception as e:
        print(f"[!] Error saving state: {e}")


def periodic_save():
    """Background thread that saves state every SAVE_INTERVAL seconds."""
    while True:
        time.sleep(SAVE_INTERVAL)
        save_state()


def prune_old_entries(client_ip, domain):
    """Removes entries older than STATE_TTL_SECONDS for a given client/domain."""
    now = time.time()
    dns_history[client_ip][domain] = [
        e for e in dns_history[client_ip][domain]
        if now - e["seen_at"] < STATE_TTL_SECONDS
    ]



def detect_fast_flux(packet):
    """Analyzes DNS responses to track unique IPs per domain per client."""
    if not (packet.haslayer(DNS) and packet.haslayer(IP)):
        return

    dns_layer = packet.getlayer(DNS)
    ip_layer = packet.getlayer(IP)

    # Only process DNS responses with answers
    if dns_layer.qr != 1 or dns_layer.ancount == 0:
        return

    
    client_ip = ip_layer.dst

    
    try:
        query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
    except Exception:
        return

    # Collect A records from the answer section
    new_entries = []
    low_ttl_seen = False

    for i in range(dns_layer.ancount):
        record = dns_layer.an[i]
        if record.type == 1:  # A record (IPv4)
            ip_str = str(record.rdata)  
            ttl = record.ttl
            if ttl < LOW_TTL_THRESHOLD:
                low_ttl_seen = True
            new_entries.append({"ip": ip_str, "ttl": ttl, "seen_at": time.time()})

    if not new_entries:
        return

    # Update state under lock
    with state_lock:
        dns_history.setdefault(client_ip, {}).setdefault(query_name, [])

        # Prune stale entries before evaluating
        prune_old_entries(client_ip, query_name)

        # Add only IPs not already tracked
        known_ips = {e["ip"] for e in dns_history[client_ip][query_name]}
        state_changed = False
        for entry in new_entries:
            if entry["ip"] not in known_ips:
                dns_history[client_ip][query_name].append(entry)
                known_ips.add(entry["ip"])
                state_changed = True

        unique_ips = [e["ip"] for e in dns_history[client_ip][query_name]]
        unique_count = len(unique_ips)
        alert_key = (client_ip, query_name)

        # Alert only once per (client, domain) pair until state resets
        if unique_count >= IP_THRESHOLD and alert_key not in alerted_domains:
            alerted_domains.add(alert_key)

            suspicion = "HIGH" if low_ttl_seen else "MEDIUM"
            ttl_note = f"Low TTL detected (<{LOW_TTL_THRESHOLD}s) — strong fast flux indicator." if low_ttl_seen else \
                       f"TTLs appear normal — possible CDN, verify manually."

            print("\n" + "!" * 60)
            print(f"  FAST FLUX ALERT  [{suspicion} CONFIDENCE]")
            print("!" * 60)
            print(f"  Client IP  : {client_ip}")
            print(f"  Domain     : {query_name}")
            print(f"  Unique IPs : {unique_count}")
            print(f"  IP List    : {', '.join(unique_ips)}")
            print(f"  Note       : {ttl_note}")
            print("!" * 60 + "\n")

    # No per-packet file I/O — periodic_save() handles persistence



def start_monitor():
    check_root()

    print(f"[*] Loading historical state from {STATE_FILE}...")
    load_state()

    # Start background save thread
    save_thread = threading.Thread(target=periodic_save, daemon=True)
    save_thread.start()

    print(f"[*] Alert threshold : {IP_THRESHOLD} unique IPs per domain")
    print(f"[*] Low TTL flag    : < {LOW_TTL_THRESHOLD}s")
    print(f"[*] History window  : {STATE_TTL_SECONDS // 3600}h rolling\n")

    try:
        sniff(
            iface=MONITOR_INTERFACE,
            filter="udp port 53",
            prn=detect_fast_flux,
            store=0
        )
    except KeyboardInterrupt:
        print("\n[*] Shutting down. Saving final state...")
        save_state()
        print("[*] Done.")
    except Exception as e:
        print(f"[CRITICAL] Sniff error: {e}")
        save_state()


if __name__ == "__main__":
    start_monitor()