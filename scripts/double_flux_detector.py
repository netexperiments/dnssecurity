import os
import sys
import json
import time
import threading
from scapy.all import sniff, DNS, DNSRR, IP, UDP

# --- Configuration ---
MONITOR_INTERFACE = "eth0"
STATE_FILE = "/home/fast_flux_state.json"
IP_THRESHOLD = 3          # Alert if N or more unique IPs are seen for a domain (A records)
NS_THRESHOLD = 2          # Alert if N or more unique NS IPs are seen for a domain
LOW_TTL_THRESHOLD = 300   # TTLs below this are considered suspicious (seconds)
STATE_TTL_SECONDS = 86400 # Forget IPs older than 24 hours
SAVE_INTERVAL = 60        # Save state to disk every N seconds


# A record history:  { "client_ip": { "domain": [{"ip": "1.2.3.4", "seen_at": 1234567890, "ttl": 60}] } }
# NS record history: { "domain": [{"ns_ip": "1.2.3.4", "seen_at": 1234567890, "ttl": 60}] }
dns_history = {}
ns_history = {}
alerted_domains = set()     # Tracks (client_ip, domain) pairs already alerted for A-record flux
alerted_ns_domains = set()  # Tracks domains already alerted for NS-record flux
state_lock = threading.Lock()



def check_root():
    if os.geteuid() != 0:
        sys.exit("[!] This script must be run as root.")



def load_state():
    """Loads persisted history from JSON, skipping already-expired entries."""
    global dns_history, ns_history
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                raw = json.load(f)

            now = time.time()

            # Load A record history
            for client_ip, domains in raw.get("a_records", {}).items():
                dns_history[client_ip] = {}
                for domain, entries in domains.items():
                    valid = [e for e in entries if now - e["seen_at"] < STATE_TTL_SECONDS]
                    if valid:
                        dns_history[client_ip][domain] = valid

            # Load NS record history
            for domain, entries in raw.get("ns_records", {}).items():
                valid = [e for e in entries if now - e["seen_at"] < STATE_TTL_SECONDS]
                if valid:
                    ns_history[domain] = valid

            print(f"[*] State loaded from {STATE_FILE}.")
        except Exception as e:
            print(f"[!] Error loading state file: {e}. Starting fresh.")
            dns_history = {}
            ns_history = {}


def save_state():
    """Saves the current A and NS history to disk (called from background thread)."""
    with state_lock:
        snapshot = {
            "a_records": json.loads(json.dumps(dns_history)),
            "ns_records": json.loads(json.dumps(ns_history))
        }
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
    """Removes A record entries older than STATE_TTL_SECONDS for a given client/domain."""
    now = time.time()
    dns_history[client_ip][domain] = [
        e for e in dns_history[client_ip][domain]
        if now - e["seen_at"] < STATE_TTL_SECONDS
    ]


def prune_old_ns_entries(domain):
    """Removes NS record entries older than STATE_TTL_SECONDS for a given domain."""
    now = time.time()
    ns_history[domain] = [
        e for e in ns_history[domain]
        if now - e["seen_at"] < STATE_TTL_SECONDS
    ]


def detect_fast_flux(packet):
    """
    Analyzes DNS responses to detect both Single Flux (rotating A records)
    and Double Flux (rotating NS records).
    """
    if not (packet.haslayer(DNS) and packet.haslayer(IP)):
        return

    dns_layer = packet.getlayer(DNS)
    ip_layer = packet.getlayer(IP)

    # Only process DNS responses with answers
    if dns_layer.qr != 1 or dns_layer.ancount == 0:
        return

    client_ip = ip_layer.dst

    # Extract queried domain name
    try:
        query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
    except Exception:
        return

    # --- Collect A records and NS records from the answer section ---
    a_entries = []
    ns_entries = []
    low_ttl_seen = False

    for i in range(dns_layer.ancount):
        record = dns_layer.an[i]
        ttl = record.ttl

        if record.type == 1:  # A record (IPv4)
            ip_str = str(record.rdata)
            if ttl < LOW_TTL_THRESHOLD:
                low_ttl_seen = True
            a_entries.append({"ip": ip_str, "ttl": ttl, "seen_at": time.time()})

        elif record.type == 2:  # NS record
            try:
                ns_name = record.rdata.decode('utf-8').rstrip('.')
            except Exception:
                ns_name = str(record.rdata).rstrip('.')
            if ttl < LOW_TTL_THRESHOLD:
                low_ttl_seen = True
            ns_entries.append({"ns_name": ns_name, "ttl": ttl, "seen_at": time.time()})

    # Also check the additional/authority sections for glue A records tied to NS names
    # These are found in dns_layer.ar (additional records)
    ns_glue_ips = []
    try:
        ar_count = dns_layer.arcount
        for i in range(ar_count):
            record = dns_layer.ar[i]
            if record.type == 1:  # Glue A record for a nameserver
                ns_glue_ips.append({
                    "ip": str(record.rdata),
                    "ttl": record.ttl,
                    "seen_at": time.time()
                })
                if record.ttl < LOW_TTL_THRESHOLD:
                    low_ttl_seen = True
    except Exception:
        pass

    with state_lock:

        # ----------------------------------------------------------------
        # Single Flux check: rotating A records for the queried domain
        # ----------------------------------------------------------------
        if a_entries:
            dns_history.setdefault(client_ip, {}).setdefault(query_name, [])
            prune_old_entries(client_ip, query_name)

            known_ips = {e["ip"] for e in dns_history[client_ip][query_name]}
            for entry in a_entries:
                if entry["ip"] not in known_ips:
                    dns_history[client_ip][query_name].append(entry)
                    known_ips.add(entry["ip"])

            unique_ips = [e["ip"] for e in dns_history[client_ip][query_name]]
            unique_count = len(unique_ips)
            alert_key = (client_ip, query_name)

            if unique_count >= IP_THRESHOLD and alert_key not in alerted_domains:
                alerted_domains.add(alert_key)
                suspicion = "HIGH" if low_ttl_seen else "MEDIUM"
                ttl_note = (
                    f"Low TTL detected (<{LOW_TTL_THRESHOLD}s) — strong fast flux indicator."
                    if low_ttl_seen else
                    f"TTLs appear normal — possible CDN, verify manually."
                )
                print("\n" + "!" * 60)
                print(f"  SINGLE FLUX ALERT  [{suspicion} CONFIDENCE]")
                print("!" * 60)
                print(f"  Client IP  : {client_ip}")
                print(f"  Domain     : {query_name}")
                print(f"  Unique IPs : {unique_count}")
                print(f"  IP List    : {', '.join(unique_ips)}")
                print(f"  Note       : {ttl_note}")
                print("!" * 60 + "\n")

        # ----------------------------------------------------------------
        # Double Flux check: rotating NS glue IPs for the queried domain
        # We track the IPs of the nameservers themselves (glue records),
        # since in Double Flux it is the NS IP that rotates, not just the name.
        # ----------------------------------------------------------------
        if ns_glue_ips:
            ns_history.setdefault(query_name, [])
            prune_old_ns_entries(query_name)

            known_ns_ips = {e["ip"] for e in ns_history[query_name]}
            for entry in ns_glue_ips:
                if entry["ip"] not in known_ns_ips:
                    ns_history[query_name].append(entry)
                    known_ns_ips.add(entry["ip"])

            unique_ns_ips = [e["ip"] for e in ns_history[query_name]]
            unique_ns_count = len(unique_ns_ips)

            if unique_ns_count >= NS_THRESHOLD and query_name not in alerted_ns_domains:
                alerted_ns_domains.add(query_name)

                # Determine NS TTL suspicion independently
                ns_low_ttl = any(e["ttl"] < LOW_TTL_THRESHOLD for e in ns_history[query_name])
                suspicion = "HIGH" if ns_low_ttl else "MEDIUM"
                ttl_note = (
                    f"Low NS TTL detected (<{LOW_TTL_THRESHOLD}s) — strong double flux indicator."
                    if ns_low_ttl else
                    f"NS TTLs appear normal — verify manually."
                )

                print("\n" + "!" * 60)
                print(f"  DOUBLE FLUX ALERT  [{suspicion} CONFIDENCE]")
                print("!" * 60)
                print(f"  Domain          : {query_name}")
                print(f"  Unique NS IPs   : {unique_ns_count}")
                print(f"  NS IP List      : {', '.join(unique_ns_ips)}")
                print(f"  Note            : {ttl_note}")
                print("!" * 60 + "\n")



def start_monitor():
    check_root()

    print(f"[*] Loading historical state from {STATE_FILE}...")
    load_state()

    save_thread = threading.Thread(target=periodic_save, daemon=True)
    save_thread.start()

    print(f"[*] Alert threshold (A records / Single Flux)  : {IP_THRESHOLD} unique IPs per domain")
    print(f"[*] Alert threshold (NS records / Double Flux) : {NS_THRESHOLD} unique NS IPs per domain")
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