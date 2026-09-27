import time
import os
import subprocess
import threading
import collections
from scapy.all import sniff, DNS, IP, UDP

MONITOR_INTERFACE = "eth1" # The internal-facing interface (10.0.5.254)
MIN_SUBDOMAIN_LENGTH = 15  # Heuristic for detection
BLOCK_DURATION = 300       # 5 minutes
IPTABLES_PATH = "iptables" 

BLOCKED_HOSTS = {}
BLOCKED_HOSTS_LOCK = threading.Lock() # Lock for thread-safe access to the dictionary
QUERY_COUNTS = collections.defaultdict(list)
QUERY_COUNTS_LOCK = threading.Lock()

QUERY_RATE_WINDOW = 10    # seconds to look back
QUERY_RATE_THRESHOLD = 7 # max queries allowed in that window


def block_host(client_ip):

    
    block_cmd = [IPTABLES_PATH, '-I', 'FORWARD', '-s', client_ip, '-j', 'DROP']

    
    try:
        subprocess.run(block_cmd, check=True, capture_output=True)
        print(f"\n[!!! BLOCK ACTION !!!] Successfully BLOCKED all traffic from: {client_ip}")

        # Schedule the unblock action
        timer = threading.Timer(BLOCK_DURATION, unblock_host, args=[client_ip])
        timer.start()
        BLOCKED_HOSTS[client_ip] = timer
        print(f"[INFO] Host {client_ip} scheduled for unblock in {BLOCK_DURATION} seconds.")

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to execute iptables command: {e.stderr.decode().strip()}")
    except FileNotFoundError:
        print(f"[ERROR] {IPTABLES_PATH} command not found.")


def unblock_host(client_ip):
    """Removes the iptables rule, unblocking the client_ip."""

    unblock_cmd = [IPTABLES_PATH, '-D', 'FORWARD', '-s', client_ip, '-j', 'DROP']

    try:
        subprocess.run(unblock_cmd, check=True, capture_output=True)
        print(f"\n[!!! UNBLOCK ACTION !!!] Successfully UNBLOCKED traffic from: {client_ip}")

        # Clean up state
        with BLOCKED_HOSTS_LOCK:
            if client_ip in BLOCKED_HOSTS:
                del BLOCKED_HOSTS[client_ip]

    except subprocess.CalledProcessError as e:
        print(f"[WARNING] Failed to delete iptables rule for {client_ip}. Rule may not exist.")



def detect_tunnel(packet):
    """
    Callback function executed for every packet matching the filter.
    Applies the long subdomain heuristic and triggers the block_host function.
    """

    if packet.haslayer(DNS) and packet.haslayer(IP):
        dns_layer = packet.getlayer(DNS)
        ip_layer = packet.getlayer(IP)

        now = time.time()
        client_ip = ip_layer.src
        with QUERY_COUNTS_LOCK:
            # Add current timestamp
            QUERY_COUNTS[client_ip].append(now)
            
            # Purge timestamps outside the window
            QUERY_COUNTS[client_ip] = [
                t for t in QUERY_COUNTS[client_ip]
                if now - t <= QUERY_RATE_WINDOW
            ]
    
        recent_count = len(QUERY_COUNTS[client_ip])


        if dns_layer.qr == 0 and dns_layer.qd:

            # The query name can be in the format b'subdomain.subdomain.domain.tld.'
            query_name_bytes = dns_layer.qd.qname

            try:
                full_domain = query_name_bytes.decode('utf-8').rstrip('.')
                domain_parts = full_domain.split('.')

                if len(domain_parts) >= 2:
                    subdomains = domain_parts[:-2]
                    client_ip = ip_layer.src

                    if sum(len(label) for label in subdomains) > MIN_SUBDOMAIN_LENGTH or recent_count > QUERY_RATE_THRESHOLD:

                        # --- Acquire Lock ONLY for Host Check/State Update ---
                        block_needed = False
                        with BLOCKED_HOSTS_LOCK:
                            if client_ip not in BLOCKED_HOSTS:
                                block_needed = True

                        if block_needed:
                            print("\n" + "=" * 60)
                            print(f"!!! TUNNEL DETECTED (Scapy) !!!")
                            print(f"Client: {client_ip} | Domain: {full_domain}")
                            combined = '.'.join(subdomains)
                            print(f"Subdomain: {combined} (Length: {sum(len(label) for label in subdomains)})")
                            print("=" * 60 + "\n")

                            
                            block_host(client_ip)

            except UnicodeDecodeError:
                # Handle non-standard encoding used by some tunellers
                pass
            except Exception as e:
                # print(f"Processing error: {e}")
                pass



def start_sniffing():
    print(f"Starting Scapy DNS Blocker on interface: {MONITOR_INTERFACE}")
    # Filter only UDP port 53 traffic...DNS queries)
    BFP_FILTER = "udp port 53"

    try:
        # Start sniffing, calling detect_tunnel for every matching packet
        sniff(iface=MONITOR_INTERFACE, filter=BFP_FILTER, prn=detect_tunnel, store=0)

    except OSError as e:
        print(f"\n[CRITICAL ERROR] Failed to start sniffing. Check interface name and root permissions.")
        print(f"Error detail: {e}")

    except Exception as e:
        print(f"[CRITICAL ERROR] An unexpected error occurred: {e}")

if __name__ == "__main__":
    start_sniffing()
