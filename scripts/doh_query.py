import urllib.request
import ssl
import sys
import struct

def query_doh(domain, resolver_ip):
    # 1. Build the DNS Query Packet
    # Header: ID=0x1234, Flags=0x0100 (Standard query), Questions=1...
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    
    # Question Section
    question = b""
    for part in domain.split("."):
        question += struct.pack("B", len(part)) + part.encode()
    question += b"\x00"                # End of domain
    question += struct.pack("!HH", 1, 1) # Type A, Class IN

    packet = header + question

    # 2. Setup HTTPS Request
    url = f"https://{resolver_ip}/dns-query"
    
    # Ignore self-signed cert issues
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, data=packet, headers={
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message"
    })

    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            data = resp.read()
            # The IPv4 address is the last 4 bytes of the Answer section
            # We skip the first part of the response to find the RDATA
            ip = ".".join(map(str, data[-4:]))
            print(f"[{resolver_ip}] {domain} -> {ip}")
    except Exception as e:
        print(f"Error connecting to {resolver_ip}: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 query.py <domain> [resolver_ip]")
        sys.exit(1)

    domain_to_query = sys.argv[1]
    # Use 10.0.1.1 as default if no IP is provided
    dns_server = sys.argv[2] if len(sys.argv) > 2 else "10.0.1.1"
    
    query_doh(domain_to_query, dns_server)