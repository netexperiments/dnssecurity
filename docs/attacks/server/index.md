# DNS Server Attacks

DNS server attacks target the infrastructure and software running DNS services. 
These attacks aim to disrupt, corrupt, or take control of DNS servers, 
affecting all clients that rely on them for name resolution.

## Attacks

- **[NXDOMAIN DDoS](nxdomain-ddos.md)** – Floods a DNS server with queries 
for non-existent domains, exhausting its resources
- **[DNS Cache Poisoning](cache-poisoning.md)** – Injects malicious records 
into a DNS resolver's cache to redirect traffic
- **[Kaminsky Cache Poisoning](kaminsky.md)** – A sophisticated cache poisoning 
variant that exploits subdomain resolution
- **[Unauthorized Zone Transfer](zone-transfer.md)** – Exploits misconfigured DNS servers 
to retrieve entire zone data, exposing network topology
- **[DNS ARP Poisoning](dns-arp-poisoning.md)** – Combines ARP spoofing with 
DNS manipulation to intercept and redirect DNS traffic