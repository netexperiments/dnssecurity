# DNS Protocol Attacks

DNS protocol attacks exploit fundamental weaknesses in the design and behavior 
of the DNS protocol itself. These attacks manipulate how DNS queries and responses 
are processed, often leveraging the lack of authentication in standard DNS.
For lack of a better category, DHCP DNS Spoofing which exploits the DHCP protocol was also added in this set of attacks. 

## Attacks

- **[DNS Rebinding](rebinding.md)** – Bypasses the Same-Origin Policy by 
manipulating DNS responses to point a domain to an internal IP address
- **[DHCP DNS Spoofing](dhcp-dns-spoofing.md)** – Abuses DHCP to inject a 
malicious DNS server into a victim's network configuration