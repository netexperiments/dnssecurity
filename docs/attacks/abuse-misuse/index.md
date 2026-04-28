# DNS Abuse and Misuse Attacks

DNS abuse attacks exploit the DNS protocol and infrastructure for purposes 
beyond name resolution. These attacks use DNS as a vehicle for malicious 
activity, taking advantage of its ubiquity and the fact that DNS traffic 
is rarely blocked or inspected.

## Attacks

- **[DNS Amplification](amplification.md)** – Abuses open DNS resolvers to 
amplify traffic in DDoS attacks against third-party targets
- **[DNS Fast Flux (Single)-based](ff-single.md)** – Rapidly rotates DNS A records 
to hide malicious infrastructure behind a constantly changing set of IP addresses
- **[DNS Fast Flux (Double)-based](ff-double.md)** – Extends single fast flux by 
also rotating the authoritative name servers, adding another layer of evasion
- **[DNS Tunneling](tunneling.md)** – Encodes non-DNS traffic inside DNS 
queries and responses to exfiltrate data or bypass network controls
- **[DGA-based](dgas.md)** – Uses Domain Generation Algorithms to produce 
large numbers of domain names for botnet C&C communication
- **[Fast Flux and DGA-based Tunneling](ff-dgas-tunneling.md)** – Combines Fast Flux and DGA techniques with DNS 
tunneling for resilient and covert C&C channels