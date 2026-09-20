## DNS-SecLab

DNS-SecLab is a hands-on study of DNS security, developed as part of a Master's dissertation at Instituto Superior Técnico (IST). It covers defensive mechanisms that strengthen DNS integrity and privacy, as well as a broad range of DNS attack techniques and their countermeasures, all demonstrated in a controlled GNS3 lab environment.

## Documentation

Documentation site: [https://netexperiments.github.io/dnssecurity/](https://netexperiments.github.io/dnssecurity/)

## Repository

Source repository: [https://github.com/netexperiments/dnssecurity](https://github.com/netexperiments/dnssecurity)

## Current Version

v1.0.0

## License

Apache-2.0

## Required Tools

- GNS3
- Docker
- Wireshark
- Linux virtual machines or containers
- DNS server software (e.g., BIND) where required by specific labs

## Contents

- [Lab Setup](https://netexperiments.github.io/dnssecurity/setup/): overview of the GNS3-based lab environment used to perform and analyze the experiments
- [DNS Security and Privacy Enhancements](https://netexperiments.github.io/dnssecurity/enhancements/): modern protocols and extensions that improve DNS security
- [DNS Attacks and Countermeasures](https://netexperiments.github.io/dnssecurity/attacks/): demonstration and analysis of DNS attack techniques

## Supported Experiments

### DNS Security and Privacy Enhancements

- DNSSEC
- DNS-over-HTTPS (DoH)

### DNS Protocol and Resolution Attacks

- DNS Rebinding
- DHCP DNS Spoofing

### DNS Server and Infrastructure Attacks

- NXDOMAIN DDoS
- DNS Cache Poisoning
- Kaminsky Cache Poisoning
- Unauthorized Zone Transfer
- DNS ARP Poisoning

### DNS Abuse and Misuse Attacks

- DNS Amplification
- DNS Fast Flux (single-based)
- DNS Fast Flux (double-based)
- DNS Tunneling
- DGA-based attacks
- Fast Flux and DGA-based Tunneling


## Disclaimer

The attack experiments in this project are intended for education and research and must only be run inside the isolated lab environment described in the documentation. Do not use these techniques against systems you do not own or have explicit permission to test.


## How to Cite

Zenodo DOI: [https://doi.org/10.5281/zenodo.22855457](https://doi.org/10.5281/zenodo.22855457)