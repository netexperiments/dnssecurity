import os
import sys
import argparse
import paramiko
import time

dnsmasq_ip = "192.168.20.2"
dnsmasq_user = "dnsadmin"
dnsmasq_password = "dnsadmin"

def register_domain_ip(domain, ip_address, hosts_file_path="/etc/dnsmasq.d/hosts/dynamic_hosts.txt"):
    """
    Registers a domain-IP pair in a DNSMasq server by updating a hosts file
    and triggering a reload.
    """
    client = None # Initialize client to None
    sftp = None   # Initialize sftp to None
    try:
        # Create the hosts file entry (as a string first)
        new_entry_str = f"{ip_address} {domain}\n"
        print(f"Attempting to register: {new_entry_str.strip()}")

        # Establish SSH connection to DNSMasq appliance
        print(f"Connecting to DNSMasq at {dnsmasq_ip} as user {dnsmasq_user}...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=dnsmasq_ip, username=dnsmasq_user, password=dnsmasq_password)

        sftp = client.open_sftp()

        # Read existing content to filter out old entries for the same IP
        existing_lines = []
        try:
            with sftp.open(hosts_file_path, 'rb') as f: # Open in binary read mode
                existing_content_bytes = f.read()
                existing_content = existing_content_bytes.decode('utf-8') # Decode bytes to string
                # Split lines, strip whitespace, and filter out empty lines
                existing_lines = [line.strip() for line in existing_content.splitlines() if line.strip()]
        except FileNotFoundError:
            print(f"Hosts file {hosts_file_path} not found on DNSMasq server. It will be created.")
        except Exception as e:
            print(f"Warning: Could not read existing hosts file ({e}). Assuming empty.")

        # Filter out lines that contain the target IP address
        updated_lines = []
        ip_found_in_existing = False
        for line in existing_lines:
            # Skip comments or lines that don't look like IP-domain pairs
            if not line or line.startswith('#'):
                updated_lines.append(line)
                continue

            parts = line.split()
            if len(parts) >= 2:
                current_ip_in_file = parts[0]
                if current_ip_in_file == ip_address:
                    print(f"Removing existing entry for IP {ip_address}: '{line}'")
                    ip_found_in_existing = True
                else:
                    updated_lines.append(line)
            else:
                # Keeps lines that might be malformed but not for the target IP
                updated_lines.append(line)

        # Adds the new entry to the updated list of lines
        updated_lines.append(new_entry_str)

        # Joins lines with newlines and ensures a final newline at the end of the file
        new_file_content = "\n".join(updated_lines) + "\n"

        # Writes the entire updated content back to the file, overwriting the old file
        new_file_content_bytes = new_file_content.encode('utf-8')
        with sftp.open(hosts_file_path, 'wb') as f: # Use 'wb' mode to overwrite
            f.write(new_file_content_bytes)
        print(f"Updated hosts file {hosts_file_path} on DNSMasq server. Added '{new_entry_str}' and removed any old entries for {ip_address}.")

        time.sleep(2)
        # Trigger DNSMasq reload
        print("Triggering DNSMasq restart using custom script...")
        client.exec_command(f'sudo /usr/local/bin/restart_dnsmasq.sh')
        time.sleep(2)
        client.exec_command(f'sudo /usr/local/bin/start_dnsmasq.sh')

             

    except paramiko.AuthenticationException:
        print(f"Authentication failed for user {dnsmasq_user} at {dnsmasq_ip}.")
        print("Please check username and password.")
        sys.exit(1)
    except paramiko.SSHException as ssh_err:
        print(f"SSH connection error: {ssh_err}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)
    finally:
        if sftp:
            sftp.close()
        if client:
            client.close()
            print("SSH connection closed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Register a domain-IP pair in a DNSMasq server.")
    parser.add_argument("--domain", required=True, help="Domain name to register (e.g., example.com).")
    parser.add_argument("--ip", required=True, help="IP address to register for the domain (e.g., 192.168.1.100).")

    args = parser.parse_args()

    register_domain_ip(
        domain=args.domain,
        ip_address=args.ip
    )










