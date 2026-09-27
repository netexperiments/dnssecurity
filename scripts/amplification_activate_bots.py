import paramiko
import time

BOT_IPS = ['10.0.2.1']
USERNAME = 'test'
PASSWORD = 'test'
SCRIPT_TO_RUN = 'sudo python3 /home/amplification.py'


def run_remote_script(ip, command, username, password):

    #Connects to a remote host via SSH and executes a command

    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        print(f"Connecting to {ip}...")
        
        
        client.connect(hostname=ip, port=22, username=username, password=password, timeout=10)
        print(f"Successfully connected to {ip}.")

        
        print(f"Executing command: '{command}' on {ip}...")
        stdin, stdout, stderr = client.exec_command(command)

        
        exit_status = stdout.channel.recv_exit_status()
        stdout_output = stdout.read().decode().strip()
        stderr_output = stderr.read().decode().strip()

    
        print(f"--- Output from {ip} (Exit Status: {exit_status}) ---")
        if stdout_output:
            print(f"STDOUT:\n{stdout_output}")
        if stderr_output:
            print(f"STDERR:\n{stderr_output}")

    except paramiko.AuthenticationException:
        print(f"ERROR: Authentication failed for {ip}.")
    except paramiko.SSHException as e:
        print(f"ERROR: Could not establish SSH connection with {ip}. Details: {e}")
    except Exception as e:
        print(f"ERROR: An unexpected error occurred with {ip}. Details: {e}")
    finally:
        if client:
            client.close()
            print(f"Connection closed for {ip}.")
        print("-" * 40)
        time.sleep(1)


if __name__ == "__main__":
    print("Starting remote script execution on all bots...")
    print("=" * 40)
    
    for ip in BOT_IPS:
        run_remote_script(ip, SCRIPT_TO_RUN, USERNAME, PASSWORD)

    print("=" * 40)
    print("Remote script execution complete on all specified bots.")