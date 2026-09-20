import socket
import sys

HOST = '0.0.0.0'  # Listen on all available network interfaces
PORT = 9999       # The port to listen on, must match the sender's port

def handle_client(conn, addr):
    """
    Handle incoming data from a single connection.
    """
    print(f"Connection established with {addr}")
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            
            received_message = data.decode('utf-8').strip()
            print(f"Received from {addr}: {received_message}")
            
    except ConnectionResetError:
        print(f"Connection with {addr} was reset.")
    except Exception as e:
        print(f"An error occurred with connection from {addr}: {e}")
    finally:
        conn.close()
        print(f"Connection with {addr} closed.")

if __name__ == "__main__":
    print(f"Starting data receiver on port {PORT}...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            print("Listening for incoming connections...")
            
            while True:
                conn, addr = s.accept()
                # Handle each connection in a new thread or process for a real application.
                handle_client(conn, addr)
                
    except KeyboardInterrupt:
        print("\nServer is shutting down.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        sys.exit(0)
