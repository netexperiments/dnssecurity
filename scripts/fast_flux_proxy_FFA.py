from flask import Flask, request, Response
import requests

app = Flask(__name__)


CC_MACHINE_IP = "10.0.3.1"
CC_MACHINE_PORT = 8080

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def proxy(path):
    
    # Acts as a reverse proxy, forwarding requests to the C&C server.
    
    try:
        
        target_url = f"http://{CC_MACHINE_IP}:{CC_MACHINE_PORT}/{path}"
        
        
        print(f"[*] Proxying request from {request.remote_addr} to -> {target_url}")

        
        if request.method == 'GET':
            resp = requests.get(target_url, params=request.args, stream=True)
        else:
            resp = requests.post(target_url, data=request.form, stream=True)

        
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for name, value in resp.raw.headers.items() if name.lower() not in excluded_headers]
        
        
        print(f"[*] Forwarding response from C&C server to client with status code {resp.status_code}")

        
        return Response(resp.raw.read(), resp.status_code, headers)

    except requests.exceptions.RequestException as e:
        print(f"Error forwarding request to C&C server: {e}")
        return Response(f"Proxy error: Could not reach C&C server", status=502)

if __name__ == '__main__':
    print(f"FFA Proxy Server is starting, listening on port 80.")
    print(f"Forwarding requests to the C&C server at {CC_MACHINE_IP}:{CC_MACHINE_PORT}.")
    app.run(host='0.0.0.0', port=80, debug=False)