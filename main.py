import socket
import requests
import threading
import time
import tkinter as tk
from tkinter import messagebox, scrolledtext, Canvas
import urllib.request
import subprocess

# Global variable to store the selected port forwarding method
selected_method = None

# Function to get local and public IP addresses
def get_ip_addresses():
    local_ip = socket.gethostbyname(socket.gethostname())
    try:
        public_ip = urllib.request.urlopen('https://api.ipify.org').read().decode('utf8')
    except Exception as e:
        public_ip = "Unable to retrieve public IP"
    return local_ip, public_ip

# Constants
SERVER_URL = "http://scandalous-global-catamaran.glitch.me"  # Your Glitch URL (HTTP)
LOCAL_PORT = 25565  # Minecraft default port

# Get local IP address
LOCAL_IP, _ = get_ip_addresses()  # Initialize LOCAL_IP from the function

# Forward traffic to Minecraft server
def forward_to_minecraft(data):
    try:
        print(f"Forwarding data to Minecraft: {data.decode()}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((LOCAL_IP, LOCAL_PORT))
            s.sendall(data)
            response = s.recv(1024)
            print(f"Received response from Minecraft server: {response.decode()}")
            return response
    except Exception as e:
        print(f"Error forwarding to Minecraft: {e}")
        return None

# Send HTTP request to the Express server
def send_http_request(data):
    try:
        response = requests.post(SERVER_URL, json={"message": data})
        if response.status_code == 200:
            print("Data sent to Express server successfully.")
            return response.json()
        else:
            print(f"Failed to send data. Status code: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"HTTP Request failed: {e}")
        return None

# Handle incoming messages
def on_message(message):
    print(f"Message received: {message}")
    response = forward_to_minecraft(message.encode())
    if response:
        print("Data forwarded successfully to Minecraft server.")
        send_http_request("Data forwarded successfully to Minecraft server.")
    else:
        print("Failed to forward data.")
        send_http_request("Failed to forward data.")

# Simulate receiving messages for testing
def simulate_incoming_messages():
    while True:
        message = "Test message from WebSocket"
        on_message(message)
        time.sleep(5)

# Function to test connection to the Glitch server
def test_connection():
    try:
        response = requests.get(f"{SERVER_URL}/secret")
        if response.status_code == 200:
            secret_key = response.text
            messagebox.showinfo("Connection Test", f"Secret key retrieved: {secret_key}")
        else:
            messagebox.showwarning("Connection Test", "Failed to retrieve secret key.")
    except requests.RequestException as e:
        messagebox.showerror("Connection Test", f"Connection failed: {e}")

# Function to send message to Glitch server output
## Make sure this label is declared in the global scope or in the function where you're creating the UI

confirmation_label = None  # Declare the variable at the beginning

def create_gui():
    global confirmation_label  # Declare it as global if created inside this function
    
    # Your other GUI setup code here...
    
    # Add the label for confirmation near your input fields
    confirmation_label = tk.Label(root, text="")
    confirmation_label.pack(pady=5)

def submit_message():
    message = message_entry.get()
    
    if message:
        response = send_http_request(message)
        if response:
            confirmation_label.config(text="Message sent successfully.", fg="green")
        else:
            confirmation_label.config(text="Failed to send message to the server.", fg="red")
    else:
        confirmation_label.config(text="Please enter a message to send.", fg="orange")

# Function to refresh active connections
def refresh_connections(text_area, canvas, label, port):
    text_area.config(state=tk.NORMAL)
    text_area.delete('1.0', tk.END)
    canvas.delete("all")
    label.config(text="")
    check_active_connections(port, text_area, canvas, label)

# Function to check active connections and display Minecraft status
def check_active_connections(port, text_area=None, canvas=None, label=None):
    try:
        command = f'netstat -ano | findstr :{port}'
        result = subprocess.check_output(command, shell=True, text=True)

        if text_area is None:
            connection_window = tk.Toplevel()
            connection_window.title("Active Connections")

            text_area = scrolledtext.ScrolledText(connection_window, wrap=tk.WORD, width=50, height=15)
            text_area.pack(pady=10)

            canvas = Canvas(connection_window, width=200, height=200)
            canvas.pack()

            label = tk.Label(connection_window, font=("Arial", 14))
            label.pack()

            refresh_button = tk.Button(connection_window, text="Refresh", command=lambda: refresh_connections(text_area, canvas, label, port))
            refresh_button.pack(side=tk.RIGHT, padx=10, pady=5)

        if result:
            text_area.insert(tk.END, result)
            if "ESTABLISHED" in result or "LISTENING" in result:
                canvas.create_oval(50, 50, 150, 150, fill="green")
                label.config(text="Minecraft server is deployed and listening on port 25565")
        else:
            messagebox.showwarning("No Active Connections", "Make sure the Minecraft server is running.")

        text_area.config(state=tk.DISABLED)
    except subprocess.CalledProcessError as e:
        if "returned non-zero exit status" in str(e):
            messagebox.showerror("NO SERVER FOUND RUNNING ON PORT", f"Failed to check active connections: {e}")
        else:
            messagebox.showerror("Error", f"Failed to check active connections: {e}")

# Function to handle port forwarding
def port_forward():
    global selected_method

    if selected_method is None:
        messagebox.showwarning("Port Forwarding", "Please select a port forwarding method first.")
        return

    public_ip = public_ip_entry.get()
    port = port_entry.get()
    server_name = server_name_entry.get()

    payload = {
        'command': 'port_forward',
        'ip': public_ip,
        'port': port,
        'message': f"{server_name} (Method: {selected_method})"
    }

    try:
        if selected_method == "TCP":
            start_tcp_tunnel(int(port))
        elif selected_method == "HTTP":
            response = requests.post(f"{SERVER_URL}/command", json=payload)
            if response.status_code == 200:
                messagebox.showinfo("Port Forwarding", f"Response: {response.json().get('message')}")
            else:
                messagebox.showerror("Port Forwarding Failed", "Failed to forward port.")
        else:
            messagebox.showinfo("Port Forwarding", f"Selected method '{selected_method}' is not implemented.")
    except Exception as e:
        messagebox.showerror("Port Forwarding Error", f"Error: {e}")

# Function to start the TCP tunnel for port forwarding
def start_tcp_tunnel(port):
    def handle_connection(client_socket, remote_host, remote_port):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((remote_host, remote_port))

            threading.Thread(target=forward_data, args=(client_socket, server_socket)).start()
            threading.Thread(target=forward_data, args=(server_socket, client_socket)).start()
        except Exception as e:
            print(f"Error establishing connection: {e}")
            client_socket.close()

    def forward_data(source_socket, destination_socket):
        try:
            while True:
                data = source_socket.recv(4096)
                if not data:
                    break
                destination_socket.sendall(data)
        except Exception as e:
            print(f"Error forwarding data: {e}")
        finally:
            source_socket.close()
            destination_socket.close()

    threading.Thread(target=lambda: handle_connection, args=(port,), daemon=True).start()
    messagebox.showinfo("TCP Tunnel", f"TCP Tunnel started on port {port}.")

# Function to check port forwarding methods and make them selectable
def check_port_forwarding_methods():
    global selected_method

    # Clear any previous content from the box
    methods_box.delete(0, tk.END)

    methods = []

    # Check TCP method
    try:
        tcp_test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_result = tcp_test.connect_ex((LOCAL_IP, LOCAL_PORT))
        tcp_status = "TCP: Enabled" if tcp_result == 0 else "TCP: Disabled"
    except Exception:
        tcp_status = "TCP: Error checking"
    if "Enabled" in tcp_status:
        methods.append("TCP")
    methods_box.insert(tk.END, tcp_status)

    # Check UDP method
    try:
        udp_test = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_result = udp_test.connect_ex((LOCAL_IP, LOCAL_PORT))
        udp_status = "UDP: Enabled" if udp_result == 0 else "UDP: Disabled"
    except Exception:
        udp_status = "UDP: Error checking"
    if "Enabled" in udp_status:
        methods.append("UDP")
    methods_box.insert(tk.END, udp_status)

    # Check HTTP method
    try:
        http_response = requests.get(SERVER_URL)
        http_status = f"HTTP: {http_response.status_code}"
        if http_response.status_code == 200:
            methods.append("HTTP")
    except Exception:
        http_status = "HTTP: Error checking"
    methods_box.insert(tk.END, http_status)

    # Add checkboxes for each method
    def select_method():
        selected_method = methods_box.get(tk.ACTIVE)

    tk.Button(root, text="Select Method", command=select_method).pack(pady=5)

# Tkinter GUI
root = tk.Tk()
root.title("Port Forwarding GUI")

server_name_label = tk.Label(root, text="Server Name:")
server_name_label.pack(pady=5)
server_name_entry = tk.Entry(root)
server_name_entry.pack(pady=5)

ip_label = tk.Label(root, text="Your IPV4:")
ip_label.pack(pady=5)
public_ip_entry = tk.Entry(root)
public_ip_entry.insert(0, LOCAL_IP)  # Use local IP (192.168.0.245)
public_ip_entry.pack(pady=5)

port_label = tk.Label(root, text="Port:")
port_label.pack(pady=5)
port_entry = tk.Entry(root)
port_entry.insert(0, "25565")  # Autofill with port 25565
port_entry.pack(pady=5)

test_button = tk.Button(root, text="Test Connection", command=test_connection)
test_button.pack(side=tk.LEFT, padx=10, pady=5)

methods_button = tk.Button(root, text="Check Methods", command=check_port_forwarding_methods)
methods_button.pack(side=tk.LEFT, padx=10, pady=5)

submit_button = tk.Button(root, text="Port Forward", command=port_forward)
submit_button.pack(side=tk.LEFT, padx=10, pady=5)

refresh_button = tk.Button(root, text="Check Connections", command=lambda: check_active_connections(port_entry.get()))
refresh_button.pack(side=tk.LEFT, padx=10, pady=5)

message_label = tk.Label(root, text="")
message_label.pack(pady=5)
message_entry = tk.Entry(root)
message_entry.pack(pady=5)

# Listbox to display methods
methods_box = tk.Listbox(root, height=5)
methods_box.pack(pady=5)

submit_message_button = tk.Button(root, text="Submit Message", command=submit_message)
submit_message_button.pack(side=tk.LEFT, padx=10, pady=5)

root.mainloop()
