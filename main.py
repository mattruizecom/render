import miniupnpc
import socket
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk

# Function to discover and forward port using UPnP
def forward_port(port):
    # Initialize UPnP
    upnp = miniupnpc.UPnP()
    upnp.discoverdelay = 200
    found = upnp.discover()

    if found > 0:
        upnp.selectigd()
        print("Router found: {}".format(upnp.routername))

        # Try to add a port mapping
        try:
            external_port = port
            internal_port = port
            internal_ip = upnp.lanaddr

            # Update progress bar
            progress_bar.start()
            upnp.addportmapping(external_port, 'TCP', internal_ip, internal_port, 'Minecraft Server', '')
            progress_bar.stop()

            # Success message
            messagebox.showinfo("Success", "Port {} forwarded to {}:{}".format(external_port, internal_ip, internal_port))
            print("Port {} forwarded to {}:{}".format(external_port, internal_ip, internal_port))
            display_forwarded_info(internal_ip, external_port)
        except Exception as e:
            progress_bar.stop()
            messagebox.showerror("Error", "Failed to forward port: {}".format(e))
            print("Error: {}".format(e))  # Log the error in the console
    else:
        messagebox.showerror("Error", "No UPnP router found.")
        print("No UPnP router found.")  # Log this message in the console

def display_forwarded_info(ip, port):
    result_label.config(text="Public IP: {}, Port: {}".format(ip, port))

# Function to find open ports
def find_open_ports():
    open_ports = []
    for port in range(25565, 65535):  # Starting from Minecraft default port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set timeout for the connection attempt
        result = sock.connect_ex(('127.0.0.1', port))  # Change to your local network address if needed
        if result != 0:
            open_ports.append(port)
        sock.close()
        if len(open_ports) >= 5:  # Limit to 5 open ports
            break

    if open_ports:
        open_ports_str = "\n".join(map(str, open_ports))
        messagebox.showinfo("Open Ports", "Available ports:\n{}".format(open_ports_str))
        port_entry.delete(0, tk.END)
        port_entry.insert(0, str(open_ports[0]))  # Set the first open port as default
    else:
        messagebox.showwarning("No Open Ports", "No available ports found.")

# Setup GUI
def start_program():
    try:
        port = int(port_entry.get())
        forward_port(port)
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid port number.")

# Create the main window
root = tk.Tk()
root.title("Minecraft Server Port Forwarding")

# Create a frame for the port scanning functionality
frame = tk.Frame(root)
frame.pack(pady=10)

find_ports_button = tk.Button(frame, text="Find Open Ports on Network", command=find_open_ports)
find_ports_button.pack(side=tk.LEFT, padx=5)

# Progress bar
progress_bar = ttk.Progressbar(frame, mode='indeterminate')
progress_bar.pack(side=tk.LEFT, padx=5)

tk.Label(root, text="Enter Minecraft Server Port:").pack(pady=10)
port_entry = tk.Entry(root)
port_entry.insert(0, "25565")  # Default port
port_entry.pack(pady=10)

start_button = tk.Button(root, text="Start Port Forwarding", command=start_program)
start_button.pack(pady=20)

# Label to display forwarded information
result_label = tk.Label(root, text="")
result_label.pack(pady=10)

root.mainloop()

# Keep console open
input("Press Enter to exit...")
