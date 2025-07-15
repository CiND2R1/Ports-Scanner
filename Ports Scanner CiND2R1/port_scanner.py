import socket
import threading
from queue import Queue
import time

# Get target from user
target = input("🖥️ Enter target IP or domain: ").strip()

# Get ports from user
port_input = input("🔢 Enter ports (e.g., 53,67 or 1-1024): ").strip()
port_range = []

# Parse port input
if '-' in port_input:
    start_port, end_port = map(int, port_input.split('-'))
    port_range = range(start_port, end_port + 1)
else:
    port_range = [int(p.strip()) for p in port_input.split(',')]

# Choose scan type
scan_type = input("📡 Choose scan type (TCP/UDP): ").strip().lower()

# Configuration
num_threads = 100
open_ports = []
queue = Queue()

# Get service name
def get_service_name(port, protocol='tcp'):
    try:
        return socket.getservbyport(port, protocol)
    except:
        return "Unknown"

# TCP scanning function
def scan_tcp_port(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            service = get_service_name(port, 'tcp')
            print(f"[+] TCP Port {port} is open — Service: {service}")
            open_ports.append((port, service, 'TCP'))
        sock.close()
    except:
        pass

# UDP scanning function
def scan_udp_port(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(b'\x00', (target, port))
        try:
            data, _ = sock.recvfrom(1024)
            service = get_service_name(port, 'udp')
            print(f"[+] UDP Port {port} is open or responding — Service: {service}")
            open_ports.append((port, service, 'UDP'))
        except socket.timeout:
            service = get_service_name(port, 'udp')
            print(f"[?] UDP Port {port} might be open (no response) — Service: {service}")
            open_ports.append((port, service, 'UDP'))
        sock.close()
    except:
        pass

# Worker function
def worker():
    while not queue.empty():
        port = queue.get()
        if scan_type == 'tcp':
            scan_tcp_port(port)
        elif scan_type == 'udp':
            scan_udp_port(port)
        queue.task_done()

# Start time
start_time = time.time()

# Fill queue
for port in port_range:
    queue.put(port)

# Start threads
threads = []
for _ in range(num_threads):
    t = threading.Thread(target=worker)
    t.start()
    threads.append(t)

# Wait for completion
for t in threads:
    t.join()

# End time
end_time = time.time()
elapsed_time = end_time - start_time

# Final result
print("\n✅ Scan completed.")
if open_ports:
    print("📋 Open ports and services:")
    for port, service, protocol in open_ports:
        print(f"- {protocol} Port {port}: {service}")
else:
    print("❌ No open ports found.")

# Save results
with open("scan_results.txt", "w") as f:
    f.write(f"Target: {target}\n")
    f.write(f"Scanned Ports: {port_input}\n")
    f.write(f"Scan Type: {scan_type.upper()}\n")
    f.write(f"Time Taken: {elapsed_time:.2f} seconds\n")
    f.write("Open Ports:\n")
    if open_ports:
        for port, service, protocol in open_ports:
            f.write(f"- {protocol} Port {port}: {service}\n")
    else:
        f.write("None\n")

print("📁 Results saved to scan_results.txt")