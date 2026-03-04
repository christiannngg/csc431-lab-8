import socket

# Dummy Listener (needed so senders don't get connection refused)
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9999))
s.listen(10)
print("[*] Listener ready on port 9999...")
while True:
    conn, addr = s.accept()
    data = conn.recv(4096)
    conn.close()