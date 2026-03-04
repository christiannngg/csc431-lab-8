import socket, time

HOST, PORT = "127.0.0.1", 9999

#Plaintext Traffic Generator (should NOT be blocked)
messages = [
    "GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "Hello this is normal readable plaintext traffic for testing purposes okay",
    "username=admin&password=hello&action=login&redirect=dashboard&lang=en",
]

print("[*] Sending LOW-entropy plaintext packets...")
for i, msg in enumerate(messages):
    s = socket.socket()
    s.connect((HOST, PORT))
    s.sendall(msg.encode())
    s.close()
    print(f"  Sent packet {i+1}: entropy should be ~4.0-5.5")
    time.sleep(0.5)

print("[*] Done. Detector should NOT have flagged these.")