import socket, os, time

HOST, PORT = "127.0.0.1", 9999

# Encrypted Traffic Generator (SHOULD be blocked)
print("[*] Sending HIGH-entropy encrypted-like packets...")
for i in range(5):
    # os.urandom produces cryptographically random bytes — maximum entropy
    payload = os.urandom(256)
    s = socket.socket()
    s.connect((HOST, PORT))
    s.sendall(payload)
    s.close()
    print(f"  Sent packet {i+1}: 256 random bytes, entropy ~7.9-8.0")
    time.sleep(0.5)

print("[*] Done. Detector should have flagged + blocked 127.0.0.1 after 3 packets.")