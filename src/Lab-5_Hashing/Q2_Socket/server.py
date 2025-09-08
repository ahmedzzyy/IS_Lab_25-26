import socket


def hash_function(text):
    hash_value = 5381

    for char in text:
        hash_value = (hash_value * 33) + ord(char)
        hash_value &= 0xFFFFFFFF  # 32-bit

    return hash_value


HOST = "127.0.0.1"
PORT = 5000

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"[SERVER] Listening on {HOST}:{PORT} ...")

    conn, addr = s.accept()
    with conn:
        print(f"[SERVER] Connected by {addr}")
        data = conn.recv(1024).decode()
        print("[SERVER] Received:", data)

        # compute hash
        h = hash_function(data)
        print("[SERVER] Hash:", h)

        # send hash back to client
        conn.sendall(str(h).encode())
