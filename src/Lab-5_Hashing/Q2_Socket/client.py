import socket


def hash_function(text):
    hash_value = 5381

    for char in text:
        hash_value = (hash_value * 33) + ord(char)
        hash_value &= 0xFFFFFFFF  # 32-bit

    return hash_value


HOST = "127.0.0.1"
PORT = 5000

msg = input("Enter message: ")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    s.sendall(msg.encode())

    # local_msg = msg + "X" # Corrupts message
    local_msg = msg

    server_hash = int(s.recv(1024).decode())
    local_hash = hash_function(local_msg)

    print("[CLIENT] Original msg:", msg)
    print("[CLIENT] Local hash :", local_hash)
    print("[CLIENT] Server hash:", server_hash)

    if local_hash == server_hash:
        print("[CLIENT] Data integrity verified")
    else:
        print("[CLIENT] Data corruption detected!")
