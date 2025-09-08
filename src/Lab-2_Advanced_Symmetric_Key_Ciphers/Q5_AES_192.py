from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def encrypt(key, plaintext, mode=AES.MODE_ECB):
    cipher = AES.new(key, mode)

    padded_message = pad(plaintext.encode(), AES.block_size)

    ciphertext = cipher.encrypt(padded_message)

    return ciphertext


def decrypt(key, ciphertext, mode=AES.MODE_ECB):
    decipher = AES.new(key, mode)

    decrypted_padded = decipher.decrypt(ciphertext)

    decrypted_message = unpad(decrypted_padded, AES.block_size).decode()

    return decrypted_message


def main():
    key = b"FEDCBA9876543210FEDCBA9876543210"
    pt = "Top Secret Data"  # Plaintext

    ct = encrypt(key, pt)
    print(f"Ciphertext (in bytes) : {ct}")
    print(f"Ciphertext (in hex)   : {ct.hex()}")

    dt = decrypt(key, ct)
    print(f"Decrypted Message     : {dt}")
    print(f"Decryption Successful : {dt == pt}")


if __name__ == "__main__":
    main()
