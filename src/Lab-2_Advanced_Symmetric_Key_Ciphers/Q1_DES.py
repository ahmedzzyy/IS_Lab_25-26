from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def encrypt(key, plaintext, mode=DES.MODE_ECB):
    cipher = DES.new(key, mode)

    padded_message = pad(plaintext.encode(), DES.block_size)

    ciphertext = cipher.encrypt(padded_message)

    return ciphertext


def decrypt(key, ciphertext, mode=DES.MODE_ECB):
    decipher = DES.new(key, mode)

    decrypted_padded = decipher.decrypt(ciphertext)

    decrypted_message = unpad(decrypted_padded, DES.block_size).decode()

    return decrypted_message


def main():
    key = b"A1B2C3D4"
    pt = "Confidential Data"  # Plaintext

    ct = encrypt(key, pt)
    print(f"Ciphertext (in bytes) : {ct}")
    print(f"Ciphertext (in hex)   : {ct.hex()}")

    dt = decrypt(key, ct)
    print(f"Decrypted Message     : {dt}")
    print(f"Decryption Successful : {dt == pt}")


if __name__ == "__main__":
    main()
