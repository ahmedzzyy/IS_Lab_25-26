from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad


def encrypt(key, plaintext, mode=DES3.MODE_ECB):
    cipher = DES3.new(key, mode)

    padded_message = pad(plaintext.encode(), DES3.block_size)

    ciphertext = cipher.encrypt(padded_message)

    return ciphertext


def decrypt(key, ciphertext, mode=DES3.MODE_ECB):
    decipher = DES3.new(key, mode)

    decrypted_padded = decipher.decrypt(ciphertext)

    decrypted_message = unpad(decrypted_padded, DES3.block_size).decode()

    return decrypted_message


def main():
    pt = "Classified Text"
    given_key = b"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
    key = given_key[:24]

    ct = encrypt(key, pt)
    print(f"Ciphertext (in bytes) : {ct}")
    print(f"Ciphertext (in hex)   : {ct.hex()}")

    dt = decrypt(key, ct)
    print(f"Decrypted Message     : {dt}")
    print(f"Decryption Successful : {dt == pt}")


if __name__ == "__main__":
    main()
