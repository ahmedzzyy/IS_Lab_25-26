from Crypto.PublicKey import RSA


def generate_keys(key_size=1024):
    key = RSA.generate(key_size)

    return key.n, key.e, key.d


def encrypt(public_key, plaintext):
    n, e = public_key

    plaintext_int = int.from_bytes(plaintext.encode(), byteorder="big")

    # c = m^e mod n
    ciphertext_int = pow(plaintext_int, e, n)

    return ciphertext_int


def decrypt(private_key, ciphertext):
    n, d = private_key

    # m = c^d mod n
    decrypted_int = pow(ciphertext, d, n)

    byte_length = (decrypted_int.bit_length() + 7) // 8
    decrypted_message = decrypted_int.to_bytes(byte_length, byteorder="big").decode()

    return decrypted_message


def main():
    n, e, d = generate_keys()

    public_key = (n, e)
    private_key = (n, d)

    pt = "Asymmetric Encryption"  # Plaintext

    ct = encrypt(public_key, pt)
    print(f"Ciphertext (as integer) : {ct}")
    print(f"Ciphertext (in hex)     : {hex(ct)}")

    dt = decrypt(private_key, ct)
    print(f"Decrypted Message       : {dt}")
    print(f"Decryption Successful   : {dt == pt}")


if __name__ == "__main__":
    main()
