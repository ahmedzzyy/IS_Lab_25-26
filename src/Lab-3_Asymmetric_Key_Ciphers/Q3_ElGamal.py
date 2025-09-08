from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random


def generate_keys(bits=256):
    p = getPrime(bits)
    g = random.randint(2, p - 2)
    x = random.randint(1, p - 2)  # Private key
    y = pow(g, x, p)  # Public key
    return (p, g, y), x  # Return public and private keys


def encrypt(plaintext, public_key):
    (p, g, y) = public_key
    k = random.randint(1, p - 2)

    # c1 = g^k mod p
    c1 = pow(g, k, p)

    m = bytes_to_long(plaintext.encode())
    # c2 = m * y^k mod p
    c2 = (m * pow(y, k, p)) % p

    return c1, c2


def decrypt(ciphertext, private_key, public_key):
    (c1, c2) = ciphertext
    (p, g, y) = public_key
    x = private_key

    # s = c1^x mod p
    s = pow(c1, x, p)
    # m = c2 * s^(-1) mod p
    m = (c2 * inverse(s, p)) % p

    return long_to_bytes(m).decode()


def main():
    (p, g, y), private_key = generate_keys()

    print("Public Key:")
    print("p (prime)       :", p)
    print("g (generator)   :", g)
    print("y (public key)  :", y)
    print("Private Key:")
    print("x               :", private_key)

    pt = "Confidential Data"

    ct1, ct2 = encrypt(pt, (p, g, y))
    print("\nCiphertext:")
    print("c1 :", ct1)
    print("c2 :", ct2)

    dt = decrypt((ct1, ct2), private_key, (p, g, y))
    print(f"Decrypted Text        : {dt}")
    print(f"Decryption Successful : {dt == pt}")


if __name__ == "__main__":
    main()
