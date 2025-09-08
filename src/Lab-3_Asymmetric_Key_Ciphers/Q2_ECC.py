from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import os


def generate_ecc_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    return private_key, public_key


def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

    # Derive a symmetric key from the shared key
    derived_key = hashes.Hash(hashes.SHA256())
    derived_key.update(shared_key)

    return derived_key.finalize()[:32]  # AES-256 key


def encrypt(key, plaintext):
    nonce = os.urandom(16)  # number used once

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))  # ECB not used
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    tag = encryptor.tag

    return ciphertext, nonce, tag


def decrypt(key, ciphertext, nonce, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))

    decryptor = cipher.decryptor()
    decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_bytes.decode()


def main():
    # Variable name idea, credit: ChatGPT
    alice_private_key, alice_public_key = generate_ecc_keypair()
    bob_private_key, bob_public_key = generate_ecc_keypair()

    pem_public_alice = alice_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    print("Alice's Public Key:")
    print(pem_public_alice.decode())
    print()

    aes_key_bob = derive_shared_key(bob_private_key, alice_public_key)

    pt = "Secure Transactions"  # Plaintext

    ct, nonce, tag = encrypt(aes_key_bob, pt)

    print(f"Ciphertext (in bytes) : {ct}")
    print(f"Ciphertext (in hex)   : {ct.hex()}")
    print(f"Nonce (in hex)        : {nonce.hex()}")
    print(f"Tag (in hex)          : {tag.hex()}")

    dt = decrypt(aes_key_bob, ct, nonce, tag)
    print(f"Decrypted Text        : {dt}")
    print(f"Decryption Successful : {dt == pt}")


if __name__ == "__main__":
    main()
