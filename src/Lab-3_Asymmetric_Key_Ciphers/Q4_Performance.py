import time
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


# --- RSA Hybrid Functions --- #
def rsa_hybrid_encrypt(file_data, rsa_key):
    aes_key = get_random_bytes(32)  # AES-256
    aes_cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = aes_cipher.encrypt_and_digest(file_data)
    rsa_cipher = PKCS1_OAEP.new(rsa_key.publickey())
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    return encrypted_aes_key, aes_cipher.nonce, ciphertext, tag


def rsa_hybrid_decrypt(encrypted_aes_key, nonce, ciphertext, tag, rsa_key):
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)
    aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = aes_cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_data


# --- ECC Hybrid Functions (AES + Signing) --- #
def ecc_hybrid_encrypt(file_data, ecc_key):
    aes_key = get_random_bytes(32)
    aes_cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = aes_cipher.encrypt_and_digest(file_data)
    h = SHA256.new(aes_key)
    signer = DSS.new(ecc_key, "fips-186-3")
    signature = signer.sign(h)
    return signature, aes_cipher.nonce, ciphertext, tag


# --- Main Performance Test --- #
def main():
    # Generate RSA & ECC keys
    rsa_key = RSA.generate(2048)
    ecc_key = ECC.generate(curve="P-256")

    # Test files
    file_1mb = get_random_bytes(1024 * 1024)
    file_10mb = get_random_bytes(1024 * 1024 * 10)

    # --- RSA 1MB --- #
    start = time.perf_counter()
    enc_aes_key, nonce, ciphertext, tag = rsa_hybrid_encrypt(file_1mb, rsa_key)
    rsa_enc_time_1mb = time.perf_counter() - start

    start = time.perf_counter()
    rsa_hybrid_decrypt(enc_aes_key, nonce, ciphertext, tag, rsa_key)
    rsa_dec_time_1mb = time.perf_counter() - start

    # --- RSA 10MB --- #
    start = time.perf_counter()
    enc_aes_key, nonce, ciphertext, tag = rsa_hybrid_encrypt(file_10mb, rsa_key)
    rsa_enc_time_10mb = time.perf_counter() - start

    start = time.perf_counter()
    rsa_hybrid_decrypt(enc_aes_key, nonce, ciphertext, tag, rsa_key)
    rsa_dec_time_10mb = time.perf_counter() - start

    # --- ECC 1MB --- #
    start = time.perf_counter()
    ecc_signature, nonce, ecc_ciphertext, tag = ecc_hybrid_encrypt(file_1mb, ecc_key)
    ecc_enc_time_1mb = time.perf_counter() - start

    # --- ECC 10MB --- #
    start = time.perf_counter()
    ecc_signature, nonce, ecc_ciphertext, tag = ecc_hybrid_encrypt(file_10mb, ecc_key)
    ecc_enc_time_10mb = time.perf_counter() - start

    # --- Print Results --- #
    print("RSA Encryption Time (1MB) : {:.10f} seconds".format(rsa_enc_time_1mb))
    print("RSA Decryption Time (1MB) : {:.10f} seconds".format(rsa_dec_time_1mb))
    print("RSA Encryption Time (10MB): {:.10f} seconds".format(rsa_enc_time_10mb))
    print("RSA Decryption Time (10MB): {:.10f} seconds".format(rsa_dec_time_10mb))
    print()
    print("ECC Encryption Time (1MB) : {:.10f} seconds".format(ecc_enc_time_1mb))
    print("ECC Encryption Time (10MB): {:.10f} seconds".format(ecc_enc_time_10mb))


if __name__ == "__main__":
    main()
