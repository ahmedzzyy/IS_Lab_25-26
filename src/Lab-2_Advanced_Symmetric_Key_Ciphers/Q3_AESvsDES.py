import time

from Q1_DES import encrypt as des_encrypt, decrypt as des_decrypt
from Q2_AES_128 import encrypt as aes_encrypt, decrypt as aes_decrypt

message = "Performance Testing of Encryption Algorithms"
des_key = b"A1B2C3D4"  # 8 bytes for DES
aes_key = des_key * 4  # 32 bytes for AES-256

start_time = time.perf_counter()
des_ciphertext = des_encrypt(des_key, message)
des_encryption_time = time.perf_counter() - start_time

start_time = time.perf_counter()
des_decrypted = des_decrypt(des_key, des_ciphertext)
des_decryption_time = time.perf_counter() - start_time

start_time = time.perf_counter()
aes_ciphertext = aes_encrypt(aes_key, message)
aes_encryption_time = time.perf_counter() - start_time

start_time = time.perf_counter()
aes_decrypted = aes_decrypt(aes_key, aes_ciphertext)
aes_decryption_time = time.perf_counter() - start_time

print("DES Encryption Time     : {:.10f} seconds".format(des_encryption_time))
print("DES Decryption Time     : {:.10f} seconds".format(des_decryption_time))
print("AES-256 Encryption Time : {:.10f} seconds".format(aes_encryption_time))
print("AES-256 Decryption Time : {:.10f} seconds".format(aes_decryption_time))
