from Crypto.PublicKey import DSA
from Crypto.Random import get_random_bytes
import time


def generate_dh_keypair(p, g):
    private_key = int.from_bytes(get_random_bytes(32), byteorder="big") % p

    public_key = pow(g, private_key, p)

    return private_key, public_key


def compute_shared_secret(their_public, my_private, p):
    return pow(their_public, my_private, p)


def main():
    dh_params = DSA.generate(2048)
    p = dh_params.p
    g = dh_params.g

    # Peer 1
    start = time.perf_counter()
    alice_private, alice_public = generate_dh_keypair(p, g)
    key_gen_time_alice = time.perf_counter() - start

    # Peer 2
    start = time.perf_counter()
    bob_private, bob_public = generate_dh_keypair(p, g)
    key_gen_time_bob = time.perf_counter() - start

    # Peer 1
    start = time.perf_counter()
    shared_secret_alice = compute_shared_secret(bob_public, alice_private, p)
    key_exchange_time_alice = time.perf_counter() - start

    # Peer 2
    start = time.perf_counter()
    shared_secret_bob = compute_shared_secret(alice_public, bob_private, p)
    key_exchange_time_bob = time.perf_counter() - start

    print(f"Key Generation Time (Alice): {key_gen_time_alice:.10f} seconds")
    print(f"Key Generation Time (Bob)  : {key_gen_time_bob:.10f} seconds")
    print()
    print(f"Key Exchange Time (Alice)  : {key_exchange_time_alice:.10f} seconds")
    print(f"Key Exchange Time (Bob)    : {key_exchange_time_bob:.10f} seconds")
    print()
    print(f"Shared secrets match       : {shared_secret_alice == shared_secret_bob}")


if __name__ == "__main__":
    main()
