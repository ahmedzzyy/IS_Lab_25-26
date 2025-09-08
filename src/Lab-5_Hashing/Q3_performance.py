import hashlib
import random
import secrets
import string
import time


def random_string_secrets(length=12):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


dataset_size = random.randint(50, 100)  # between 50 and 100 strings
dataset = [random_string_secrets(12) for _ in range(dataset_size)]
print(f"Generated dataset of {dataset_size} random strings\n")


def compute_hashes(dataset, algo="md5"):
    hashes = []
    start = time.time()
    for data in dataset:
        if algo == "md5":
            h = hashlib.md5(data.encode()).hexdigest()
        elif algo == "sha1":
            h = hashlib.sha1(data.encode()).hexdigest()
        elif algo == "sha256":
            h = hashlib.sha256(data.encode()).hexdigest()
        hashes.append(h)
    end = time.time()
    return hashes, (end - start)


def detect_collisions(hashes):
    seen = {}
    collisions = []
    for i, h in enumerate(hashes):
        if h in seen:
            collisions.append((seen[h], i))
        else:
            seen[h] = i
    return collisions


results = {}
for algo in ["md5", "sha1", "sha256"]:
    hashes, elapsed = compute_hashes(dataset, algo)
    collisions = detect_collisions(hashes)
    results[algo] = {
        "time": elapsed,
        "collisions": collisions,
        "hash_count": len(hashes),
    }

for algo, info in results.items():
    print(f"Algorithm: {algo.upper()}")
    print(f" - Time taken: {info['time']:.6f} seconds")
    print(f" - Total hashes: {info['hash_count']}")
    if info["collisions"]:
        print(f" - Collisions detected! {info['collisions']}")
    else:
        print(" - No collisions detected")
    print()
