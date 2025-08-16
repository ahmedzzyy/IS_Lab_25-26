PLAIN_TEXT = "I am learning information security"
ADDITIVE_KEY = 20
MULTIPLICATIVE_KEY = 15
AFFINE_KEY = (15, 20)


def additive_encrypt(plaintext: str, key: int):
    ciphertext: list[str] = []
    for char in plaintext:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shifted = (ord(char) - base + key) % 26
            ciphertext.append(chr(base + shifted))
        else:
            ciphertext.append(char)
    return "".join(ciphertext)


def additive_decrypt(ciphertext: str, key: int):
    plaintext: list[str] = []
    for char in ciphertext:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shifted = (ord(char) - base - key) % 26
            plaintext.append(chr(base + shifted))
        else:
            plaintext.append(char)
    return "".join(plaintext)


def multiplicative_encrypt(plaintext: str, key: int):
    ciphertext: list[str] = []
    for char in plaintext:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            x = ord(char) - base
            enc = (x * key) % 26
            ciphertext.append(chr(base + enc))
        else:
            ciphertext.append(char)
    return "".join(ciphertext)


def multiplicative_decrypt(ciphertext: str, key: int):
    plaintext: list[str] = []
    inv_key = pow(key, -1, 26)
    for char in ciphertext:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            x = ord(char) - base
            dec = (x * inv_key) % 26
            plaintext.append(chr(base + dec))
        else:
            plaintext.append(char)
    return "".join(plaintext)


def affine_encrypt(plaintext: str, key: tuple[int, int]):
    a, b = key
    ciphertext: list[str] = []
    for char in plaintext:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            x = ord(char) - base
            enc = (a * x + b) % 26
            ciphertext.append(chr(base + enc))
        else:
            ciphertext.append(char)
    return "".join(ciphertext)


def affine_decrypt(ciphertext: str, key: tuple[int, int]):
    a, b = key
    inv_a = pow(a, -1, 26)
    plaintext: list[str] = []
    for char in ciphertext:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            y = ord(char) - base
            dec = (inv_a * (y - b)) % 26
            plaintext.append(chr(base + dec))
        else:
            plaintext.append(char)
    return "".join(plaintext)


if __name__ == "__main__":
    print("---- ADDITIVE CIPHER ----")
    cipher_text = additive_encrypt(PLAIN_TEXT, ADDITIVE_KEY)
    print(f"Ciphertext: {cipher_text}")

    plain_text = additive_decrypt(cipher_text, ADDITIVE_KEY)
    print(f"Decrypted: {plain_text}")

    print("---- MULTIPLICATIVE CIPHER ----")
    cipher_text = multiplicative_encrypt(PLAIN_TEXT, MULTIPLICATIVE_KEY)
    print(f"Ciphertext: {cipher_text}")

    plain_text = multiplicative_decrypt(cipher_text, MULTIPLICATIVE_KEY)
    print(f"Decrypted: {plain_text}")

    print("---- AFFINE CIPHER ----")
    cipher_text = affine_encrypt(PLAIN_TEXT, AFFINE_KEY)
    print(f"Ciphertext: {cipher_text}")

    plain_text = affine_decrypt(cipher_text, AFFINE_KEY)
    print(f"Decrypted: {plain_text}")
