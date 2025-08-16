PLAIN_TEXT = "the house is being sold tonight"
VIGENERE_KEY = "dollars"
AUTOKEY_KEY = 7


def vigenere_encrypt(plaintext: str, key: str):
    ciphertext: list[str] = []
    key = key.upper()
    key_index = 0

    for char in plaintext:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shift = ord(key[key_index % len(key)]) - ord("A")
            enc = (ord(char) - base + shift) % 26
            ciphertext.append(chr(base + enc))
            key_index += 1
        else:
            ciphertext.append(char)
    return "".join(ciphertext)


def vigenere_decrypt(ciphertext: str, key: str):
    plaintext: list[str] = []
    key = key.upper()
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shift = ord(key[key_index % len(key)]) - ord("A")
            dec = (ord(char) - base - shift) % 26
            plaintext.append(chr(base + dec))
            key_index += 1
        else:
            plaintext.append(char)
    return "".join(plaintext)


def autokey_encrypt(plaintext: str, key: int) -> str:
    ciphertext: list[str] = []
    key_stream: list[int] = [key]

    for char in plaintext:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shift = key_stream[0] % 26
            enc = (ord(char) - base + shift) % 26
            cipher_char = chr(base + enc)
            ciphertext.append(cipher_char)

            key_stream.append(ord(char.upper()) - ord("A"))
            key_stream.pop(0)
        else:
            ciphertext.append(char)
    return "".join(ciphertext)


def autokey_decrypt(ciphertext: str, key: int) -> str:
    plaintext: list[str] = []
    key_stream: list[int] = [key]

    for char in ciphertext:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shift = key_stream[0] % 26
            dec = (ord(char) - base - shift) % 26
            plain_char = chr(base + dec)
            plaintext.append(plain_char)

            key_stream.append(ord(plain_char.upper()) - ord("A"))
            key_stream.pop(0)
        else:
            plaintext.append(char)
    return "".join(plaintext)


if __name__ == "__main__":
    print("---- VIGENÈRE CIPHER ----")
    cipher_text = vigenere_encrypt(PLAIN_TEXT, VIGENERE_KEY)
    print(f"Ciphertext: {cipher_text}")

    plain_text = vigenere_decrypt(cipher_text, VIGENERE_KEY)
    print(f"Decrypted: {plain_text}")

    print("---- AUTOKEY CIPHER ----")
    cipher_text = autokey_encrypt(PLAIN_TEXT, AUTOKEY_KEY)
    print(f"Ciphertext: {cipher_text}")

    plain_text = autokey_decrypt(cipher_text, AUTOKEY_KEY)
    print(f"Decrypted: {plain_text}")
