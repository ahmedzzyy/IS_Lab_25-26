import numpy as np

PLAIN_TEXT = "We live in an insecure world"
HILL_KEY = np.array([[3, 3], [2, 7]])


def prepare_text(text: str, block_size: int):
    text = "".join([c for c in text.upper() if c.isalpha()])
    while len(text) % block_size != 0:
        text += "X"
    return text


def text_to_numbers(text: str):
    return [ord(c) - ord("A") for c in text]


def numbers_to_text(nums: list[int]):
    return "".join(chr(n % 26 + ord("A")) for n in nums)


def hill_encrypt(plaintext: str, key: np.ndarray):
    block_size = key.shape[0]
    text = prepare_text(plaintext, block_size)
    nums = text_to_numbers(text)

    ciphertext_nums: list[int] = []
    for i in range(0, len(nums), block_size):
        block = np.array(nums[i : i + block_size])
        cipher_block = key.dot(block) % 26
        ciphertext_nums.extend(cipher_block)

    return numbers_to_text(ciphertext_nums)


def mod_inverse_matrix(matrix: np.ndarray, modulus: int):
    det = int(round(np.linalg.det(matrix)))  # determinant
    det_inv = pow(det % modulus, -1, modulus)  # modular inverse of determinant
    matrix_mod_inv = (
        det_inv * np.round(det * np.linalg.inv(matrix)).astype(int) % modulus
    )
    return matrix_mod_inv


def hill_decrypt(ciphertext: str, key: np.ndarray):
    block_size = key.shape[0]
    nums = text_to_numbers(ciphertext)

    key_inv = mod_inverse_matrix(key, 26)

    plaintext_nums: list[int] = []
    for i in range(0, len(nums), block_size):
        block = np.array(nums[i : i + block_size])
        plain_block = key_inv.dot(block) % 26
        plaintext_nums.extend(plain_block)

    return numbers_to_text(plaintext_nums)


if __name__ == "__main__":
    print("---- HILL CIPHER ----")
    cipher_text = hill_encrypt(PLAIN_TEXT, HILL_KEY)
    print(f"Ciphertext: {cipher_text}")

    plain_text = hill_decrypt(cipher_text, HILL_KEY)
    print(f"Decrypted: {plain_text}")
