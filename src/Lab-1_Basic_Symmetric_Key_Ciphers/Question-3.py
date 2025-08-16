PLAIN_TEXT = "The key is hidden under the door pad"
PLAYFAIR_KEY = "GUIDANCE"


def prepare_text(text: str):
    text = text.upper().replace("J", "I")
    return "".join([c for c in text if c.isalpha()])


def chunk_pairs(text: str):
    pairs: list[str] = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else "X"
        if a == b:
            pairs.append(a + "X")
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    return pairs


def create_matrix(key: str):
    key = prepare_text(key)
    matrix: list[str] = []
    for char in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in matrix:
            matrix.append(char)
    return [matrix[i : i + 5] for i in range(0, 25, 5)]


def find_position(matrix: list[list[str]], char: str):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    raise ValueError(f"Char {char} not found in matrix")


def playfair_encrypt(plaintext: str, key: str) -> str:
    matrix = create_matrix(key)
    text = prepare_text(plaintext)
    pairs = chunk_pairs(text)
    ciphertext: list[str] = []

    for pair in pairs:
        r1, c1 = find_position(matrix, pair[0])
        r2, c2 = find_position(matrix, pair[1])
        if r1 == r2:  # same row
            ciphertext.append(matrix[r1][(c1 + 1) % 5])
            ciphertext.append(matrix[r2][(c2 + 1) % 5])
        elif c1 == c2:  # same column
            ciphertext.append(matrix[(r1 + 1) % 5][c1])
            ciphertext.append(matrix[(r2 + 1) % 5][c2])
        else:  # rectangle rule
            ciphertext.append(matrix[r1][c2])
            ciphertext.append(matrix[r2][c1])
    return "".join(ciphertext)


def playfair_decrypt(ciphertext: str, key: str) -> str:
    matrix = create_matrix(key)
    pairs = [ciphertext[i : i + 2] for i in range(0, len(ciphertext), 2)]
    plaintext: list[str] = []

    for pair in pairs:
        r1, c1 = find_position(matrix, pair[0])
        r2, c2 = find_position(matrix, pair[1])
        if r1 == r2:  # same row
            plaintext.append(matrix[r1][(c1 - 1) % 5])
            plaintext.append(matrix[r2][(c2 - 1) % 5])
        elif c1 == c2:  # same column
            plaintext.append(matrix[(r1 - 1) % 5][c1])
            plaintext.append(matrix[(r2 - 1) % 5][c2])
        else:  # rectangle rule
            plaintext.append(matrix[r1][c2])
            plaintext.append(matrix[r2][c1])
    return "".join(plaintext)


if __name__ == "__main__":
    print("---- PLAYFAIR CIPHER ----")
    cipher_text = playfair_encrypt(PLAIN_TEXT, PLAYFAIR_KEY)
    print(f"Ciphertext: {cipher_text}")

    plain_text = playfair_decrypt(cipher_text, PLAYFAIR_KEY)
    print(f"Decrypted: {plain_text}")
