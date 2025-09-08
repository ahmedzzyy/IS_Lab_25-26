def hash_function(text):
    hash_value = 5381

    for char in text:
        hash_value = (hash_value * 33) + ord(char)
        hash_value &= 0xFFFFFFFF  # 32-bit

    return hash_value


if __name__ == "__main__":
    input_string = input("Enter a string to hash: ")
    print(f"Hash value: {hash_function(input_string)}")
