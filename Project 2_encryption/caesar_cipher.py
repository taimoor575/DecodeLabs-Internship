def encrypt(text: str, shift: int) -> str:
    """
    Encrypts the given text using a Caesar cipher with the given shift (key).

    Edge case handling:
        - Uppercase letters (A-Z) are shifted within the uppercase range.
        - Lowercase letters (a-z) are shifted within the lowercase range.
        - Non-alphabetic characters (spaces, punctuation, digits, symbols)
          are left completely untouched, since they have no "letter
          position" to shift.
    """
    result = []

    for char in text:
        if char.isupper():
            # Subtract base (65), add key, wrap with modulo, add base back
            shifted = (ord(char) - ord('A') + shift) % 26 + ord('A')
            result.append(chr(shifted))
        elif char.islower():
            # Same logic, but lowercase base is 97
            shifted = (ord(char) - ord('a') + shift) % 26 + ord('a')
            result.append(chr(shifted))
        else:
            # Spaces, punctuation, numbers, emojis, etc. pass through untouched
            result.append(char)

    return "".join(result)


def decrypt(cipher_text: str, shift: int) -> str:
    """
    Decrypts Caesar-ciphered text using the same key.

    Since Caesar cipher is symmetric encryption (same key locks and
    unlocks), decryption is simply encryption with a negative shift.
    Reusing encrypt() avoids duplicating logic and keeps a single
    source of truth for the math.
    """
    return encrypt(cipher_text, -shift)


def validate(original: str, shift: int) -> bool:
    """
    Validation step required by the project brief:
    Encrypts the original text, then decrypts the result, and checks
    that it matches the original exactly. This proves the cipher logic
    is correctly reversible.
    """
    cipher_text = encrypt(original, shift)
    decrypted_text = decrypt(cipher_text, shift)
    return decrypted_text == original


def get_valid_shift() -> int:
    """Prompts the user for a shift key and validates the input."""
    while True:
        raw = input("Enter shift key (an integer, e.g. 3): ").strip()
        try:
            return int(raw)
        except ValueError:
            print("  Invalid input. Please enter a whole number (e.g. 3 or -5).\n")


def main():
    print("=" * 60)
    print(" DecodeLabs | Project 2: Basic Encryption & Decryption")
    print(" Caesar Cipher - Confidentiality Logic Demo")
    print("=" * 60)

    # ---- INPUT ----
    plaintext = input("\nEnter the text you want to encrypt: ")
    shift = get_valid_shift()

    # ---- PROCESS ----
    cipher_text = encrypt(plaintext, shift)
    decrypted_text = decrypt(cipher_text, shift)
    is_valid = validate(plaintext, shift)

    # ---- OUTPUT ----
    print("\n" + "-" * 60)
    print(f"{'Original Text':<18}: {plaintext}")
    print(f"{'Shift Key (n)':<18}: {shift}")
    print(f"{'Encrypted Text':<18}: {cipher_text}")
    print(f"{'Decrypted Text':<18}: {decrypted_text}")
    print("-" * 60)

    if is_valid:
        print("Validation PASSED: Decrypted text matches the original. ✔")
    else:
        print("Validation FAILED: Something went wrong in the cipher logic. ✘")
    print("=" * 60)


if __name__ == "__main__":
    main()
