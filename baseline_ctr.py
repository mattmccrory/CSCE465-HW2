
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Fixed command required by the assignment
MESSAGE = b'{"action":"READ","path":"notes.txt"}'


def encrypt(key, iv, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def relay(ciphertext):
    # Change READ to WRITE without knowing the encryption key.
    modified = bytearray(ciphertext)

    original = b"READ"
    replacement = b"WRIT"

    offset = MESSAGE.index(original)

    # XOR the ciphertext with the difference between
    # the original and replacement plaintext.
    for i in range(len(original)):
        delta = original[i] ^ replacement[i]
        modified[offset + i] ^= delta

    return bytes(modified)


def receiver(key, iv, ciphertext, processed):
    plaintext = decrypt(key, iv, ciphertext)
    command = plaintext.decode()

    processed.append(command)
    print("Receiver processed:", command)


def main():
    key = os.urandom(32)
    iv = os.urandom(16)

    print("Original plaintext:", MESSAGE.decode())

    ciphertext = encrypt(key, iv, MESSAGE)
    print("\nOriginal ciphertext:", ciphertext.hex())

    # Demonstrate bit-flipping
    modified_ciphertext = relay(ciphertext)

    print("\nModified ciphertext:", modified_ciphertext.hex())

    modified_plaintext = decrypt(key, iv, modified_ciphertext)

    print("Modified plaintext:", modified_plaintext.decode())

    # Demonstrate XOR relationship
    original_bytes = MESSAGE
    modified_bytes = modified_plaintext

    print("\nXOR differences:")
    for i in range(len(original_bytes)):
        if original_bytes[i] != modified_bytes[i]:
            print(
                f"Position {i}: "
                f"{original_bytes[i]:02x} XOR "
                f"{modified_bytes[i]:02x} = "
                f"{original_bytes[i] ^ modified_bytes[i]:02x}"
            )

    # Demonstrate replay
    print("\n--- Replay Attack ---")

    processed = []

    print("First transmission:")
    receiver(key, iv, ciphertext, processed)

    print("\nSecond transmission (replay):")
    receiver(key, iv, ciphertext, processed)

    print("\nTotal commands processed:", len(processed))


if __name__ == "__main__":
    main()
