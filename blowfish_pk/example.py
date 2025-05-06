from blowfish_pk.utils import encrypt_text, decrypt_text

if __name__ == "__main__":
    plaintext = b"To jest tajna wiadomosc!"
    print(f"Plaintext: {plaintext}")

    encrypted = encrypt_text(plaintext)
    print(f"Encrypted: {encrypted}")

    decrypted = decrypt_text(encrypted)
    print(f"Decrypted: {decrypted}")