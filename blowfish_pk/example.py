from blowfish_pk.utils import encrypt_text, decrypt_text
from blowfish_pk.core import generate_keys, save_keys
# from blowfish_pk.core import load_keys

if __name__ == "__main__":
    # Key generation & saving
    generate_keys()
    save_keys("keys_example.json")
    
    # Loading keys
    # load_keys("keys_example.json")
    
		# Example usage
    plaintext = b"To jest tajna wiadomosc!"
    print(f"Plaintext: {plaintext}")

    encrypted = encrypt_text(plaintext)
    print(f"Encrypted: {encrypted}")

    decrypted = decrypt_text(encrypted)
    print(f"Decrypted: {decrypted}")