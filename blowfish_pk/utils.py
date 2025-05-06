import struct
from .core import encrypt_block, decrypt_block

def pad(text: bytes) -> bytes:
    pad_len = 8 - (len(text) % 8)
    return text + bytes([pad_len] * pad_len)

def unpad(text: bytes) -> bytes:
    pad_len = text[-1]
    return text[:-pad_len]

def encrypt_text(plaintext_bytes: bytes) -> bytes:
    ciphertext = b""
    padded = pad(plaintext_bytes)
    for i in range(0, len(padded), 8):
        block = padded[i:i+8]
        L, R = struct.unpack('>II', block)
        L_enc, R_enc = encrypt_block(L, R)
        ciphertext += struct.pack('>II', L_enc, R_enc)
    return ciphertext

def decrypt_text(ciphertext_bytes: bytes) -> bytes:
    plaintext = b""
    for i in range(0, len(ciphertext_bytes), 8):
        block = ciphertext_bytes[i:i+8]
        L, R = struct.unpack('>II', block)
        L_dec, R_dec = decrypt_block(L, R)
        plaintext += struct.pack('>II', L_dec, R_dec)
    return unpad(plaintext)