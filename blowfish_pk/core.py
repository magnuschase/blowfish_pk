import secrets
import json
import os

# Default keys for simplified Blowfish algorithm
P_ARRAY = [0x243F6A88, 0x85A308D3] + [0] * 16
S_BOXES = [[i for i in range(256)] for _ in range(4)]

# Generation of random keys for Blowfish - int32 arrays
# Since keys are 32 bit integers, we need to mask values to 32 bits during encryption/decryption
def generate_keys():
    global P_ARRAY, S_BOXES
    P_ARRAY = [secrets.randbits(32) for _ in range(18)]
    S_BOXES = [[secrets.randbits(32) for _ in range(256)] for _ in range(4)]

def save_keys(filename="blowfish_keys.json"):
    keys = {
        "P_ARRAY": P_ARRAY,
        "S_BOXES": S_BOXES
    }
    with open(filename, "w") as f:
        json.dump(keys, f)

def load_keys(filename="blowfish_keys.json"):
    global P_ARRAY, S_BOXES
    if not os.path.exists(filename):
        raise FileNotFoundError(f"Key file '{filename}' not found.")
    with open(filename, "r") as f:
        keys = json.load(f)
        P_ARRAY = keys["P_ARRAY"]
        S_BOXES = keys["S_BOXES"]

def F(x):
    a = (x >> 24) & 0xFF
    b = (x >> 16) & 0xFF
    c = (x >> 8) & 0xFF
    d = x & 0xFF
    return (((S_BOXES[0][a] + S_BOXES[1][b]) & 0xFFFFFFFF) ^ S_BOXES[2][c] + S_BOXES[3][d]) & 0xFFFFFFFF

def encrypt_block(L, R):
    for i in range(16):
        L = (L ^ P_ARRAY[i]) & 0xFFFFFFFF
        R = (R ^ F(L)) & 0xFFFFFFFF
        L, R = R, L
    L, R = R, L
    R = (R ^ P_ARRAY[16]) & 0xFFFFFFFF
    L = (L ^ P_ARRAY[17]) & 0xFFFFFFFF
    return L, R

def decrypt_block(L, R):
    for i in reversed(range(2, 18)):
        L = (L ^ P_ARRAY[i]) & 0xFFFFFFFF
        R = (R ^ F(L)) & 0xFFFFFFFF
        L, R = R, L
    L, R = R, L
    R = (R ^ P_ARRAY[1]) & 0xFFFFFFFF
    L = (L ^ P_ARRAY[0]) & 0xFFFFFFFF
    return L, R