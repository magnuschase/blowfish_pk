P_ARRAY = [0x243F6A88, 0x85A308D3] + [0] * 16
S_BOXES = [[i for i in range(256)] for _ in range(4)]

def F(x):
    a = (x >> 24) & 0xFF
    b = (x >> 16) & 0xFF
    c = (x >> 8) & 0xFF
    d = x & 0xFF
    return ((S_BOXES[0][a] + S_BOXES[1][b]) ^ S_BOXES[2][c]) + S_BOXES[3][d]

def encrypt_block(L, R):
    for i in range(16):
        L ^= P_ARRAY[i]
        R ^= F(L)
        L, R = R, L
    L, R = R, L
    R ^= P_ARRAY[16]
    L ^= P_ARRAY[17]
    return L, R

def decrypt_block(L, R):
    for i in reversed(range(2, 18)):
        L ^= P_ARRAY[i]
        R ^= F(L)
        L, R = R, L
    L, R = R, L
    R ^= P_ARRAY[1]
    L ^= P_ARRAY[0]
    return L, R