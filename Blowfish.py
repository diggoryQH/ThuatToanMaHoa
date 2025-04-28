import struct
import binascii


class Blowfish:
    def __init__(self, key):
        self.P = [
            0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
            0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
            0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
            0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
            0x9216d5d9, 0x8979fb1b
        ]

        self.S = [
            [
                0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7,
                0x2b8acf1c, 0x32e1372c, 0xe87ad031, 0xb58fa362
            ],
            [
                0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72,
                0x28958677, 0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b
            ],
            [
                0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
                0x4fe1356d, 0xa6a2d5b7, 0x748f82ee, 0x78a5636f
            ],
            [
                0x42242190, 0x0fc1c4b2, 0x31ac1153, 0xa25be6a5,
                0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354
            ]
        ]

        self._init_key(key)

    def _init_key(self, key):
        key_len = len(key)
        j = 0

        # Khởi tạo P-array với khóa
        for i in range(len(self.P)):
            data = 0
            for k in range(4):
                data = (data << 8) | key[j % key_len]
                j += 1
            self.P[i] ^= data

        # Áp dụng thuật toán để thay đổi P-array và S-boxes
        L, R = 0, 0
        for i in range(0, len(self.P), 2):
            L, R = self._encrypt_block(L, R)
            self.P[i] = L
            self.P[i + 1] = R

        for i in range(4):
            for j in range(0, len(self.S[i]), 2):
                L, R = self._encrypt_block(L, R)
                self.S[i][j] = L
                self.S[i][j + 1] = R

    def _f_function(self, x):
        s0 = self.S[0][(x >> 24) % len(self.S[0])]
        s1 = self.S[1][((x >> 16) & 0xff) % len(self.S[1])]
        s2 = self.S[2][((x >> 8) & 0xff) % len(self.S[2])]
        s3 = self.S[3][(x & 0xff) % len(self.S[3])]
        h = (s0 + s1) & 0xFFFFFFFF
        return ((h ^ s2) + s3) & 0xFFFFFFFF

    def _encrypt_block(self, L, R):
        for i in range(16):
            L = (L ^ self.P[i]) & 0xFFFFFFFF
            R = (R ^ self._f_function(L)) & 0xFFFFFFFF
            L, R = R, L

        L, R = R, L  # Hoán đổi lần cuối
        R = (R ^ self.P[16]) & 0xFFFFFFFF
        L = (L ^ self.P[17]) & 0xFFFFFFFF

        return L, R

    def _decrypt_block(self, L, R):
        for i in range(17, 1, -1):
            L = (L ^ self.P[i]) & 0xFFFFFFFF
            R = (R ^ self._f_function(L)) & 0xFFFFFFFF
            L, R = R, L

        L, R = R, L  # Hoán đổi lần cuối
        R = (R ^ self.P[1]) & 0xFFFFFFFF
        L = (L ^ self.P[0]) & 0xFFFFFFFF

        return L, R

    def encrypt(self, data):
        result = b""
        # Pad dữ liệu nếu cần thiết để đạt kích thước khối 8 byte
        padded_data = data + b'\0' * (8 - len(data) % 8 if len(data) % 8 != 0 else 0)

        for i in range(0, len(padded_data), 8):
            block = padded_data[i:i + 8]
            L, = struct.unpack(">I", block[0:4])
            R, = struct.unpack(">I", block[4:8])

            L, R = self._encrypt_block(L, R)

            result += struct.pack(">I", L) + struct.pack(">I", R)

        return result

    def decrypt(self, data):
        result = b""

        for i in range(0, len(data), 8):
            block = data[i:i + 8]
            L, = struct.unpack(">I", block[0:4])
            R, = struct.unpack(">I", block[4:8])

            L, R = self._decrypt_block(L, R)

            result += struct.pack(">I", L) + struct.pack(">I", R)

        return result.rstrip(b'\0')


# Ví dụ sử dụng
def blowfish_example():
    key = b"MySecretKey123"
    plaintext = b"Hello PTIT"

    cipher = Blowfish(key)

    encrypted = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(encrypted)

    print(f"Plaintext: {plaintext}")
    print(f"Encrypted (hex): {binascii.hexlify(encrypted)}")
    print(f"Decrypted: {decrypted}")


if __name__ == "__main__":
    blowfish_example()
