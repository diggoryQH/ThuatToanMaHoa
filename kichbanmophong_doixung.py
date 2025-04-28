import struct
import binascii
import os
from datetime import datetime

# ==========================
# Blowfish đầy đủ S-box
# ==========================

class Blowfish:
    def __init__(self, key):
        self.P = [
            0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
            0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
            0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
            0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
            0x9216D5D9, 0x8979FB1B
        ]

        # Full S-boxes 256 elements each (you can get full from RFC 2451 or online reference)
        self.S = [[i for i in range(256)] for _ in range(4)]  # Dummy S-box for demo

        self._init_key(key)

    def _init_key(self, key):
        key_len = len(key)
        j = 0

        for i in range(len(self.P)):
            data = 0
            for _ in range(4):
                data = (data << 8) | key[j % key_len]
                j += 1
            self.P[i] ^= data

        L, R = 0, 0
        for i in range(0, len(self.P), 2):
            L, R = self._encrypt_block(L, R)
            self.P[i] = L
            self.P[i + 1] = R

        for i in range(4):
            for j in range(0, len(self.S[i]), 2):
                L, R = self._encrypt_block(L, R)
                self.S[i][j] = L & 0xFFFFFFFF
                self.S[i][j + 1] = R & 0xFFFFFFFF

    def _f_function(self, x):
        a = (x >> 24) & 0xFF
        b = (x >> 16) & 0xFF
        c = (x >> 8) & 0xFF
        d = x & 0xFF

        h = (self.S[0][a] + self.S[1][b]) & 0xFFFFFFFF
        h ^= self.S[2][c]
        h = (h + self.S[3][d]) & 0xFFFFFFFF
        return h

    def _encrypt_block(self, L, R):
        for i in range(16):
            L = L ^ self.P[i]
            R = self._f_function(L) ^ R
            L, R = R, L
        L, R = R, L
        R = R ^ self.P[16]
        L = L ^ self.P[17]
        return L, R

    def _decrypt_block(self, L, R):
        for i in range(17, 1, -1):
            L = L ^ self.P[i]
            R = self._f_function(L) ^ R
            L, R = R, L
        L, R = R, L
        R = R ^ self.P[1]
        L = L ^ self.P[0]
        return L, R

    def encrypt(self, data):
        result = b""
        padding_len = 8 - (len(data) % 8)
        data += bytes([padding_len]) * padding_len

        for i in range(0, len(data), 8):
            block = data[i:i + 8]
            L, = struct.unpack(">I", block[:4])
            R, = struct.unpack(">I", block[4:])
            L, R = self._encrypt_block(L, R)
            result += struct.pack(">I", L) + struct.pack(">I", R)

        return result

    def decrypt(self, data):
        result = b""
        for i in range(0, len(data), 8):
            block = data[i:i + 8]
            L, = struct.unpack(">I", block[:4])
            R, = struct.unpack(">I", block[4:])
            L, R = self._decrypt_block(L, R)
            result += struct.pack(">I", L) + struct.pack(">I", R)

        padding_len = result[-1]
        return result[:-padding_len]


# ==========================
# Kịch bản mô phỏng đối xứng
# ==========================

class Person:
    def __init__(self, name):
        self.name = name
        self.received_messages = []

    def __str__(self):
        return self.name


class SymmetricMessaging:
    def __init__(self, algorithm='blowfish'):
        self.algorithm = algorithm
        self.shared_key = os.urandom(16)  # 128-bit key

        if algorithm == 'blowfish':
            self.cipher = Blowfish(self.shared_key)
        else:
            raise ValueError("Thuật toán chưa hỗ trợ!")

    def setup_key_exchange(self, sender, recipient):
        print(f"\n----- THIẾT LẬP KHÓA ĐỐI XỨNG ({self.algorithm.upper()}) -----")
        print(f"[Thiết lập] {sender} và {recipient} chia sẻ khóa bí mật: {binascii.hexlify(self.shared_key).decode()}")
        print(f"[Thiết lập] Khóa đã được trao đổi qua kênh an toàn")
        print("-" * 50)

    def send_message(self, sender, recipient, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"\n----- {sender} GỬI TIN NHẮN ĐẾN {recipient} -----")
        print(f"[{timestamp}] {sender}: Tin nhắn gốc: {message}")

        encrypted = self.cipher.encrypt(message.encode('utf-8'))
        print(f"[{timestamp}] {sender}: Tin nhắn đã mã hóa: {binascii.hexlify(encrypted).decode()}")

        print(f"[{timestamp}] {sender}: Gửi tin nhắn đã mã hóa đến {recipient}")

        print(f"\n----- {recipient} NHẬN TIN NHẮN TỪ {sender} -----")
        print(f"[{timestamp}] {recipient}: Nhận được tin nhắn đã mã hóa: {binascii.hexlify(encrypted).decode()}")
        decrypted = self.cipher.decrypt(encrypted).decode('utf-8')
        print(f"[{timestamp}] {recipient}: Tin nhắn đã giải mã: {decrypted}")

        recipient.received_messages.append({
            'from': sender.name,
            'message': decrypted,
            'timestamp': timestamp
        })

        print("-" * 50)


def symmetric_messaging_scenario():
    alice = Person("Alice")
    bob = Person("Bob")

    messaging = SymmetricMessaging(algorithm='blowfish')
    messaging.setup_key_exchange(alice, bob)

    messaging.send_message(alice, bob, "Xin chào Bob! Đây là tin nhắn bí mật từ Alice")
    messaging.send_message(bob, alice, "Chào Alice! Mình đã nhận được tin nhắn của bạn, cảm ơn")

    print("\n----- KIỂM TRA TIN NHẮN ĐÃ NHẬN -----")
    print(f"Tin nhắn của Bob:")
    for msg in bob.received_messages:
        print(f"  - Từ {msg['from']} ({msg['timestamp']}): {msg['message']}")

    print(f"\nTin nhắn của Alice:")
    for msg in alice.received_messages:
        print(f"  - Từ {msg['from']} ({msg['timestamp']}): {msg['message']}")


if __name__ == "__main__":
    symmetric_messaging_scenario()
