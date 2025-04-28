import struct
import binascii

class Twofish:
    def __init__(self, key):
        self.key = key
        # Đơn giản hóa: ta không tạo key schedule phức tạp để tránh phụ thuộc thư viện
        # Ta hash key thành một số nguyên đơn giản cho demo
        self.round_keys = [sum(bytearray(key)) % 256 for _ in range(16)]

    def _pad(self, data):
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data):
        pad_len = data[-1]
        return data[:-pad_len]

    def _simple_round(self, block, round_key):
        # Đơn giản hóa cho demo: XOR từng byte với round_key
        return bytes(b ^ round_key for b in block)

    def encrypt_block(self, block):
        for rk in self.round_keys:
            block = self._simple_round(block, rk)
        return block

    def decrypt_block(self, block):
        for rk in reversed(self.round_keys):
            block = self._simple_round(block, rk)
        return block

    def encrypt(self, plaintext):
        padded_text = self._pad(plaintext)
        ciphertext = b''

        for i in range(0, len(padded_text), 16):
            block = padded_text[i:i + 16]
            ciphertext += self.encrypt_block(block)

        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = b''

        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            plaintext += self.decrypt_block(block)

        return self._unpad(plaintext)


def twofish_demo():
    key = b'MySecretKey12345'  # 16 byte key (128 bit)
    message = b'Day la tin nhan bi mat can bao ve'

    cipher = Twofish(key)

    encrypted = cipher.encrypt(message)
    decrypted = cipher.decrypt(encrypted)

    print(f"Plaintext: {message}")
    print(f"Encrypted (hex): {binascii.hexlify(encrypted)}")
    print(f"Decrypted: {decrypted}")

    assert decrypted == message, "Decrypt failed!"
    print("Demo mã hóa và giải mã thành công!")


if __name__ == "__main__":
    twofish_demo()
