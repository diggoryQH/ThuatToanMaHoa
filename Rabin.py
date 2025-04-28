import random
import math
import binascii


class Rabin:
    def __init__(self, key_size=512):
        self.p, self.q, self.n = self._generate_keys(key_size)
        self.public_key = self.n
        self.private_key = (self.p, self.q)

    def _generate_keys(self, key_size):
        p = self._generate_prime(key_size // 2)
        q = self._generate_prime(key_size // 2)
        n = p * q
        return p, q, n

    def _generate_prime(self, bits):
        while True:
            p = random.getrandbits(bits)
            p |= 3  # đảm bảo p ≡ 3 mod 4
            if self._is_prime(p):
                return p

    def _is_prime(self, n, k=5):
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def encrypt(self, message):
        # Tính checksum: tổng các byte % 256
        checksum = sum(message) % 256
        message_with_checksum = bytes([checksum]) + message

        m = int.from_bytes(message_with_checksum, byteorder='big')
        if m >= self.n:
            raise ValueError("Thông điệp quá lớn cho khóa hiện tại")

        c = pow(m, 2, self.n)

        return c.to_bytes((c.bit_length() + 7) // 8, byteorder='big')

    def decrypt(self, ciphertext):
        c = int.from_bytes(ciphertext, byteorder='big')
        roots = self._compute_square_roots(c)

        for root in roots:
            try:
                bytes_data = root.to_bytes((root.bit_length() + 7) // 8, byteorder='big')
                if len(bytes_data) < 2:
                    continue

                checksum = bytes_data[0]
                message = bytes_data[1:]

                if sum(message) % 256 == checksum:
                    return message
            except Exception:
                continue

        raise ValueError("Không thể giải mã chính xác")

    def _compute_square_roots(self, c):
        mp = pow(c, (self.p + 1) // 4, self.p)
        mq = pow(c, (self.q + 1) // 4, self.q)

        gcd, yp, yq = self._extended_gcd(self.p, self.q)

        u = (yp * self.p * mq) % self.n
        v = (yq * self.q * mp) % self.n

        r1 = (u + v) % self.n
        r2 = (u - v) % self.n
        r3 = self.n - r1
        r4 = self.n - r2

        return [r1, r2, r3, r4]

    def _extended_gcd(self, a, b):
        if a == 0:
            return b, 0, 1

        gcd, x1, y1 = self._extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1

        return gcd, x, y


# Ví dụ sử dụng Rabin
def rabin_example():
    rabin = Rabin(key_size=512)

    message = b"Day la tin nhan bi mat can bao ve"

    print(f"Khóa công khai (n): {rabin.public_key}")
    print(f"Khóa bí mật (p, q): ({rabin.private_key[0]}, {rabin.private_key[1]})")
    print(f"Thông điệp gốc: {message}")

    encrypted = rabin.encrypt(message)
    print(f"Dữ liệu mã hóa (hex): {binascii.hexlify(encrypted)}")

    decrypted = rabin.decrypt(encrypted)
    print(f"Dữ liệu giải mã: {decrypted}")

    assert decrypted == message, "Mã hóa và giải mã không khớp!"
    print("Mã hóa và giải mã thành công!")


if __name__ == "__main__":
    rabin_example()
