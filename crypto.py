# crypto.py
import base64, os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


# ================= KEY DERIVATION =================
def derive_fernet_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


# ================= WRAP / UNWRAP USER KEY =================
def wrap_user_key(user_key: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    fkey = derive_fernet_key(password, salt)
    f = Fernet(fkey)
    token = f.encrypt(user_key)
    return salt + token


def unwrap_user_key(wrapped: bytes, password: str) -> bytes:
    salt = wrapped[:16]
    token = wrapped[16:]
    fkey = derive_fernet_key(password, salt)
    f = Fernet(fkey)
    return f.decrypt(token)


# ================= LCG KEYSTREAM =================
def generate_keystream(key: bytes, length: int):
    # Seed dari key (biar user-specific)
    seed = sum(key) % 256

    # Parameter LCG (standar)
    a = 1103515245
    c = 12345
    m = 256

    ks = []
    k = seed

    for _ in range(length):
        k = (a * k + c) % m
        ks.append(k)

    return ks


# ================= XOR ENCRYPT =================
def xor_encrypt(data: bytes, key: bytes) -> bytes:
    ks = generate_keystream(key, len(data))
    out = bytearray()

    for i, b in enumerate(data):
        # XOR + LCG + transformasi tambahan
        val = b ^ ks[i] ^ ((i * 7) % 256)
        out.append(val)

    return bytes(out)


# ================= XOR DECRYPT =================
def xor_decrypt(data: bytes, key: bytes) -> bytes:
    ks = generate_keystream(key, len(data))
    out = bytearray()

    for i, b in enumerate(data):
        # sama karena XOR simetris
        val = b ^ ks[i] ^ ((i * 7) % 256)
        out.append(val)

    return bytes(out)


# ================= TEST (OPSIONAL) =================
if __name__ == "__main__":
    text = "hello world"
    key = b"secretkey"

    enc = xor_encrypt(text.encode(), key)
    dec = xor_decrypt(enc, key)

    print("Plaintext :", text)
    print("Encrypted :", enc)
    print("Decrypted :", dec.decode())