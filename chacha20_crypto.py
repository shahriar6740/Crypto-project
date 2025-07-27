import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_key_nonce():
    """Generate a secure 256-bit key and 128-bit nonce"""
    key = os.urandom(32)     # 256-bit key
    nonce = os.urandom(16)   # 128-bit nonce required by cryptography ChaCha20
    return key, nonce

def encrypt_chacha20(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """Encrypt data using ChaCha20 stream cipher"""
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext)

def decrypt_chacha20(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt data using ChaCha20 stream cipher"""
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)

def base64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

def base64_decode(data: str) -> bytes:
    return base64.b64decode(data.encode('utf-8'))

def save_file(path: str, data: bytes):
    with open(path, 'wb') as f:
        f.write(data)

def load_file(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()


if __name__ == "__main__":
    text = b"Confidential data to encrypt!"
    key, nonce = generate_key_nonce()

    encrypted = encrypt_chacha20(key, nonce, text)
    decrypted = decrypt_chacha20(key, nonce, encrypted)

    print("Encrypted (base64):", base64_encode(encrypted))
    print("Decrypted:", decrypted.decode('utf-8'))