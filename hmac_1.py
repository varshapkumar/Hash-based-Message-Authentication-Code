from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import hmac
import hashlib

def encrypt_aes(key: bytes, plaintext: bytes) -> tuple:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padding_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + bytes([padding_length] * padding_length)
    
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv, ciphertext

def decrypt_aes(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    padding_length = padded_plaintext[-1]
    plaintext = padded_plaintext[:-padding_length]
    return plaintext

def generate_hmac(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def verify_hmac(key: bytes, data: bytes, received_hmac: str) -> bool:
    computed_hmac = generate_hmac(key, data)
    return hmac.compare_digest(computed_hmac, received_hmac)

key_input = input("Enter a secret key (16, 24, or 32 characters): ").encode()
if len(key_input) not in (16, 24, 32):
    print("❌ Key must be exactly 16, 24, or 32 bytes for AES.")
    exit()

message_input = input("Enter the message: ").encode()

iv, ciphertext = encrypt_aes(key_input, message_input)
print("\nEncrypted message (hex):", ciphertext.hex())
print("IV (hex):", iv.hex())

hmac_value = generate_hmac(key_input, ciphertext)
print("HMAC of encrypted message:", hmac_value)

hmac_to_verify = input("\nEnter HMAC to verify: ")

if verify_hmac(key_input, ciphertext, hmac_to_verify):
    print("✅ HMAC verification successful! Decrypting message...")
    decrypted_message = decrypt_aes(key_input, iv, ciphertext)
    print("Decrypted message:", decrypted_message.decode())
else:
    print("❌ HMAC verification failed! Message may be corrupted or tampered.")
