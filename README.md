# 🔐 HMAC with AES Encryption

This project provides a simple Python implementation that combines **AES encryption** with **HMAC (Hash-based Message Authentication Code)** to ensure both confidentiality and integrity of messages.

## 📌 Features

- AES encryption using CBC mode
- HMAC generation with SHA-256
- Secure message decryption only after HMAC verification
- Input-based secret key and message handling

## 🧪 How It Works

1. User enters a secret key (16, 24, or 32 bytes – AES requirement).
2. User inputs a message to encrypt.
3. The script:
   - Encrypts the message with AES.
   - Generates HMAC on the ciphertext.
4. User can input an HMAC to verify integrity.
5. If the HMAC matches, the message is decrypted and displayed.

## ▶️ Running the Code

Make sure Python 3 and `cryptography` package are installed.

```bash
pip install cryptography
python hmac_1.py
