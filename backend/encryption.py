"""
Vitalis EHR — AES-256-CBC Encryption Module
============================================
Encrypts / decrypts sensitive health record fields using AES-256-CBC
with a unique random IV per operation (NIST SP 800-38A compliant).

Ciphertext format:  IV (16 bytes) || AES-CBC ciphertext (PKCS7 padded)
Storage format:     Base64-encoded string of the above

Usage:
    from encryption import encrypt_field, decrypt_field

    ciphertext = encrypt_field("Patient has Type 2 Diabetes")
    plaintext  = decrypt_field(ciphertext)
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def _get_key() -> bytes:
    """Load the 256-bit AES key from environment."""
    hex_key = os.getenv("AES_ENCRYPTION_KEY", "")
    if not hex_key or len(hex_key) != 64:
        raise ValueError(
            "AES_ENCRYPTION_KEY must be a 64-character hex string (32 bytes). "
            "Generate one with: python -c \"import os; print(os.urandom(32).hex())\""
        )
    return bytes.fromhex(hex_key)


def encrypt_field(plaintext: str) -> str:
    """
    Encrypt a plaintext string with AES-256-CBC.

    Returns a Base64-encoded string containing IV + ciphertext.
    Each call generates a unique 16-byte IV for semantic security.
    """
    if not plaintext:
        return ""

    key = _get_key()
    iv = os.urandom(16)  # unique IV per operation

    # PKCS7 padding to AES block size (128 bits)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Prepend IV to ciphertext and Base64-encode
    return base64.b64encode(iv + ciphertext).decode("utf-8")


def decrypt_field(encoded_ciphertext: str) -> str:
    """
    Decrypt a Base64-encoded AES-256-CBC ciphertext.

    Expects the first 16 bytes to be the IV, followed by PKCS7-padded ciphertext.
    """
    if not encoded_ciphertext:
        return ""

    key = _get_key()
    raw = base64.b64decode(encoded_ciphertext)

    iv = raw[:16]
    ciphertext = raw[16:]

    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode("utf-8")


def get_encryption_proof(plaintext: str) -> dict:
    """
    Generate an encryption proof showing plaintext vs ciphertext.
    Used by the Encryption Proof transparency page.

    Returns:
        {
            "plaintext": "...",
            "ciphertext_b64": "...",
            "ciphertext_hex": "...",
            "iv_hex": "...",
            "algorithm": "AES-256-CBC",
            "key_length": 256,
            "block_size": 128,
        }
    """
    ciphertext_b64 = encrypt_field(plaintext)
    raw = base64.b64decode(ciphertext_b64)
    iv = raw[:16]
    ct = raw[16:]

    return {
        "plaintext": plaintext,
        "ciphertext_b64": ciphertext_b64,
        "ciphertext_hex": ct.hex(),
        "iv_hex": iv.hex(),
        "algorithm": "AES-256-CBC",
        "key_length": 256,
        "block_size": 128,
    }
