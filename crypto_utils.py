"""crypto_utils.py
Small, well-named cryptographic helper functions used by the demo.

Keeping crypto in one place makes the rest of the code easier to read.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def base64url_encode(raw_bytes: bytes) -> str:
    """Encode bytes using URL-safe base64 without '=' padding (WebAuthn-style)."""
    return base64.urlsafe_b64encode(raw_bytes).decode("utf-8").rstrip("=")


def base64url_decode(encoded: str) -> bytes:
    """Decode URL-safe base64 that may be missing '=' padding."""
    padding = "=" * (-len(encoded) % 4)  # add required '=' padding back
    return base64.urlsafe_b64decode(encoded + padding)


def sha256(data: bytes) -> bytes:
    """Return SHA-256 digest of input bytes."""
    digest = hashes.Hash(hashes.SHA256())  # create hash object
    digest.update(data)                    # feed data
    return digest.finalize()               # output digest


def derive_key_from_pin(pin: str, salt: bytes, iterations: int = 150_000) -> bytes:
    """Derive a 256-bit AES key from a PIN using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # HMAC-SHA256 inside PBKDF2
        length=32,                  # 32 bytes = 256-bit key
        salt=salt,                  # random salt
        iterations=iterations,      # slows brute force
    )
    return kdf.derive(pin.encode("utf-8"))


@dataclass
class EncryptedBlob:
    """Stores AES-GCM nonce + ciphertext (both base64url strings)."""
    nonce_b64u: str
    ciphertext_b64u: str


def aesgcm_encrypt(key: bytes, plaintext: bytes) -> EncryptedBlob:
    """Encrypt plaintext using AES-GCM (confidentiality + integrity)."""
    aesgcm = AESGCM(key)           # AES-GCM object
    nonce = os.urandom(12)         # 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return EncryptedBlob(
        nonce_b64u=base64url_encode(nonce),
        ciphertext_b64u=base64url_encode(ciphertext),
    )


def aesgcm_decrypt(key: bytes, blob: EncryptedBlob) -> bytes:
    """Decrypt AES-GCM ciphertext. Raises if integrity fails (wrong PIN/tamper)."""
    aesgcm = AESGCM(key)
    nonce = base64url_decode(blob.nonce_b64u)
    ciphertext = base64url_decode(blob.ciphertext_b64u)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
