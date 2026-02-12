"""
crypto_utils.py
==============
Small, well-named cryptographic helper functions used by the passkey demo.

This module centralizes all cryptographic operations to keep the rest of the
codebase readable and maintainable. It provides:
- Base64url encoding/decoding (WebAuthn-compatible format)
- SHA-256 hashing for challenge digests
- PBKDF2 key derivation from PIN (for vault encryption)
- AES-GCM encryption/decryption (authenticated encryption for private key storage)

Note: Real passkey implementations use OS/hardware-backed secure storage.
This demo uses file-based storage with PIN-derived encryption for visibility.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def base64url_encode(raw_bytes: bytes) -> str:
    """
    Encode raw bytes using URL-safe base64 without '=' padding (WebAuthn-style).

    WebAuthn/CTAP use base64url encoding (RFC 4648) which differs from standard
    base64: uses - and _ instead of + and /, and omits padding for compactness.

    Step-by-step:
    1. Apply base64.urlsafe_b64encode() to convert bytes → base64 bytes
    2. Decode to UTF-8 string for JSON/storage compatibility
    3. Strip trailing '=' padding characters (WebAuthn convention)
    """
    return base64.urlsafe_b64encode(raw_bytes).decode("utf-8").rstrip("=")


def base64url_decode(encoded: str) -> bytes:
    """
    Decode URL-safe base64 string back to raw bytes, handling missing padding.

    Step-by-step:
    1. Calculate how many '=' padding chars are needed (base64 requires length % 4 == 0)
    2. Append the required padding to the encoded string
    3. Decode using base64.urlsafe_b64decode() and return raw bytes
    """
    padding = "=" * (-len(encoded) % 4)  # add required '=' padding back
    return base64.urlsafe_b64decode(encoded + padding)


def sha256(data: bytes) -> bytes:
    """
    Compute SHA-256 cryptographic hash of input bytes.

    Used for hashing challenges before signing (signatures are over the hash,
    not raw challenge, for consistency with WebAuthn).

    Step-by-step:
    1. Create a Hash object configured for SHA-256 algorithm
    2. Feed the input data into the hash via update()
    3. Finalize and return the 32-byte digest
    """
    digest = hashes.Hash(hashes.SHA256())  # create hash object
    digest.update(data)                    # feed data
    return digest.finalize()               # output digest


def derive_key_from_pin(pin: str, salt: bytes, iterations: int = 150_000) -> bytes:
    """
    Derive a 256-bit AES key from a user PIN using PBKDF2-HMAC-SHA256.

    PBKDF2 (Password-Based Key Derivation Function 2) makes brute-force attacks
    on weak PINs computationally expensive by requiring many iterations.

    Step-by-step:
    1. Create PBKDF2HMAC instance with:
       - SHA-256 as the underlying hash
       - 32-byte output (256-bit key for AES-256)
       - Unique salt per credential (prevents rainbow table attacks)
       - 150,000 iterations (slows brute force; OWASP-recommended minimum)
    2. Derive the key by feeding the PIN (UTF-8 encoded) into the KDF
    3. Return the 32-byte key suitable for AES-GCM
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # HMAC-SHA256 inside PBKDF2
        length=32,                  # 32 bytes = 256-bit key
        salt=salt,                  # random salt
        iterations=iterations,      # slows brute force
    )
    return kdf.derive(pin.encode("utf-8"))


@dataclass
class EncryptedBlob:
    """
    Container for AES-GCM encryption output: nonce + ciphertext.

    Both fields are base64url-encoded strings for JSON serialization.
    - nonce_b64u: 96-bit random nonce (IV) used for this encryption
    - ciphertext_b64u: encrypted data + 16-byte GCM authentication tag
    """

    nonce_b64u: str
    ciphertext_b64u: str


def aesgcm_encrypt(key: bytes, plaintext: bytes) -> EncryptedBlob:
    """
    Encrypt plaintext using AES-256-GCM (authenticated encryption).

    AES-GCM provides both confidentiality (encryption) and integrity (auth tag).
    Tampering with ciphertext causes decryption to fail—no silent corruption.

    Step-by-step:
    1. Create AESGCM cipher instance with the 256-bit key
    2. Generate a cryptographically random 96-bit (12-byte) nonce
    3. Encrypt plaintext; GCM appends auth tag to ciphertext
    4. Base64url-encode nonce and ciphertext for storage
    5. Return EncryptedBlob with both encoded values
    """
    aesgcm = AESGCM(key)           # AES-GCM object
    nonce = os.urandom(12)         # 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return EncryptedBlob(
        nonce_b64u=base64url_encode(nonce),
        ciphertext_b64u=base64url_encode(ciphertext),
    )


def aesgcm_decrypt(key: bytes, blob: EncryptedBlob) -> bytes:
    """
    Decrypt AES-GCM ciphertext. Raises InvalidTag if integrity check fails.

    Integrity failure occurs when:
    - Wrong PIN (wrong key)
    - Ciphertext or nonce was tampered with
    - Corrupted data

    Step-by-step:
    1. Create AESGCM cipher with the key
    2. Decode nonce and ciphertext from base64url
    3. Call decrypt(); GCM internally verifies auth tag
    4. Return plaintext bytes (or raise on tamper/wrong key)
    """
    aesgcm = AESGCM(key)
    nonce = base64url_decode(blob.nonce_b64u)
    ciphertext = base64url_decode(blob.ciphertext_b64u)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
