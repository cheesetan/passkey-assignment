"""authenticator.py
A minimal "authenticator" that stores a passkey and signs challenges.

Demonstrates:
- Private key stays local
- RP ID check (phishing resistance)
- Encrypted vault with PIN (PBKDF2 + AES-GCM)
"""

from __future__ import annotations

import os
from typing import Dict, Any

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from crypto_utils import (
    EncryptedBlob,
    aesgcm_decrypt,
    aesgcm_encrypt,
    base64url_decode,
    base64url_encode,
    derive_key_from_pin,
    sha256,
)
from vault_store import load_vault, save_vault


class Authenticator:
    """Stores passkeys in a local encrypted vault and signs server challenges."""

    def __init__(self) -> None:
        self._vault: Dict[str, Any] = load_vault()

    def _save(self) -> None:
        save_vault(self._vault)

    def register_passkey(self, *, username: str, rp_id: str, pin: str, challenge: bytes) -> dict:
        """Create a new passkey and return data for server registration verification."""

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        salt = os.urandom(16)
        aes_key = derive_key_from_pin(pin, salt)
        encrypted = aesgcm_encrypt(aes_key, private_key_bytes)

        credential_id = base64url_encode(os.urandom(16))

        self._vault[credential_id] = {
            "username": username,
            "rp_id": rp_id,
            "public_key_b64u": base64url_encode(public_key_bytes),
            "salt_b64u": base64url_encode(salt),
            "encrypted_private_key": {
                "nonce_b64u": encrypted.nonce_b64u,
                "ciphertext_b64u": encrypted.ciphertext_b64u,
            },
            "sign_counter": 0,
        }
        self._save()

        message = rp_id.encode("utf-8") + sha256(challenge)
        signature = private_key.sign(message)

        return {
            "credential_id": credential_id,
            "username": username,
            "rp_id": rp_id,
            "public_key_b64u": base64url_encode(public_key_bytes),
            "signature_b64u": base64url_encode(signature),
        }

    def authenticate(self, *, credential_id: str, rp_id: str, pin: str, challenge: bytes) -> dict:
        """Unlock private key (PIN) and sign the login challenge."""

        if credential_id not in self._vault:
            raise ValueError("Unknown credential_id in authenticator vault.")

        entry = self._vault[credential_id]

        if entry["rp_id"] != rp_id:
            raise PermissionError(f"RP ID mismatch (stored={entry['rp_id']}, requested={rp_id}).")

        salt = base64url_decode(entry["salt_b64u"])
        aes_key = derive_key_from_pin(pin, salt)

        blob = EncryptedBlob(
            nonce_b64u=entry["encrypted_private_key"]["nonce_b64u"],
            ciphertext_b64u=entry["encrypted_private_key"]["ciphertext_b64u"],
        )
        private_key_bytes = aesgcm_decrypt(aes_key, blob)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)

        entry["sign_counter"] += 1
        self._save()

        counter_bytes = int(entry["sign_counter"]).to_bytes(4, "big")
        message = rp_id.encode("utf-8") + sha256(challenge) + counter_bytes
        signature = private_key.sign(message)

        return {
            "credential_id": credential_id,
            "rp_id": rp_id,
            "signature_b64u": base64url_encode(signature),
            "sign_counter": entry["sign_counter"],
        }

    def debug_dump(self) -> dict:
        return self._vault
