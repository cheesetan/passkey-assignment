"""
authenticator.py
===============
A minimal software authenticator that stores passkeys and signs challenges.

This simulates a WebAuthn authenticator (e.g., security key, platform authenticator).
Key behaviors demonstrated:
- Private key NEVER leaves the device; only public key is sent to server
- RP ID (Relying Party ID) binding: passkey refuses to sign for wrong domain (phishing resistance)
- Encrypted vault: private keys stored with PIN-derived AES-GCM encryption
- Sign counter: monotonic counter per credential (replay/clone detection)
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
    """
    Software authenticator: stores passkeys in an encrypted local vault and
    signs server challenges when the user provides the correct PIN.
    """

    def __init__(self) -> None:
        """Load existing vault from disk into memory."""
        self._vault: Dict[str, Any] = load_vault()

    def _save(self) -> None:
        """Persist current vault state to disk."""
        save_vault(self._vault)

    def register_passkey(self, *, username: str, rp_id: str, pin: str, challenge: bytes) -> dict:
        """
        Create a new passkey and return registration data for server verification.

        The server will verify the signature (proof-of-possession) and store
        only the public key. The private key stays encrypted in this vault.

        Step-by-step:
        1. Generate a new Ed25519 key pair (private + public)
        2. Serialize private and public keys to raw bytes
        3. Generate 16-byte random salt for PBKDF2
        4. Derive AES key from PIN + salt
        5. Encrypt private key bytes with AES-GCM
        6. Generate random 16-byte credential_id (base64url-encoded)
        7. Store in vault: username, rp_id, public_key, salt, encrypted_private_key, sign_counter=0
        8. Persist vault to disk
        9. Build proof message: rp_id || SHA256(challenge)
        10. Sign message with private key (proof-of-possession for server)
        11. Return credential_id, username, rp_id, public_key, and signature
        """
        # 1–2: Generate and serialize Ed25519 key pair
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

        # 3–5: Encrypt private key with PIN-derived key
        salt = os.urandom(16)
        aes_key = derive_key_from_pin(pin, salt)
        encrypted = aesgcm_encrypt(aes_key, private_key_bytes)

        # 6–8: Store in vault and persist
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

        # 9–11: Proof-of-possession signature for server
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
        """
        Unlock the passkey (PIN) and sign the login challenge.

        RP ID is checked before signing—passkey refuses to sign for wrong domain.
        Sign counter is incremented and persisted after each use.

        Step-by-step:
        1. Verify credential_id exists in vault; raise if unknown
        2. Load vault entry for this credential
        3. RP ID check: if stored rp_id != requested rp_id, raise PermissionError (phishing attempt)
        4. Decode salt from entry
        5. Derive AES key from PIN + salt
        6. Decrypt private key from encrypted blob (raises if wrong PIN)
        7. Reconstruct Ed25519 private key from bytes
        8. Increment sign_counter and persist vault
        9. Build auth message: rp_id || SHA256(challenge) || sign_counter(4 bytes big-endian)
        10. Sign message with private key
        11. Return credential_id, rp_id, signature, and sign_counter
        """
        # 1–2: Validate credential exists
        if credential_id not in self._vault:
            raise ValueError("Unknown credential_id in authenticator vault.")

        entry = self._vault[credential_id]

        # 3: Phishing resistance—refuse wrong RP ID
        if entry["rp_id"] != rp_id:
            raise PermissionError(f"RP ID mismatch (stored={entry['rp_id']}, requested={rp_id}).")

        # 4–7: Unlock private key with PIN
        salt = base64url_decode(entry["salt_b64u"])
        aes_key = derive_key_from_pin(pin, salt)

        blob = EncryptedBlob(
            nonce_b64u=entry["encrypted_private_key"]["nonce_b64u"],
            ciphertext_b64u=entry["encrypted_private_key"]["ciphertext_b64u"],
        )
        private_key_bytes = aesgcm_decrypt(aes_key, blob)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)

        # 8: Bump counter and save
        entry["sign_counter"] += 1
        self._save()

        # 9–11: Sign auth message
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
        """
        Return raw vault contents for demo/debugging (option 5 in main menu).

        In production, this would never be exposed. Here it shows the structure
        of stored passkeys (encrypted private keys, salts, etc.).
        """
        return self._vault
