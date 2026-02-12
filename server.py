"""
server.py
========
A minimal "server" that issues challenges and verifies passkey signatures.

This simulates the WebAuthn Relying Party (RP) server. It:
- Issues random challenges (nonces) for registration and authentication
- Verifies signatures during registration (proof-of-possession)
- Verifies signatures during login + enforces sign counter monotonicity
- Stores ONLY public keys and metadata—never private keys

Security properties:
- Replay attack resistance: each challenge is single-use
- Clone detection: sign counter must strictly increase (prevents credential cloning)
- Phishing resistance: RP ID is bound to the credential; server checks rp_id
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

from crypto_utils import base64url_decode, sha256
from vault_store import load_server_vault, save_server_vault


@dataclass
class StoredCredential:
    """
    Server-side record for a registered passkey.

    Contains everything the server needs to verify future authentications:
    - username: for looking up credential by username
    - rp_id: domain this credential is bound to
    - public_key_b64u: Ed25519 public key (base64url)
    - sign_counter: last accepted counter value (must increase each auth)
    """

    username: str
    rp_id: str
    public_key_b64u: str
    sign_counter: int = 0


class PasskeyServer:
    """Server-side verifier for the simplified passkey protocol."""

    def __init__(self) -> None:
        """
        Load server credential DB from disk and build in-memory dict.

        Step-by-step:
        1. Call load_server_vault() to get raw JSON data
        2. Transform each entry into StoredCredential (with sign_counter default 0)
        3. Store in _credential_db keyed by credential_id
        """
        raw = load_server_vault()
        self._credential_db: Dict[str, StoredCredential] = {
            cred_id: StoredCredential(
                username=c["username"],
                rp_id=c["rp_id"],
                public_key_b64u=c["public_key_b64u"],
                sign_counter=c.get("sign_counter", 0),
            )
            for cred_id, c in raw.items()
        }

    def _save(self) -> None:
        """Persist current credential DB to disk."""
        save_server_vault(self.debug_dump())

    def issue_challenge(self) -> bytes:
        """
        Generate a fresh random 32-byte challenge (nonce).

        Challenges are single-use and unpredictable. Used for both registration
        and authentication to prevent replay attacks.
        """
        return os.urandom(32)

    def store_credential(self, credential_id: str, stored: StoredCredential) -> None:
        """
        Store or update a credential record after successful registration.

        Step-by-step:
        1. Add/overwrite entry in _credential_db keyed by credential_id
        2. Persist to disk via _save()
        """
        self._credential_db[credential_id] = stored
        self._save()

    def get_credential(self, credential_id: str) -> Optional[StoredCredential]:
        """Fetch stored credential by credential_id, or None if not found."""
        return self._credential_db.get(credential_id)

    def get_credential_id_for_username(self, username: str) -> Optional[str]:
        """
        Look up credential_id for a given username.

        Used when user logs in with username—we need the credential_id to
        pass to the authenticator. Returns None if username not registered.
        """
        for cred_id, stored in self._credential_db.items():
            if stored.username == username:
                return cred_id
        return None

    def verify_registration(
        self, *, rp_id: str, challenge: bytes, public_key_b64u: str, signature_b64u: str
    ) -> bool:
        """
        Verify registration proof-of-possession signature.

        The authenticator signs: rp_id || SHA256(challenge)
        This proves the authenticator holds the private key without sending it.

        Step-by-step:
        1. Decode public key from base64url
        2. Reconstruct Ed25519 public key object
        3. Build expected message: rp_id (UTF-8) concatenated with SHA256(challenge)
        4. Verify signature using public_key.verify()
        5. Return True if valid, False if signature invalid (catches exception)
        """
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(base64url_decode(public_key_b64u))
        expected_message = rp_id.encode("utf-8") + sha256(challenge)

        try:
            public_key.verify(base64url_decode(signature_b64u), expected_message)
            return True
        except Exception:
            return False

    def verify_authentication(
        self,
        *,
        credential_id: str,
        rp_id: str,
        challenge: bytes,
        signature_b64u: str,
        sign_counter: int,
    ) -> bool:
        """
        Verify login signature and enforce sign counter monotonicity.

        The authenticator signs: rp_id || SHA256(challenge) || sign_counter(4 bytes)
        Counter must be > stored value to detect replay or cloned authenticators.

        Step-by-step:
        1. Fetch stored credential; return False if not found
        2. Check rp_id matches stored value
        3. Check sign_counter > stored.sign_counter (replay/clone detection)
        4. Decode public key and build expected message
        5. Verify signature
        6. On success: update stored.sign_counter and persist
        7. Return True/False
        """
        stored = self.get_credential(credential_id)
        if stored is None:
            return False

        if stored.rp_id != rp_id:
            return False

        if sign_counter <= stored.sign_counter:
            return False

        public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            base64url_decode(stored.public_key_b64u)
        )
        counter_bytes = int(sign_counter).to_bytes(4, "big")
        expected_message = rp_id.encode("utf-8") + sha256(challenge) + counter_bytes

        try:
            public_key.verify(base64url_decode(signature_b64u), expected_message)
        except Exception:
            return False

        stored.sign_counter = sign_counter
        self._save()
        return True

    def debug_dump(self) -> Dict[str, dict]:
        """
        Return JSON-friendly view of server DB for demo (option 5 in main menu).

        Shows credential_id → {username, rp_id, public_key_b64u, sign_counter}.
        In production, this would not be exposed.
        """
        return {
            cred_id: {
                "username": cred.username,
                "rp_id": cred.rp_id,
                "public_key_b64u": cred.public_key_b64u,
                "sign_counter": cred.sign_counter,
            }
            for cred_id, cred in self._credential_db.items()
        }
