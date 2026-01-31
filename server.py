"""server.py
A minimal "server" that issues challenges and verifies passkey signatures.

Server stores ONLY:
- credential_id -> public key
- sign counter  -> helps detect replay/cloned authenticators
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

from crypto_utils import base64url_decode, sha256


@dataclass
class StoredCredential:
    """Server-side record created after registration."""
    username: str
    rp_id: str
    public_key_b64u: str
    sign_counter: int = 0


class PasskeyServer:
    """Server verifier for our simplified passkey protocol."""

    def __init__(self) -> None:
        self._credential_db: Dict[str, StoredCredential] = {}

    def issue_challenge(self) -> bytes:
        """Generate a fresh random challenge (nonce)."""
        return os.urandom(32)

    def store_credential(self, credential_id: str, stored: StoredCredential) -> None:
        """Store the credential record."""
        self._credential_db[credential_id] = stored

    def get_credential(self, credential_id: str) -> Optional[StoredCredential]:
        """Fetch stored credential by ID."""
        return self._credential_db.get(credential_id)

    def verify_registration(self, *, rp_id: str, challenge: bytes, public_key_b64u: str, signature_b64u: str) -> bool:
        """Verify registration proof-of-possession signature.

        Authenticator signs:
            rp_id || SHA256(challenge)
        """
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(base64url_decode(public_key_b64u))
        expected_message = rp_id.encode("utf-8") + sha256(challenge)

        try:
            public_key.verify(base64url_decode(signature_b64u), expected_message)
            return True
        except Exception:
            return False

    def verify_authentication(self, *, credential_id: str, rp_id: str, challenge: bytes, signature_b64u: str, sign_counter: int) -> bool:
        """Verify login signature + counter monotonic increase.

        Authenticator signs:
            rp_id || SHA256(challenge) || sign_counter(4 bytes)
        """
        stored = self.get_credential(credential_id)
        if stored is None:
            return False

        if stored.rp_id != rp_id:
            return False

        if sign_counter <= stored.sign_counter:
            return False

        public_key = ed25519.Ed25519PublicKey.from_public_bytes(base64url_decode(stored.public_key_b64u))
        counter_bytes = int(sign_counter).to_bytes(4, "big")
        expected_message = rp_id.encode("utf-8") + sha256(challenge) + counter_bytes

        try:
            public_key.verify(base64url_decode(signature_b64u), expected_message)
        except Exception:
            return False

        stored.sign_counter = sign_counter
        return True

    def debug_dump(self) -> Dict[str, dict]:
        """JSON-friendly view of server DB for demo."""
        return {
            cred_id: {
                "username": cred.username,
                "rp_id": cred.rp_id,
                "public_key_b64u": cred.public_key_b64u,
                "sign_counter": cred.sign_counter,
            }
            for cred_id, cred in self._credential_db.items()
        }
