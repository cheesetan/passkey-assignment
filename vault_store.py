"""
vault_store.py
=============
Tiny JSON-based persistence layer for the authenticator vault and server credential DB.

In a real passkey deployment:
- Authenticator data lives in OS keychain (macOS Keychain, Windows Hello, etc.)
  or hardware security modules (TPM, Secure Enclave)
- Server credential DB would be a proper database (PostgreSQL, etc.)

This module uses simple JSON files so the demo is visible and debuggable.
Files are human-readable with pretty-printing (indent=2, sort_keys=True).
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict

# -----------------------------------------------------------------------------
# File paths for persistent storage
# -----------------------------------------------------------------------------
VAULT_FILENAME = "authenticator_vault.json"    # Client-side: encrypted passkeys
SERVER_VAULT_FILENAME = "server_vault.json"   # Server-side: public keys + metadata


def load_vault() -> Dict[str, Any]:
    """
    Load the authenticator vault from disk.

    The vault stores multiple passkeys keyed by credential_id. Each entry
    contains username, rp_id, salt, encrypted private key, and sign counter.

    Step-by-step:
    1. Check if VAULT_FILENAME exists on disk
    2. If not, return empty dict {} (fresh install / no passkeys yet)
    3. If exists, open file, parse JSON, return the dict
    """
    if not os.path.exists(VAULT_FILENAME):
        return {}
    with open(VAULT_FILENAME, "r", encoding="utf-8") as f:
        return json.load(f)


def save_vault(vault: Dict[str, Any]) -> None:
    """
    Persist the authenticator vault to disk as pretty-printed JSON.

    Called after creating a new passkey or after each authentication
    (to update sign_counter).

    Step-by-step:
    1. Open VAULT_FILENAME for writing (overwrites existing)
    2. JSON-serialize vault with indent=2 (readable) and sort_keys=True (stable)
    3. Write to disk
    """
    with open(VAULT_FILENAME, "w", encoding="utf-8") as f:
        json.dump(vault, f, indent=2, sort_keys=True)


def load_server_vault() -> Dict[str, Any]:
    """
    Load the server credential database from disk.

    The server vault maps credential_id → {username, rp_id, public_key_b64u, sign_counter}.
    Server stores ONLY public keys, never private keys.

    Step-by-step:
    1. Check if SERVER_VAULT_FILENAME exists
    2. If not, return {} (no registrations yet)
    3. If exists, parse JSON and return the credential DB dict
    """
    if not os.path.exists(SERVER_VAULT_FILENAME):
        return {}
    with open(SERVER_VAULT_FILENAME, "r", encoding="utf-8") as f:
        return json.load(f)


def save_server_vault(data: Dict[str, Any]) -> None:
    """
    Persist the server credential DB to disk.

    Called after storing a new credential or after successful authentication
    (to update sign_counter in the stored record).

    Step-by-step:
    1. Open SERVER_VAULT_FILENAME for writing
    2. JSON-serialize with indent=2 and sort_keys=True
    3. Write to disk
    """
    with open(SERVER_VAULT_FILENAME, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
