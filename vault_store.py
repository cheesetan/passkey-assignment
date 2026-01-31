"""vault_store.py
Tiny JSON storage for the authenticator vault.

Real passkeys are stored in secure OS/hardware. This file keeps the demo visible.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict

VAULT_FILENAME = "authenticator_vault.json"


def load_vault() -> Dict[str, Any]:
    """Load vault from disk; return empty dict if file doesn't exist."""
    if not os.path.exists(VAULT_FILENAME):
        return {}
    with open(VAULT_FILENAME, "r", encoding="utf-8") as f:
        return json.load(f)


def save_vault(vault: Dict[str, Any]) -> None:
    """Save vault as pretty JSON for readability."""
    with open(VAULT_FILENAME, "w", encoding="utf-8") as f:
        json.dump(vault, f, indent=2, sort_keys=True)
