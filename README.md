# Passkeys Demo (Python) — readable multi-file prototype

This prototype demonstrates the **core cryptographic operations behind passkeys** in a simplified way:

- Server generates a random **challenge** (nonce)
- Authenticator holds a **private key locally** (never sent to server)
- Authenticator signs a message derived from (rp_id + challenge_hash + sign_counter)
- Server verifies the signature using the stored **public key**
- Authenticator enforces **RP ID match** (phishing resistance)
- Private key is stored in an authenticator "vault" encrypted using **AES-GCM**
  with a key derived from a **PIN** via **PBKDF2-HMAC-SHA256**

## Run
```bash
pip install -r requirements.txt
python main.py
```

## Files
- `main.py` — CLI demo (register / login / attack demos)
- `server.py` — server logic: issue challenge, store public key, verify signatures
- `authenticator.py` — authenticator logic: create keypair, encrypt private key, sign challenges
- `crypto_utils.py` — crypto helpers (hashing, KDF, AES-GCM, base64url)
- `vault_store.py` — JSON storage helper for the authenticator vault

> Teaching/demo prototype, not a full WebAuthn/FIDO2 implementation.
