"""
main.py
======
Interactive demo for a simplified passkey registration and authentication flow.

This script orchestrates:
- PasskeyServer: issues challenges, verifies signatures, stores public keys
- Authenticator: stores passkeys (encrypted), signs challenges when PIN is correct

Demo options:
1. Register - create new passkey, verify proof-of-possession, store public key
2. Login - authenticate with passkey, verify signature + sign counter
3. Phishing attempt - authenticator refuses wrong rp_id (phish.com vs example.com)
4. Tampered challenge - server rejects when attacker modifies challenge
5. Show stored data - debug dump of server DB and authenticator vault
"""

import json
from crypto_utils import base64url_encode
from server import PasskeyServer, StoredCredential
from authenticator import Authenticator


def main() -> None:
    """
    Main entry point: run interactive passkey demo loop.

    Step-by-step flow:
    1. Initialize server and authenticator (load from disk)
    2. Set rp_id (Relying Party ID) = "example.com"
    3. Enter infinite loop presenting menu
    4. Branch on user choice to handle: register, login, phishing, tamper, dump, exit
    """
    rp_id = "example.com"

    server = PasskeyServer()
    authenticator = Authenticator()

    last_credential_id = None

    while True:
        print("\n=== PASSKEY DEMO ===")
        print("1) Register (create passkey)")
        print("2) Login (use passkey)")
        print("3) Phishing attempt (wrong rp_id)")
        print("4) Tampered challenge (verification fails)")
        print("5) Show stored data (server + vault)")
        print("0) Exit")

        choice = input("Choose: ").strip()

        if choice == "0":
            break

        # ---------------------------------------------------------------------
        # Option 1: Register a new passkey
        # ---------------------------------------------------------------------
        if choice == "1":
            username = input("Username: ").strip()
            pin = input("Set PIN (demo unlock): ").strip()

            # Server issues challenge; authenticator creates passkey and signs it
            challenge = server.issue_challenge()
            print(f"[Server] Issued challenge: {base64url_encode(challenge)}")

            registration = authenticator.register_passkey(
                username=username,
                rp_id=rp_id,
                pin=pin,
                challenge=challenge,
            )
            print(
                f"[Authenticator] Passkey created. credential_id={registration['credential_id']}"
            )

            # Server verifies proof-of-possession, then stores PUBLIC KEY only
            ok = server.verify_registration(
                rp_id=rp_id,
                challenge=challenge,
                public_key_b64u=registration["public_key_b64u"],
                signature_b64u=registration["signature_b64u"],
            )
            print(f"[Server] Verify registration: {'OK' if ok else 'FAIL'}")

            if ok:
                server.store_credential(
                    registration["credential_id"],
                    StoredCredential(
                        username=registration["username"],
                        rp_id=registration["rp_id"],
                        public_key_b64u=registration["public_key_b64u"],
                    ),
                )
                last_credential_id = registration["credential_id"]
                print("[Server] Stored PUBLIC KEY only.")

        # ---------------------------------------------------------------------
        # Option 2: Login with passkey
        # ---------------------------------------------------------------------
        elif choice == "2":
            username = input("Username: ").strip()
            credential_id = server.get_credential_id_for_username(username)
            if credential_id is None:
                print("Username not found. Please register first (option 1).")
                continue

            pin = input("Enter PIN to unlock passkey: ").strip()
            challenge = server.issue_challenge()
            print(f"[Server] Issued challenge: {base64url_encode(challenge)}")

            try:
                assertion = authenticator.authenticate(
                    credential_id=credential_id,
                    rp_id=rp_id,
                    pin=pin,
                    challenge=challenge,
                )
                print("[Authenticator] Signed challenge using local private key.")
            except Exception as e:
                print(f"[Authenticator] ERROR: {e}")
                continue

            # Server verifies signature and sign counter
            ok = server.verify_authentication(
                credential_id=assertion["credential_id"],
                rp_id=assertion["rp_id"],
                challenge=challenge,
                signature_b64u=assertion["signature_b64u"],
                sign_counter=assertion["sign_counter"],
            )
            print(f"[Server] Verify login: {'OK' if ok else 'FAIL'}")
            if ok:
                last_credential_id = credential_id

        # ---------------------------------------------------------------------
        # Option 3: Phishing attempt (wrong rp_id)
        # ---------------------------------------------------------------------
        elif choice == "3":
            username = input("Username: ").strip()
            credential_id = server.get_credential_id_for_username(username)
            if credential_id is None:
                print("Username not found. Please register first (option 1).")
                continue

            pin = input("PIN: ").strip()
            phishing_rp_id = "phish.com"

            challenge = server.issue_challenge()
            print(f"[Phishing Site] Issued challenge: {base64url_encode(challenge)}")

            # Authenticator should REFUSE: rp_id mismatch (phishing resistance)
            try:
                _ = authenticator.authenticate(
                    credential_id=credential_id,
                    rp_id=phishing_rp_id,
                    pin=pin,
                    challenge=challenge,
                )
                print("[Authenticator] Unexpected: signed for phishing site.")
            except Exception as e:
                print(f"[Authenticator] Refused (expected): {e}")

        # ---------------------------------------------------------------------
        # Option 4: Tampered challenge (replay/ MITM)
        # ---------------------------------------------------------------------
        elif choice == "4":
            username = input("Username: ").strip()
            credential_id = server.get_credential_id_for_username(username)
            if credential_id is None:
                print("Username not found. Please register first (option 1).")
                continue

            pin = input("PIN: ").strip()
            challenge = server.issue_challenge()
            print(f"[Server] Issued challenge: {base64url_encode(challenge)}")

            try:
                assertion = authenticator.authenticate(
                    credential_id=credential_id,
                    rp_id=rp_id,
                    pin=pin,
                    challenge=challenge,
                )
            except Exception as e:
                print(f"[Authenticator] ERROR: {e}")
                continue

            print("[Authenticator] Signed ORIGINAL challenge.")

            # Attacker tampers with challenge (e.g., intercepts and modifies)
            tampered = bytearray(challenge)
            tampered[0] ^= 0xFF
            tampered = bytes(tampered)
            print(f"[Attacker] Tampered challenge: {base64url_encode(tampered)}")

            # Server verifies with TAMPERED challenge; signature won't match
            ok = server.verify_authentication(
                credential_id=assertion["credential_id"],
                rp_id=assertion["rp_id"],
                challenge=tampered,
                signature_b64u=assertion["signature_b64u"],
                sign_counter=assertion["sign_counter"],
            )
            print(
                f"[Server] Verify tampered challenge: {'OK (unexpected)' if ok else 'FAIL (expected)'}"
            )

        # ---------------------------------------------------------------------
        # Option 5: Debug dump of stored data
        # ---------------------------------------------------------------------
        elif choice == "5":
            print("\n--- SERVER DB ---")
            print(json.dumps(server.debug_dump(), indent=2))
            print("\n--- AUTHENTICATOR VAULT ---")
            print(json.dumps(authenticator.debug_dump(), indent=2))

        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
