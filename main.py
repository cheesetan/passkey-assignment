import json
from crypto_utils import base64url_encode
from server import PasskeyServer, StoredCredential
from authenticator import Authenticator


def main() -> None:
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

        if choice == "1":
            username = input("Username: ").strip()
            pin = input("Set PIN (demo unlock): ").strip()

            challenge = server.issue_challenge()
            print(f"[Server] Issued challenge: {base64url_encode(challenge)}")

            registration = authenticator.register_passkey(
                username=username,
                rp_id=rp_id,
                pin=pin,
                challenge=challenge,
            )
            print(f"[Authenticator] Passkey created. credential_id={registration['credential_id']}")

            ok = server.verify_registration(
                rp_id=rp_id,
                challenge=challenge,
                public_key_b64u=registration["public_key_b64u"],
                signature_b64u=registration["signature_b64u"],
            )
            print(f"[Server] Verify registration: {'OK' if ok else 'FAIL'}" )

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
                print("[Server] Stored PUBLIC KEY only." )

        elif choice == "2":
            if not last_credential_id:
                print("Register first (option 1)." )
                continue

            pin = input("Enter PIN to unlock passkey: ").strip()
            challenge = server.issue_challenge()
            print(f"[Server] Issued challenge: {base64url_encode(challenge)}" )

            try:
                assertion = authenticator.authenticate(
                    credential_id=last_credential_id,
                    rp_id=rp_id,
                    pin=pin,
                    challenge=challenge,
                )
                print("[Authenticator] Signed challenge using local private key." )
            except Exception as e:
                print(f"[Authenticator] ERROR: {e}" )
                continue

            ok = server.verify_authentication(
                credential_id=assertion["credential_id"],
                rp_id=assertion["rp_id"],
                challenge=challenge,
                signature_b64u=assertion["signature_b64u"],
                sign_counter=assertion["sign_counter"],
            )
            print(f"[Server] Verify login: {'OK' if ok else 'FAIL'}" )

        elif choice == "3":
            if not last_credential_id:
                print("Register first (option 1)." )
                continue

            pin = input("PIN: ").strip()
            phishing_rp_id = "phish.com"

            challenge = server.issue_challenge()
            print(f"[Phishing Site] Issued challenge: {base64url_encode(challenge)}" )

            try:
                _ = authenticator.authenticate(
                    credential_id=last_credential_id,
                    rp_id=phishing_rp_id,
                    pin=pin,
                    challenge=challenge,
                )
                print("[Authenticator] Unexpected: signed for phishing site." )
            except Exception as e:
                print(f"[Authenticator] Refused (expected): {e}" )

        elif choice == "4":
            if not last_credential_id:
                print("Register first (option 1)." )
                continue

            pin = input("PIN: ").strip()
            challenge = server.issue_challenge()
            print(f"[Server] Issued challenge: {base64url_encode(challenge)}" )

            assertion = authenticator.authenticate(
                credential_id=last_credential_id,
                rp_id=rp_id,
                pin=pin,
                challenge=challenge,
            )
            print("[Authenticator] Signed ORIGINAL challenge." )

            tampered = bytearray(challenge)
            tampered[0] ^= 0xFF
            tampered = bytes(tampered)
            print(f"[Attacker] Tampered challenge: {base64url_encode(tampered)}" )

            ok = server.verify_authentication(
                credential_id=assertion["credential_id"],
                rp_id=assertion["rp_id"],
                challenge=tampered,
                signature_b64u=assertion["signature_b64u"],
                sign_counter=assertion["sign_counter"],
            )
            print(f"[Server] Verify tampered challenge: {'OK (unexpected)' if ok else 'FAIL (expected)'}" )

        elif choice == "5":
            print("\n--- SERVER DB ---")
            print(json.dumps(server.debug_dump(), indent=2))
            print("\n--- AUTHENTICATOR VAULT ---")
            print(json.dumps(authenticator.debug_dump(), indent=2))

        else:
            print("Invalid option." )


if __name__ == "__main__":
    main()
