from crypto.hash_utils import generate_commitment

class Verifier:
    def __init__(self, role_secret: str):
        self.role_secret = role_secret

    def verify_proof(self, proof: dict) -> bool:
        commitment = proof.get("commitment")
        nonce = proof.get("nonce")
        message = proof.get("message")

        if not commitment or not nonce or not message:
            return False

        expected_commitment = generate_commitment(
            self.role_secret + message, nonce
        )

        return commitment == expected_commitment
