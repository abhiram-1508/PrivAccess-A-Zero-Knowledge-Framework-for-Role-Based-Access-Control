import secrets
from crypto.hash_utils import generate_commitment

class Prover:
    def __init__(self, role_secret: str):
        self.role_secret = role_secret

    def generate_proof(self, user: str, action: str, resource: str):
        """
        Generate a zero-knowledge proof using user, action, and resource.
        """
        nonce = secrets.token_hex(16)

        # Bind proof to context (user, action, resource)
        message = f"{user}:{action}:{resource}"
        commitment = generate_commitment(self.role_secret + message, nonce)

        return {
            "commitment": commitment,
            "nonce": nonce,
            "message": message
        }
