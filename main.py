# main.py

from rbac.roles import get_role_secret
from zkp.prover import Prover
from zkp.verifier import Verifier
from rbac.access_control import AccessControl


def main():
    print("=== PrivAccess: Zero-Knowledge RBAC Demo ===\n")

    # Change role here to test: ADMIN / USER / MANAGER / INVALID
    role_name = "ADMIN"
    print(f"User attempting access with role: {role_name}")

    # Fetch role secret
    role_secret = get_role_secret(role_name)
    if role_secret is None:
        print("Invalid role. Access Denied.")
        return

    # Prover generates proof
    prover = Prover(role_secret)
    proof = prover.generate_proof()
    print("\nGenerating zero-knowledge proof...")

    # Verifier verifies proof
    verifier = Verifier(role_secret)
    print("Verifying proof...")
    proof_valid = verifier.verify_proof(proof)

    # Access control decision
    access_control = AccessControl()
    access_granted = access_control.decide_access(proof_valid, role_name)

    if access_granted:
        print("Proof verified successfully.")
        print(f"Access Granted to {role_name} resources.")
    else:
        print("Proof verification failed.")
        print("Access Denied.")


if __name__ == "__main__":
    main()
