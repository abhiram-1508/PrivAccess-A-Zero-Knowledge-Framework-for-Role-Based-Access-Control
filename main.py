# main.py

from rbac.roles import get_role_secret, ROLES
from zkp.prover import Prover
from zkp.verifier import Verifier
from rbac.access_control import AccessControl


def main():
    print("\n=== PrivAccess: Zero-Knowledge RBAC System ===\n")

    print("Available Roles:")
    for role in ROLES.keys():
        print(f" - {role}")

    print("\nAllowed Actions: read / write / delete\n")

    user = input("Enter username: ").strip()
    role_name = input("Enter role from above list: ").strip().upper()
    action = input("Enter action: ").strip().lower()
    resource = input("Enter resource name: ").strip()

    role_secret = get_role_secret(role_name)
    if not role_secret:
        print("\n❌ Invalid role selected")
        print("❌ Access Denied")
        return

    print("\n🔐 Generating Zero-Knowledge Proof...")
    prover = Prover(role_secret)
    proof = prover.generate_proof(user=user, action=action, resource=resource)

    print("🔍 Verifying Proof...")
    verifier = Verifier(role_secret)
    proof_valid = verifier.verify_proof(proof)

    access_control = AccessControl()
    access_granted = access_control.decide_access(proof_valid, role_name, action)

    print("\n=== RESULT ===")
    if access_granted:
        print("✅ Proof Verified")
        print(f"✅ Access Granted to {role_name}")
        print(f"➡ Action: {action}")
        print(f"➡ Resource: {resource}")
    else:
        print("❌ Access Denied")
        print(f"🚫 {role_name} is not allowed to perform '{action}'")


if __name__ == "__main__":
    main()
