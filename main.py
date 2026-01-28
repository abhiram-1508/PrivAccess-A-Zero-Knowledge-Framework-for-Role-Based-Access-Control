#!/usr/bin/env python3
"""
PrivAccess - A Zero-Knowledge Framework for Role-Based Access Control
Main entry point for the PrivAccess system
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from rbac.access_control import AccessControlManager
from zkp.prover import Prover
from zkp.verifier import Verifier


def main():
    """Main function to demonstrate PrivAccess functionality"""
    print("PrivAccess - Zero-Knowledge Framework for Role-Based Access Control")
    print("=" * 70)
    
    # Initialize components
    acm = AccessControlManager()
    prover = Prover()
    verifier = Verifier()
    
    # Demo: Basic role-based access control with zero-knowledge proofs
    print("\n1. Setting up roles and permissions...")
    acm.create_role("admin", ["read", "write", "delete"])
    acm.create_role("user", ["read"])
    acm.create_role("moderator", ["read", "write"])
    
    print("2. Assigning roles to users...")
    acm.assign_role("alice", "admin")
    acm.assign_role("bob", "user")
    acm.assign_role("charlie", "moderator")
    
    print("3. Testing access with zero-knowledge proofs...")
    
    # Test scenarios
    test_scenarios = [
        ("alice", "read", "sensitive_data.txt"),
        ("bob", "read", "public_data.txt"),
        ("bob", "write", "public_data.txt"),  # Should fail
        ("charlie", "write", "moderated_content.txt"),
        ("charlie", "delete", "moderated_content.txt"),  # Should fail
    ]
    
    for user, action, resource in test_scenarios:
        print(f"\n  Testing: {user} wants to {action} {resource}")
        
        # Check if user has permission
        has_permission = acm.check_permission(user, action)
        
        if has_permission:
            print(f"    ✓ Permission granted")
            
            # Generate zero-knowledge proof
            proof = prover.generate_proof(user, action, resource)
            print(f"    ✓ ZKP proof generated")
            
            # Verify proof
            is_valid = verifier.verify_proof(proof, resource)
            print(f"    ✓ Proof verification: {'VALID' if is_valid else 'INVALID'}")
        else:
            print(f"    ✗ Permission denied")
    
    print("\n" + "=" * 70)
    print("PrivAccess demonstration completed!")


if __name__ == "__main__":
    main()
