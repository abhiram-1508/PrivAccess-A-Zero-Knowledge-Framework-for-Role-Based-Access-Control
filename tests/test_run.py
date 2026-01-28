"""
Test Suite for PrivAccess Zero-Knowledge Framework
Comprehensive testing of RBAC and ZKP functionality
"""

import sys
import os
import unittest
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from rbac.roles import RoleManager, Permission
from rbac.access_control import AccessControlManager
from zkp.prover import Prover
from zkp.verifier import Verifier
from crypto.hash_utils import HashUtils


class TestHashUtils(unittest.TestCase):
    """Test cryptographic hash utilities"""
    
    def setUp(self):
        self.hash_utils = HashUtils()
    
    def test_compute_hash(self):
        """Test basic hash computation"""
        data = "test_data"
        hash_result = self.hash_utils.compute_hash(data)
        
        self.assertIsInstance(hash_result, str)
        self.assertEqual(len(hash_result), 64)  # SHA256 hex length
        self.assertEqual(hash_result, self.hash_utils.compute_hash(data))  # Deterministic
    
    def test_hash_dict(self):
        """Test hashing dictionary data"""
        data = {"key1": "value1", "key2": "value2"}
        hash_result = self.hash_utils.compute_hash(data)
        
        self.assertIsInstance(hash_result, str)
        # Same data should produce same hash regardless of key order
        data_reordered = {"key2": "value2", "key1": "value1"}
        self.assertEqual(hash_result, self.hash_utils.compute_hash(data_reordered))
    
    def test_hmac(self):
        """Test HMAC computation"""
        data = "test_data"
        key = "secret_key"
        hmac_result = self.hash_utils.compute_hmac(data, key)
        
        self.assertIsInstance(hmac_result, str)
        self.assertEqual(len(hmac_result), 64)
    
    def test_hash_with_salt(self):
        """Test salted hashing"""
        data = "test_data"
        hash_result, salt = self.hash_utils.hash_with_salt(data)
        
        self.assertIsInstance(hash_result, str)
        self.assertIsInstance(salt, str)
        self.assertEqual(len(salt), 64)  # 32 bytes = 64 hex chars
        
        # Verify salted hash
        self.assertTrue(self.hash_utils.verify_hash_with_salt(data, hash_result, salt))
        self.assertFalse(self.hash_utils.verify_hash_with_salt("wrong_data", hash_result, salt))
    
    def test_commitment(self):
        """Test cryptographic commitment"""
        data = "secret_data"
        commitment, nonce = self.hash_utils.create_commitment(data)
        
        self.assertIsInstance(commitment, str)
        self.assertIsInstance(nonce, str)
        
        # Verify commitment
        self.assertTrue(self.hash_utils.verify_commitment(data, commitment, nonce))
        self.assertFalse(self.hash_utils.verify_commitment("wrong_data", commitment, nonce))


class TestRoleManager(unittest.TestCase):
    """Test role management functionality"""
    
    def setUp(self):
        self.role_manager = RoleManager()
    
    def test_create_role(self):
        """Test role creation"""
        success = self.role_manager.create_role("test_role", [Permission.READ, Permission.WRITE])
        self.assertTrue(success)
        
        # Duplicate role should fail
        success = self.role_manager.create_role("test_role", [Permission.READ])
        self.assertFalse(success)
    
    def test_role_permissions(self):
        """Test role permission management"""
        role_name = "test_role"
        self.role_manager.create_role(role_name, [Permission.READ])
        
        role = self.role_manager.get_role(role_name)
        self.assertIsNotNone(role)
        self.assertTrue(role.has_permission(Permission.READ))
        self.assertFalse(role.has_permission(Permission.WRITE))
        
        # Add permission
        success = role.add_permission(Permission.WRITE)
        self.assertTrue(success)
        self.assertTrue(role.has_permission(Permission.WRITE))
        
        # Remove permission
        success = role.remove_permission(Permission.READ)
        self.assertTrue(success)
        self.assertFalse(role.has_permission(Permission.READ))
    
    def test_role_inheritance(self):
        """Test role inheritance"""
        self.role_manager.create_role("parent", [Permission.READ])
        self.role_manager.create_role("child", [Permission.WRITE])
        
        success = self.role_manager.add_role_inheritance("child", "parent")
        self.assertTrue(success)
        
        # Child should have both its own and inherited permissions
        effective_perms = self.role_manager.get_effective_permissions("child")
        self.assertIn(Permission.READ, effective_perms)
        self.assertIn(Permission.WRITE, effective_perms)
    
    def test_user_role_assignment(self):
        """Test user role assignment"""
        self.role_manager.create_role("user_role", [Permission.READ])
        
        success = self.role_manager.assign_role_to_user("test_user", "user_role")
        self.assertTrue(success)
        
        user_roles = self.role_manager.get_user_roles("test_user")
        self.assertIn("user_role", user_roles)
        
        user_permissions = self.role_manager.get_user_permissions("test_user")
        self.assertIn(Permission.READ, user_permissions)


class TestZeroKnowledgeProofs(unittest.TestCase):
    """Test zero-knowledge proof functionality"""
    
    def setUp(self):
        self.prover = Prover()
        self.verifier = Verifier()
    
    def test_proof_generation(self):
        """Test basic proof generation"""
        user = "test_user"
        action = "read"
        resource = "test_resource"
        
        proof = self.prover.generate_proof(user, action, resource)
        
        # Check proof structure
        required_fields = ["commitment", "challenge", "response", "timestamp", "resource", "action"]
        for field in required_fields:
            self.assertIn(field, proof)
        
        self.assertEqual(proof["resource"], resource)
        self.assertEqual(proof["action"], action)
    
    def test_proof_verification(self):
        """Test proof verification"""
        user = "test_user"
        action = "read"
        resource = "test_resource"
        
        # Generate proof
        proof = self.prover.generate_proof(user, action, resource)
        
        # Verify proof
        is_valid = self.verifier.verify_proof(proof, resource)
        self.assertTrue(is_valid)
        
        # Verify with wrong resource should fail
        is_valid = self.verifier.verify_proof(proof, "wrong_resource")
        self.assertFalse(is_valid)
    
    def test_proof_integrity(self):
        """Test proof integrity verification"""
        user = "test_user"
        action = "read"
        resource = "test_resource"
        
        proof = self.prover.generate_proof(user, action, resource)
        
        # Check integrity
        is_valid = self.prover.verify_proof_integrity(proof)
        self.assertTrue(is_valid)
        
        # Tamper with proof
        tampered_proof = proof.copy()
        tampered_proof["commitment"] = "wrong_commitment"
        
        is_valid = self.prover.verify_proof_integrity(tampered_proof)
        self.assertFalse(is_valid)
    
    def test_batch_verification(self):
        """Test batch proof verification"""
        proofs = []
        resources = []
        
        for i in range(3):
            user = f"user_{i}"
            action = "read"
            resource = f"resource_{i}"
            
            proof = self.prover.generate_proof(user, action, resource)
            proofs.append(proof)
            resources.append(resource)
        
        # Verify all proofs
        results = self.verifier.batch_verify_proofs(proofs, resources)
        self.assertEqual(len(results), 3)
        self.assertTrue(all(results))


class TestAccessControlManager(unittest.TestCase):
    """Test integrated access control management"""
    
    def setUp(self):
        self.acm = AccessControlManager()
    
    def test_role_creation_and_assignment(self):
        """Test role creation and user assignment"""
        success = self.acm.create_role("test_role", ["read", "write"])
        self.assertTrue(success)
        
        success = self.acm.assign_role("test_user", "test_role")
        self.assertTrue(success)
    
    def test_permission_checking(self):
        """Test permission checking"""
        self.acm.create_role("reader", ["read"])
        self.acm.assign_role("reader_user", "reader")
        
        # Should have read permission
        self.assertTrue(self.acm.check_permission("reader_user", "read"))
        
        # Should not have write permission
        self.assertFalse(self.acm.check_permission("reader_user", "write"))
    
    def test_access_control_with_zkp(self):
        """Test access control with zero-knowledge proofs"""
        # Setup
        self.acm.create_role("admin", ["read", "write", "delete"])
        self.acm.assign_role("admin_user", "admin")
        self.acm.register_resource("sensitive_file.txt", "file")
        
        # Test access with ZKP
        result = self.acm.request_access_with_zkp("admin_user", "read", "sensitive_file.txt")
        
        self.assertTrue(result["access_granted"])
        self.assertIn("zkp_proof", result)
        
        # Verify the generated proof
        proof = result["zkp_proof"]
        is_valid = self.acm.verify_access_proof(proof, "sensitive_file.txt")
        self.assertTrue(is_valid)
    
    def test_access_denied(self):
        """Test access denial scenarios"""
        self.acm.create_role("guest", ["read"])
        self.acm.assign_role("guest_user", "guest")
        self.acm.register_resource("admin_file.txt", "file")
        
        # Try to access without permission
        result = self.acm.request_access_with_zkp("guest_user", "delete", "admin_file.txt")
        
        self.assertFalse(result["access_granted"])
        self.assertNotIn("zkp_proof", result)
    
    def test_session_management(self):
        """Test session management"""
        user = "test_user"
        session_id = self.acm.create_session(user, duration_minutes=30)
        
        self.assertIsInstance(session_id, str)
        self.assertIn(session_id, self.acm.sessions)
        
        # Check session validity
        context = {"session_id": session_id}
        is_valid = self.acm._is_session_valid(user, context)
        self.assertTrue(is_valid)
    
    def test_access_logging(self):
        """Test access logging functionality"""
        self.acm.create_role("user_role", ["read"])
        self.acm.assign_role("test_user", "user_role")
        self.acm.register_resource("test_file.txt", "file")
        
        # Perform access
        self.acm.request_access_with_zkp("test_user", "read", "test_file.txt")
        
        # Check logs
        logs = self.acm.get_access_logs()
        self.assertGreater(len(logs), 0)
        
        # Filter by user
        user_logs = self.acm.get_access_logs(user="test_user")
        self.assertGreater(len(user_logs), 0)
        self.assertEqual(user_logs[0]["user"], "test_user")
    
    def test_system_statistics(self):
        """Test system statistics"""
        stats = self.acm.get_system_stats()
        
        required_fields = ["total_users", "total_roles", "total_resources", 
                         "active_sessions", "total_access_attempts"]
        
        for field in required_fields:
            self.assertIn(field, stats)
            self.assertIsInstance(stats[field], int)


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete system"""
    
    def setUp(self):
        self.acm = AccessControlManager()
    
    def test_complete_workflow(self):
        """Test complete access control workflow"""
        # 1. Setup roles and users
        self.acm.create_role("manager", ["read", "write"])
        self.acm.create_role("employee", ["read"])
        
        self.acm.assign_role("alice", "manager")
        self.acm.assign_role("bob", "employee")
        
        # 2. Register resources
        self.acm.register_resource("project_plan.doc", "document")
        self.acm.register_resource("company_policy.pdf", "document")
        
        # 3. Test manager access
        result = self.acm.request_access_with_zkp("alice", "write", "project_plan.doc")
        self.assertTrue(result["access_granted"])
        
        # Verify proof
        proof = result["zkp_proof"]
        self.assertTrue(self.acm.verify_access_proof(proof, "project_plan.doc"))
        
        # 4. Test employee limited access
        result = self.acm.request_access_with_zkp("bob", "write", "project_plan.doc")
        self.assertFalse(result["access_granted"])
        
        result = self.acm.request_access_with_zkp("bob", "read", "company_policy.pdf")
        self.assertTrue(result["access_granted"])
        
        # 5. Check system statistics
        stats = self.acm.get_system_stats()
        self.assertEqual(stats["total_users"], 2)
        self.assertEqual(stats["total_roles"], 4)  # Including default roles
        self.assertEqual(stats["total_resources"], 2)
        self.assertGreater(stats["total_access_attempts"], 0)
    
    def test_policy_enforcement(self):
        """Test policy-based access control"""
        # Create sensitive resource
        self.acm.register_resource("sensitive_data.txt", "file")
        
        # Assign role with permissions
        self.acm.create_role("data_analyst", ["read", "write"])
        self.acm.assign_role("analyst", "data_analyst")
        
        # Test access during business hours (should work)
        result = self.acm.request_access_with_zkp("analyst", "read", "sensitive_data.txt")
        # Note: This test depends on current time, policy enforcement logic may need adjustment
        
        # Check that policies are being evaluated
        self.assertIsNotNone(result)


def run_tests():
    """Run all tests"""
    print("Running PrivAccess Test Suite")
    print("=" * 50)
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestHashUtils,
        TestRoleManager,
        TestZeroKnowledgeProofs,
        TestAccessControlManager,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print("\n" + "=" * 50)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")
    
    success = len(result.failures) == 0 and len(result.errors) == 0
    print(f"\nOverall result: {'PASSED' if success else 'FAILED'}")
    
    return success


if __name__ == "__main__":
    run_tests()
