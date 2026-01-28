"""
Zero-Knowledge Prover Module for PrivAccess
Implements the prover side of zero-knowledge proof generation
"""

import json
import hashlib
import time
from typing import Dict, Any, Tuple, Optional
from crypto.hash_utils import HashUtils


class Prover:
    """Zero-Knowledge Prover for generating access control proofs"""
    
    def __init__(self):
        """Initialize the prover with cryptographic utilities"""
        self.hash_utils = HashUtils()
        self.proof_cache = {}
        
    def generate_proof(self, user: str, action: str, resource: str, 
                       secret_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate a zero-knowledge proof for access control
        
        Args:
            user: User identifier
            action: Action being performed (read, write, delete, etc.)
            resource: Resource being accessed
            secret_data: Optional secret data for proof generation
            
        Returns:
            Dictionary containing the zero-knowledge proof
        """
        timestamp = int(time.time())
        
        # Create commitment
        commitment = self._create_commitment(user, action, resource, timestamp)
        
        # Generate challenge
        challenge = self._generate_challenge(commitment, timestamp)
        
        # Generate response
        response = self._generate_response(challenge, user, action, resource)
        
        # Construct proof
        proof = {
            "commitment": commitment,
            "challenge": challenge,
            "response": response,
            "timestamp": timestamp,
            "resource": resource,
            "action": action,
            "proof_type": "zkp_access_control",
            "version": "1.0"
        }
        
        # Cache the proof
        proof_id = self.hash_utils.compute_hash(json.dumps(proof, sort_keys=True))
        self.proof_cache[proof_id] = proof
        
        return proof
    
    def _create_commitment(self, user: str, action: str, resource: str, timestamp: int) -> str:
        """Create a commitment for the proof"""
        commitment_data = f"{user}:{action}:{resource}:{timestamp}"
        return self.hash_utils.compute_hash(commitment_data)
    
    def _generate_challenge(self, commitment: str, timestamp: int) -> str:
        """Generate a cryptographic challenge"""
        challenge_data = f"{commitment}:{timestamp}:{self._get_random_nonce()}"
        return self.hash_utils.compute_hash(challenge_data)
    
    def _generate_response(self, challenge: str, user: str, action: str, resource: str) -> str:
        """Generate response to the challenge"""
        response_data = f"{challenge}:{user}:{action}:{resource}"
        return self.hash_utils.compute_hash(response_data)
    
    def _get_random_nonce(self) -> str:
        """Generate a random nonce for proof generation"""
        import random
        return str(random.randint(100000, 999999))
    
    def verify_proof_integrity(self, proof: Dict[str, Any]) -> bool:
        """
        Verify the integrity of a generated proof
        
        Args:
            proof: The proof to verify
            
        Returns:
            True if proof is valid, False otherwise
        """
        required_fields = ["commitment", "challenge", "response", "timestamp", "resource", "action"]
        
        # Check required fields
        for field in required_fields:
            if field not in proof:
                return False
        
        # Verify proof structure
        try:
            # Recompute commitment
            commitment_check = self._create_commitment(
                "user", proof["action"], proof["resource"], proof["timestamp"]
            )
            
            # Verify challenge
            challenge_check = self._generate_challenge(commitment_check, proof["timestamp"])
            
            return proof["challenge"] == challenge_check
            
        except Exception:
            return False
    
    def get_cached_proof(self, proof_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a cached proof by ID"""
        return self.proof_cache.get(proof_id)
    
    def clear_cache(self):
        """Clear the proof cache"""
        self.proof_cache.clear()
    
    def get_proof_statistics(self) -> Dict[str, int]:
        """Get statistics about generated proofs"""
        return {
            "total_proofs": len(self.proof_cache),
            "cache_size": len(self.proof_cache)
        }
