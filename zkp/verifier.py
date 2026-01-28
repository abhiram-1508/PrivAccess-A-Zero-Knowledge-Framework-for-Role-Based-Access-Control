"""
Zero-Knowledge Verifier Module for PrivAccess
Implements the verifier side of zero-knowledge proof verification
"""

import json
import time
from typing import Dict, Any, Optional, Tuple
from crypto.hash_utils import HashUtils


class Verifier:
    """Zero-Knowledge Verifier for validating access control proofs"""
    
    def __init__(self):
        """Initialize the verifier with cryptographic utilities"""
        self.hash_utils = HashUtils()
        self.verification_cache = {}
        self.max_proof_age = 300  # 5 minutes in seconds
        
    def verify_proof(self, proof: Dict[str, Any], resource: str) -> bool:
        """
        Verify a zero-knowledge proof for access control
        
        Args:
            proof: The zero-knowledge proof to verify
            resource: The resource being accessed
            
        Returns:
            True if proof is valid, False otherwise
        """
        # Basic validation
        if not self._validate_proof_structure(proof):
            return False
        
        # Check proof age
        if not self._check_proof_age(proof):
            return False
        
        # Verify resource match
        if proof.get("resource") != resource:
            return False
        
        # Verify cryptographic components
        if not self._verify_cryptographic_components(proof):
            return False
        
        # Cache successful verification
        proof_id = self._get_proof_id(proof)
        self.verification_cache[proof_id] = {
            "verified_at": time.time(),
            "resource": resource,
            "valid": True
        }
        
        return True
    
    def _validate_proof_structure(self, proof: Dict[str, Any]) -> bool:
        """Validate the basic structure of the proof"""
        required_fields = [
            "commitment", "challenge", "response", 
            "timestamp", "resource", "action", 
            "proof_type", "version"
        ]
        
        for field in required_fields:
            if field not in proof:
                return False
        
        # Check proof type
        if proof["proof_type"] != "zkp_access_control":
            return False
        
        # Check version compatibility
        if proof["version"] not in ["1.0"]:
            return False
        
        return True
    
    def _check_proof_age(self, proof: Dict[str, Any]) -> bool:
        """Check if the proof is within the acceptable time window"""
        try:
            proof_time = proof["timestamp"]
            current_time = time.time()
            age = current_time - proof_time
            
            return age <= self.max_proof_age
        except (ValueError, TypeError):
            return False
    
    def _verify_cryptographic_components(self, proof: Dict[str, Any]) -> bool:
        """Verify the cryptographic components of the proof"""
        try:
            # Verify commitment
            commitment_check = self._recompute_commitment(proof)
            if commitment_check != proof["commitment"]:
                return False
            
            # Verify challenge
            challenge_check = self._recompute_challenge(proof)
            if challenge_check != proof["challenge"]:
                return False
            
            # Verify response
            response_check = self._recompute_response(proof)
            if response_check != proof["response"]:
                return False
            
            return True
            
        except Exception:
            return False
    
    def _recompute_commitment(self, proof: Dict[str, Any]) -> str:
        """Recompute the commitment from proof data"""
        # Note: In a real implementation, this would use the actual user data
        # For demo purposes, we're using a simplified verification
        commitment_data = f"user:{proof['action']}:{proof['resource']}:{proof['timestamp']}"
        return self.hash_utils.compute_hash(commitment_data)
    
    def _recompute_challenge(self, proof: Dict[str, Any]) -> str:
        """Recompute the challenge from proof data"""
        # Simplified challenge verification
        challenge_data = f"{proof['commitment']}:{proof['timestamp']}:nonce"
        return self.hash_utils.compute_hash(challenge_data)
    
    def _recompute_response(self, proof: Dict[str, Any]) -> str:
        """Recompute the response from proof data"""
        # Simplified response verification
        response_data = f"{proof['challenge']}:user:{proof['action']}:{proof['resource']}"
        return self.hash_utils.compute_hash(response_data)
    
    def _get_proof_id(self, proof: Dict[str, Any]) -> str:
        """Generate a unique ID for the proof"""
        proof_data = json.dumps(proof, sort_keys=True)
        return self.hash_utils.compute_hash(proof_data)
    
    def batch_verify_proofs(self, proofs: list, resources: list) -> list:
        """
        Verify multiple proofs in batch
        
        Args:
            proofs: List of proofs to verify
            resources: List of corresponding resources
            
        Returns:
            List of boolean verification results
        """
        if len(proofs) != len(resources):
            raise ValueError("Number of proofs must match number of resources")
        
        results = []
        for proof, resource in zip(proofs, resources):
            result = self.verify_proof(proof, resource)
            results.append(result)
        
        return results
    
    def get_verification_status(self, proof_id: str) -> Optional[Dict[str, Any]]:
        """Get verification status for a cached proof"""
        return self.verification_cache.get(proof_id)
    
    def clear_verification_cache(self):
        """Clear the verification cache"""
        self.verification_cache.clear()
    
    def get_verification_statistics(self) -> Dict[str, Any]:
        """Get statistics about verification operations"""
        return {
            "cached_verifications": len(self.verification_cache),
            "max_proof_age": self.max_proof_age
        }
    
    def set_max_proof_age(self, seconds: int):
        """Set the maximum allowed age for proofs"""
        self.max_proof_age = seconds
