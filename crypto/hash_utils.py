"""
Hash Utilities Module for PrivAccess
Provides cryptographic hashing functions for zero-knowledge proofs
"""

import hashlib
import hmac
import os
import json
from typing import Dict, Any, Optional, Union


class HashUtils:
    """Utility class for cryptographic hashing operations"""
    
    def __init__(self, hash_algorithm: str = "sha256"):
        """
        Initialize hash utilities
        
        Args:
            hash_algorithm: Hash algorithm to use (sha256, sha512, etc.)
        """
        self.hash_algorithm = hash_algorithm.lower()
        self.supported_algorithms = {
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512,
            "sha1": hashlib.sha1,
            "md5": hashlib.md5,
            "sha384": hashlib.sha384,
            "sha224": hashlib.sha224
        }
        
        if self.hash_algorithm not in self.supported_algorithms:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")
    
    def compute_hash(self, data: Union[str, bytes, Dict[str, Any]]) -> str:
        """
        Compute hash of given data
        
        Args:
            data: Data to hash (string, bytes, or dictionary)
            
        Returns:
            Hexadecimal hash string
        """
        if isinstance(data, dict):
            # Convert dict to JSON string with sorted keys for consistency
            data = json.dumps(data, sort_keys=True, separators=(',', ':'))
        elif isinstance(data, str):
            data = data.encode('utf-8')
        elif not isinstance(data, bytes):
            data = str(data).encode('utf-8')
        
        hash_func = self.supported_algorithms[self.hash_algorithm]()
        hash_func.update(data)
        return hash_func.hexdigest()
    
    def compute_hmac(self, data: Union[str, bytes], key: Union[str, bytes]) -> str:
        """
        Compute HMAC (Hash-based Message Authentication Code)
        
        Args:
            data: Data to authenticate
            key: Secret key for HMAC
            
        Returns:
            Hexadecimal HMAC string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        elif not isinstance(data, bytes):
            data = str(data).encode('utf-8')
        
        if isinstance(key, str):
            key = key.encode('utf-8')
        elif not isinstance(key, bytes):
            key = str(key).encode('utf-8')
        
        hmac_func = hmac.new(key, data, getattr(hashlib, self.hash_algorithm))
        return hmac_func.hexdigest()
    
    def generate_salt(self, length: int = 32) -> str:
        """
        Generate a random salt for hashing
        
        Args:
            length: Length of salt in bytes
            
        Returns:
            Hexadecimal salt string
        """
        return os.urandom(length).hex()
    
    def hash_with_salt(self, data: Union[str, bytes], salt: Optional[str] = None) -> tuple[str, str]:
        """
        Hash data with salt
        
        Args:
            data: Data to hash
            salt: Salt to use (generated if not provided)
            
        Returns:
            Tuple of (hash, salt)
        """
        if salt is None:
            salt = self.generate_salt()
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        elif not isinstance(data, bytes):
            data = str(data).encode('utf-8')
        
        salt_bytes = bytes.fromhex(salt)
        combined_data = data + salt_bytes
        
        hash_func = self.supported_algorithms[self.hash_algorithm]()
        hash_func.update(combined_data)
        
        return hash_func.hexdigest(), salt
    
    def verify_hash_with_salt(self, data: Union[str, bytes], hash_value: str, salt: str) -> bool:
        """
        Verify hash against data and salt
        
        Args:
            data: Original data
            hash_value: Hash to verify against
            salt: Salt used for hashing
            
        Returns:
            True if hash matches
        """
        computed_hash, _ = self.hash_with_salt(data, salt)
        return hmac.compare_digest(computed_hash, hash_value)
    
    def compute_merkle_root(self, hashes: list[str]) -> str:
        """
        Compute Merkle root from list of hashes
        
        Args:
            hashes: List of hash strings
            
        Returns:
            Merkle root hash
        """
        if not hashes:
            return self.compute_hash("")
        
        if len(hashes) == 1:
            return hashes[0]
        
        # Make sure we have an even number of hashes
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        
        # Compute next level
        next_level = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i + 1]
            next_level.append(self.compute_hash(combined))
        
        # Recursively compute root
        return self.compute_merkle_root(next_level)
    
    def create_commitment(self, data: Union[str, bytes], nonce: Optional[str] = None) -> tuple[str, str]:
        """
        Create a cryptographic commitment
        
        Args:
            data: Data to commit to
            nonce: Random nonce (generated if not provided)
            
        Returns:
            Tuple of (commitment, nonce)
        """
        if nonce is None:
            nonce = self.generate_salt()
        
        commitment_data = f"{data}:{nonce}"
        commitment = self.compute_hash(commitment_data)
        
        return commitment, nonce
    
    def verify_commitment(self, data: Union[str, bytes], commitment: str, nonce: str) -> bool:
        """
        Verify a commitment
        
        Args:
            data: Original data
            commitment: Commitment to verify
            nonce: Nonce used for commitment
            
        Returns:
            True if commitment is valid
        """
        computed_commitment, _ = self.create_commitment(data, nonce)
        return hmac.compare_digest(computed_commitment, commitment)
    
    def hash_proof_components(self, components: Dict[str, Any]) -> str:
        """
        Hash multiple components of a zero-knowledge proof
        
        Args:
            components: Dictionary of proof components
            
        Returns:
            Combined hash of all components
        """
        # Sort components for consistent ordering
        sorted_components = sorted(components.items())
        
        # Hash each component and combine
        component_hashes = []
        for key, value in sorted_components:
            component_hash = self.compute_hash(f"{key}:{value}")
            component_hashes.append(component_hash)
        
        # Compute final hash of all component hashes
        combined = "".join(component_hashes)
        return self.compute_hash(combined)
    
    def generate_key_pair(self) -> tuple[str, str]:
        """
        Generate a simple key pair for demonstration purposes
        Note: This is NOT cryptographically secure for production use
        
        Returns:
            Tuple of (public_key, private_key)
        """
        private_key = self.generate_salt(64)
        public_key = self.compute_hash(f"pub:{private_key}")
        
        return public_key, private_key
    
    def sign_data(self, data: Union[str, bytes], private_key: str) -> str:
        """
        Sign data with private key (demonstration only)
        Note: This is NOT a real digital signature algorithm
        
        Args:
            data: Data to sign
            private_key: Private key for signing
            
        Returns:
            Signature string
        """
        signature_data = f"{data}:{private_key}"
        return self.compute_hash(signature_data)
    
    def verify_signature(self, data: Union[str, bytes], signature: str, public_key: str) -> bool:
        """
        Verify signature with public key (demonstration only)
        Note: This is NOT a real signature verification
        
        Args:
            data: Original data
            signature: Signature to verify
            public_key: Public key for verification
            
        Returns:
            True if signature is valid
        """
        # In a real implementation, this would use proper cryptographic algorithms
        # For demonstration, we'll use a simple hash-based approach
        expected_signature = self.compute_hash(f"{data}:{public_key}")
        return hmac.compare_digest(signature, expected_signature)
    
    def get_hash_info(self) -> Dict[str, Any]:
        """
        Get information about the hash configuration
        
        Returns:
            Dictionary with hash information
        """
        return {
            "algorithm": self.hash_algorithm,
            "supported_algorithms": list(self.supported_algorithms.keys()),
            "hash_length": hashlib.new(self.hash_algorithm).digest_size * 8,  # bits
            "is_secure": self.hash_algorithm in ["sha256", "sha512", "sha384", "sha224"]
        }
