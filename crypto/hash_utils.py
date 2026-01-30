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
        """
        if isinstance(data, dict):
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
        Compute HMAC
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
        return os.urandom(length).hex()
    
    def hash_with_salt(self, data: Union[str, bytes], salt: Optional[str] = None) -> tuple[str, str]:
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
        computed_hash, _ = self.hash_with_salt(data, salt)
        return hmac.compare_digest(computed_hash, hash_value)
    
    def compute_merkle_root(self, hashes: list[str]) -> str:
        if not hashes:
            return self.compute_hash("")
        
        if len(hashes) == 1:
            return hashes[0]
        
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        
        next_level = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i + 1]
            next_level.append(self.compute_hash(combined))
        
        return self.compute_merkle_root(next_level)
    
    def create_commitment(self, data: Union[str, bytes], nonce: Optional[str] = None) -> tuple[str, str]:
        if nonce is None:
            nonce = self.generate_salt()
        
        commitment_data = f"{data}:{nonce}"
        commitment = self.compute_hash(commitment_data)
        
        return commitment, nonce
    
    def verify_commitment(self, data: Union[str, bytes], commitment: str, nonce: str) -> bool:
        computed_commitment, _ = self.create_commitment(data, nonce)
        return hmac.compare_digest(computed_commitment, commitment)
    
    def hash_proof_components(self, components: Dict[str, Any]) -> str:
        sorted_components = sorted(components.items())
        
        component_hashes = []
        for key, value in sorted_components:
            component_hash = self.compute_hash(f"{key}:{value}")
            component_hashes.append(component_hash)
        
        combined = "".join(component_hashes)
        return self.compute_hash(combined)
    
    def generate_key_pair(self) -> tuple[str, str]:
        private_key = self.generate_salt(64)
        public_key = self.compute_hash(f"pub:{private_key}")
        return public_key, private_key
    
    def sign_data(self, data: Union[str, bytes], private_key: str) -> str:
        signature_data = f"{data}:{private_key}"
        return self.compute_hash(signature_data)
    
    def verify_signature(self, data: Union[str, bytes], signature: str, public_key: str) -> bool:
        expected_signature = self.compute_hash(f"{data}:{public_key}")
        return hmac.compare_digest(signature, expected_signature)
    
    def get_hash_info(self) -> Dict[str, Any]:
        return {
            "algorithm": self.hash_algorithm,
            "supported_algorithms": list(self.supported_algorithms.keys()),
            "hash_length": hashlib.new(self.hash_algorithm).digest_size * 8,
            "is_secure": self.hash_algorithm in ["sha256", "sha512", "sha384", "sha224"]
        }


# =========================================================
# 🔧 MODIFICATION (ONLY THIS PART IS NEW)
# Compatibility wrapper for ZKP modules
# =========================================================

_default_hash_utils = HashUtils()


def generate_commitment(data: str, nonce: str) -> str:
    """
    Functional wrapper required by ZKP prover/verifier.
    """
    commitment, _ = _default_hash_utils.create_commitment(data, nonce)
    return commitment
