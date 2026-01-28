"""
Access Control Module for PrivAccess
Main access control logic combining RBAC with zero-knowledge proofs
"""

from typing import Dict, List, Set, Optional, Tuple, Any
from datetime import datetime, timedelta
import json

from .roles import RoleManager, Permission
from zkp.prover import Prover
from zkp.verifier import Verifier


class AccessControlManager:
    """Main access control manager combining RBAC and ZKP"""
    
    def __init__(self):
        """Initialize the access control manager"""
        self.role_manager = RoleManager()
        self.prover = Prover()
        self.verifier = Verifier()
        
        # Access logs
        self.access_logs: List[Dict[str, Any]] = []
        
        # Resource registry
        self.resources: Dict[str, Dict[str, Any]] = {}
        
        # Session management
        self.sessions: Dict[str, Dict[str, Any]] = {}
        
        # Policy rules
        self.policies: Dict[str, Dict[str, Any]] = {}
        
        # Initialize default policies
        self._initialize_default_policies()
    
    def _initialize_default_policies(self):
        """Initialize default access policies"""
        self.policies = {
            "default": {
                "description": "Default access policy",
                "rules": [
                    {
                        "resource_pattern": "*",
                        "required_permissions": [],
                        "time_restrictions": None,
                        "location_restrictions": None
                    }
                ]
            },
            "sensitive": {
                "description": "Policy for sensitive resources",
                "rules": [
                    {
                        "resource_pattern": "sensitive_*",
                        "required_permissions": [Permission.READ, Permission.WRITE],
                        "time_restrictions": {"start_hour": 9, "end_hour": 17},
                        "location_restrictions": None
                    }
                ]
            }
        }
    
    def create_role(self, name: str, permissions: List[str], description: str = "") -> bool:
        """
        Create a new role with specified permissions
        
        Args:
            name: Role name
            permissions: List of permission strings
            description: Role description
            
        Returns:
            True if role was created successfully
        """
        # Convert string permissions to Permission enum
        perm_objects = []
        for perm_str in permissions:
            try:
                perm = Permission(perm_str.lower())
                perm_objects.append(perm)
            except ValueError:
                continue
        
        return self.role_manager.create_role(name, perm_objects, description)
    
    def assign_role(self, user: str, role: str) -> bool:
        """
        Assign a role to a user
        
        Args:
            user: User identifier
            role: Role name
            
        Returns:
            True if role was assigned successfully
        """
        success = self.role_manager.assign_role_to_user(user, role)
        if success:
            self._log_access(user, "role_assignment", f"Assigned role: {role}")
        return success
    
    def check_permission(self, user: str, action: str) -> bool:
        """
        Check if a user has permission for a specific action
        
        Args:
            user: User identifier
            action: Action to check permission for
            
        Returns:
            True if user has permission
        """
        try:
            permission = Permission(action.lower())
            user_permissions = self.role_manager.get_user_permissions(user)
            return permission in user_permissions
        except ValueError:
            return False
    
    def check_access(self, user: str, action: str, resource: str, 
                    context: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """
        Check if a user can access a resource with a specific action
        
        Args:
            user: User identifier
            action: Action to perform
            resource: Resource to access
            context: Additional context for access decision
            
        Returns:
            Tuple of (access_granted, reason)
        """
        context = context or {}
        
        # Check basic permission
        if not self.check_permission(user, action):
            reason = f"User {user} lacks permission for action {action}"
            self._log_access(user, action, resource, False, reason)
            return False, reason
        
        # Check resource existence
        if resource not in self.resources:
            reason = f"Resource {resource} not found"
            self._log_access(user, action, resource, False, reason)
            return False, reason
        
        # Check policies
        policy_result = self._check_policies(user, action, resource, context)
        if not policy_result[0]:
            reason = policy_result[1]
            self._log_access(user, action, resource, False, reason)
            return False, reason
        
        # Check session validity
        if not self._is_session_valid(user, context):
            reason = "Invalid or expired session"
            self._log_access(user, action, resource, False, reason)
            return False, reason
        
        reason = f"Access granted for {user} to {action} {resource}"
        self._log_access(user, action, resource, True, reason)
        return True, reason
    
    def _check_policies(self, user: str, action: str, resource: str, 
                       context: Dict[str, Any]) -> Tuple[bool, str]:
        """Check access against defined policies"""
        user_permissions = self.role_manager.get_user_permissions(user)
        
        for policy_name, policy in self.policies.items():
            for rule in policy["rules"]:
                # Check resource pattern match
                if not self._match_resource_pattern(resource, rule["resource_pattern"]):
                    continue
                
                # Check required permissions
                required_perms = rule.get("required_permissions", [])
                if required_perms:
                    if not all(perm in user_permissions for perm in required_perms):
                        return False, f"Missing required permissions for policy {policy_name}"
                
                # Check time restrictions
                time_restrictions = rule.get("time_restrictions")
                if time_restrictions and not self._check_time_restrictions(time_restrictions):
                    return False, f"Time restrictions violated for policy {policy_name}"
                
                # Check location restrictions
                location_restrictions = rule.get("location_restrictions")
                if location_restrictions and not self._check_location_restrictions(location_restrictions, context):
                    return False, f"Location restrictions violated for policy {policy_name}"
        
        return True, "All policies satisfied"
    
    def _match_resource_pattern(self, resource: str, pattern: str) -> bool:
        """Check if resource matches pattern"""
        if pattern == "*":
            return True
        if pattern.endswith("*"):
            return resource.startswith(pattern[:-1])
        return resource == pattern
    
    def _check_time_restrictions(self, restrictions: Dict[str, int]) -> bool:
        """Check if current time satisfies restrictions"""
        current_hour = datetime.now().hour
        start_hour = restrictions.get("start_hour", 0)
        end_hour = restrictions.get("end_hour", 23)
        
        return start_hour <= current_hour <= end_hour
    
    def _check_location_restrictions(self, restrictions: Dict[str, Any], 
                                    context: Dict[str, Any]) -> bool:
        """Check if location satisfies restrictions"""
        # Simplified location check - in real implementation would use IP geolocation
        allowed_locations = restrictions.get("allowed_locations", [])
        current_location = context.get("location", "unknown")
        
        return not allowed_locations or current_location in allowed_locations
    
    def _is_session_valid(self, user: str, context: Dict[str, Any]) -> bool:
        """Check if user session is valid"""
        session_id = context.get("session_id")
        if not session_id:
            return True  # No session required for basic access
        
        session = self.sessions.get(session_id)
        if not session:
            return False
        
        # Check session expiration
        if datetime.now() > session["expires_at"]:
            del self.sessions[session_id]
            return False
        
        # Check session user match
        return session.get("user") == user
    
    def create_session(self, user: str, duration_minutes: int = 60) -> str:
        """
        Create a new user session
        
        Args:
            user: User identifier
            duration_minutes: Session duration in minutes
            
        Returns:
            Session ID
        """
        import uuid
        session_id = str(uuid.uuid4())
        
        self.sessions[session_id] = {
            "user": user,
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(minutes=duration_minutes),
            "last_activity": datetime.now()
        }
        
        return session_id
    
    def register_resource(self, resource_id: str, resource_type: str, 
                         metadata: Optional[Dict[str, Any]] = None):
        """
        Register a new resource
        
        Args:
            resource_id: Resource identifier
            resource_type: Type of resource
            metadata: Additional metadata
        """
        self.resources[resource_id] = {
            "type": resource_type,
            "metadata": metadata or {},
            "created_at": datetime.now(),
            "access_count": 0
        }
    
    def request_access_with_zkp(self, user: str, action: str, resource: str,
                               context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Request access with zero-knowledge proof generation
        
        Args:
            user: User identifier
            action: Action to perform
            resource: Resource to access
            context: Additional context
            
        Returns:
            Dictionary containing access decision and ZKP proof if granted
        """
        context = context or {}
        
        # Check access
        access_granted, reason = self.check_access(user, action, resource, context)
        
        result = {
            "access_granted": access_granted,
            "reason": reason,
            "user": user,
            "action": action,
            "resource": resource,
            "timestamp": datetime.now().isoformat()
        }
        
        if access_granted:
            # Generate zero-knowledge proof
            proof = self.prover.generate_proof(user, action, resource)
            result["zkp_proof"] = proof
            
            # Update resource access count
            if resource in self.resources:
                self.resources[resource]["access_count"] += 1
        
        return result
    
    def verify_access_proof(self, proof: Dict[str, Any], resource: str) -> bool:
        """
        Verify a zero-knowledge proof for resource access
        
        Args:
            proof: Zero-knowledge proof
            resource: Resource being accessed
            
        Returns:
            True if proof is valid
        """
        return self.verifier.verify_proof(proof, resource)
    
    def _log_access(self, user: str, action: str, resource: str, 
                   success: bool, reason: str = ""):
        """Log access attempt"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "user": user,
            "action": action,
            "resource": resource,
            "success": success,
            "reason": reason
        }
        self.access_logs.append(log_entry)
    
    def get_access_logs(self, user: Optional[str] = None, 
                       limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get access logs with optional filtering
        
        Args:
            user: Filter by user (optional)
            limit: Maximum number of entries to return
            
        Returns:
            List of access log entries
        """
        logs = self.access_logs
        
        if user:
            logs = [log for log in logs if log["user"] == user]
        
        # Return most recent logs first
        return sorted(logs, key=lambda x: x["timestamp"], reverse=True)[:limit]
    
    def get_user_info(self, user: str) -> Dict[str, Any]:
        """
        Get comprehensive user information
        
        Args:
            user: User identifier
            
        Returns:
            Dictionary with user information
        """
        return {
            "user": user,
            "roles": self.role_manager.get_user_roles(user),
            "permissions": [p.value for p in self.role_manager.get_user_permissions(user)],
            "active_sessions": len([s for s in self.sessions.values() if s["user"] == user]),
            "access_attempts": len([log for log in self.access_logs if log["user"] == user])
        }
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get system statistics"""
        return {
            "total_users": len(self.role_manager.user_roles),
            "total_roles": len(self.role_manager.roles),
            "total_resources": len(self.resources),
            "active_sessions": len(self.sessions),
            "total_access_attempts": len(self.access_logs),
            "zkp_proofs_generated": self.prover.get_proof_statistics()["total_proofs"],
            "zkp_verifications": len(self.verifier.verification_cache)
        }
