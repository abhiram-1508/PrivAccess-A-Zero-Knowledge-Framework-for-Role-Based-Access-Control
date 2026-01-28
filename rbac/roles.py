"""
Roles Module for PrivAccess RBAC System
Defines role management and role hierarchy
"""

from typing import Dict, List, Set, Optional
from enum import Enum


class Permission(Enum):
    """Enumeration of available permissions"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    ADMIN = "admin"


class Role:
    """Represents a role with specific permissions"""
    
    def __init__(self, name: str, permissions: List[Permission] = None):
        """
        Initialize a role
        
        Args:
            name: Role name
            permissions: List of permissions for this role
        """
        self.name = name
        self.permissions: Set[Permission] = set(permissions or [])
        self.parent_roles: Set[str] = set()
        self.child_roles: Set[str] = set()
        self.description = ""
        self.created_at = None
        self.modified_at = None
        
    def add_permission(self, permission: Permission) -> bool:
        """
        Add a permission to the role
        
        Args:
            permission: Permission to add
            
        Returns:
            True if permission was added, False if already present
        """
        if permission in self.permissions:
            return False
        
        self.permissions.add(permission)
        return True
    
    def remove_permission(self, permission: Permission) -> bool:
        """
        Remove a permission from the role
        
        Args:
            permission: Permission to remove
            
        Returns:
            True if permission was removed, False if not present
        """
        if permission not in self.permissions:
            return False
        
        self.permissions.remove(permission)
        return True
    
    def has_permission(self, permission: Permission) -> bool:
        """
        Check if role has a specific permission
        
        Args:
            permission: Permission to check
            
        Returns:
            True if role has the permission
        """
        return permission in self.permissions
    
    def get_permissions(self) -> List[Permission]:
        """Get list of permissions for this role"""
        return list(self.permissions)
    
    def add_parent_role(self, role_name: str):
        """Add a parent role (for inheritance)"""
        self.parent_roles.add(role_name)
    
    def add_child_role(self, role_name: str):
        """Add a child role (for inheritance)"""
        self.child_roles.add(role_name)
    
    def to_dict(self) -> Dict:
        """Convert role to dictionary representation"""
        return {
            "name": self.name,
            "permissions": [p.value for p in self.permissions],
            "parent_roles": list(self.parent_roles),
            "child_roles": list(self.child_roles),
            "description": self.description,
            "created_at": self.created_at,
            "modified_at": self.modified_at
        }


class RoleManager:
    """Manages roles and role hierarchy"""
    
    def __init__(self):
        """Initialize the role manager"""
        self.roles: Dict[str, Role] = {}
        self.user_roles: Dict[str, Set[str]] = {}
        self._initialize_default_roles()
    
    def _initialize_default_roles(self):
        """Initialize default system roles"""
        # Create default roles
        self.create_role("guest", [Permission.READ])
        self.create_role("user", [Permission.READ, Permission.WRITE])
        self.create_role("moderator", [Permission.READ, Permission.WRITE, Permission.EXECUTE])
        self.create_role("admin", list(Permission))
        
        # Set up role hierarchy
        self.add_role_inheritance("user", "guest")
        self.add_role_inheritance("moderator", "user")
        self.add_role_inheritance("admin", "moderator")
    
    def create_role(self, name: str, permissions: List[Permission] = None, 
                   description: str = "") -> bool:
        """
        Create a new role
        
        Args:
            name: Role name
            permissions: List of permissions
            description: Role description
            
        Returns:
            True if role was created, False if already exists
        """
        if name in self.roles:
            return False
        
        role = Role(name, permissions)
        role.description = description
        self.roles[name] = role
        return True
    
    def delete_role(self, name: str) -> bool:
        """
        Delete a role
        
        Args:
            name: Role name to delete
            
        Returns:
            True if role was deleted, False if not found
        """
        if name not in self.roles:
            return False
        
        # Remove from user assignments
        for user, user_role_set in self.user_roles.items():
            user_role_set.discard(name)
        
        # Remove from role hierarchy
        role = self.roles[name]
        for parent_role in role.parent_roles:
            if parent_role in self.roles:
                self.roles[parent_role].child_roles.discard(name)
        
        for child_role in role.child_roles:
            if child_role in self.roles:
                self.roles[child_role].parent_roles.discard(name)
        
        # Delete the role
        del self.roles[name]
        return True
    
    def get_role(self, name: str) -> Optional[Role]:
        """Get a role by name"""
        return self.roles.get(name)
    
    def list_roles(self) -> List[str]:
        """Get list of all role names"""
        return list(self.roles.keys())
    
    def add_role_inheritance(self, child_role: str, parent_role: str) -> bool:
        """
        Add inheritance relationship between roles
        
        Args:
            child_role: Child role name
            parent_role: Parent role name
            
        Returns:
            True if inheritance was added, False otherwise
        """
        if child_role not in self.roles or parent_role not in self.roles:
            return False
        
        # Check for circular inheritance
        if self._would_create_circular_inheritance(child_role, parent_role):
            return False
        
        self.roles[child_role].add_parent_role(parent_role)
        self.roles[parent_role].add_child_role(child_role)
        return True
    
    def _would_create_circular_inheritance(self, child: str, parent: str) -> bool:
        """Check if adding inheritance would create a circular dependency"""
        visited = set()
        
        def dfs(role_name: str) -> bool:
            if role_name == child:
                return True
            if role_name in visited:
                return False
            
            visited.add(role_name)
            role = self.roles.get(role_name)
            if not role:
                return False
            
            for parent in role.parent_roles:
                if dfs(parent):
                    return True
            
            return False
        
        return dfs(parent)
    
    def get_effective_permissions(self, role_name: str) -> Set[Permission]:
        """
        Get all effective permissions for a role (including inherited)
        
        Args:
            role_name: Role name
            
        Returns:
            Set of effective permissions
        """
        if role_name not in self.roles:
            return set()
        
        effective_perms = set()
        visited = set()
        
        def collect_permissions(role_name: str):
            if role_name in visited or role_name not in self.roles:
                return
            
            visited.add(role_name)
            role = self.roles[role_name]
            effective_perms.update(role.permissions)
            
            for parent in role.parent_roles:
                collect_permissions(parent)
        
        collect_permissions(role_name)
        return effective_perms
    
    def assign_role_to_user(self, user: str, role_name: str) -> bool:
        """
        Assign a role to a user
        
        Args:
            user: User identifier
            role_name: Role name
            
        Returns:
            True if role was assigned, False otherwise
        """
        if role_name not in self.roles:
            return False
        
        if user not in self.user_roles:
            self.user_roles[user] = set()
        
        self.user_roles[user].add(role_name)
        return True
    
    def remove_role_from_user(self, user: str, role_name: str) -> bool:
        """
        Remove a role from a user
        
        Args:
            user: User identifier
            role_name: Role name
            
        Returns:
            True if role was removed, False otherwise
        """
        if user not in self.user_roles:
            return False
        
        return role_name in self.user_roles[user] and self.user_roles[user].remove(role_name) is None
    
    def get_user_roles(self, user: str) -> List[str]:
        """Get all roles assigned to a user"""
        return list(self.user_roles.get(user, set()))
    
    def get_user_permissions(self, user: str) -> Set[Permission]:
        """
        Get all permissions for a user (from all assigned roles)
        
        Args:
            user: User identifier
            
        Returns:
            Set of user permissions
        """
        user_perms = set()
        user_role_names = self.user_roles.get(user, set())
        
        for role_name in user_role_names:
            role_perms = self.get_effective_permissions(role_name)
            user_perms.update(role_perms)
        
        return user_perms
