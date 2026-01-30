# rbac/access_control.py

from rbac.roles import get_role_permissions


class AccessControl:
    def decide_access(self, proof_valid: bool, role_name: str, action: str) -> bool:
        """
        Decide access based on proof validity and role permissions
        """
        if not proof_valid:
            return False

        allowed_actions = get_role_permissions(role_name)
        return action in allowed_actions
