# rbac/roles.py

ROLES = {
    "ADMIN": "admin_secret_123",
    "USER": "user_secret_456",
    "MANAGER": "manager_secret_789"
}


def get_role_secret(role_name: str):
    """
    Returns the secret associated with a role.
    """
    return ROLES.get(role_name)
