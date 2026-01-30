# rbac/roles.py

ROLES = {
    "ADMIN": "admin_secret_123",
    "FACULTY": "faculty_secret_456",
    "STUDENT": "student_secret_789"
}


ROLE_PERMISSIONS = {
    "ADMIN": ["read", "write", "delete"],
    "FACULTY": ["read", "write"],
    "STUDENT": ["read"]
}


def get_role_secret(role_name: str):
    return ROLES.get(role_name)


def get_role_permissions(role_name: str):
    return ROLE_PERMISSIONS.get(role_name, [])