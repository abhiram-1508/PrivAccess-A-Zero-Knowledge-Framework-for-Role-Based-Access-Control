# rbac/access_control.py

class AccessControl:
    def __init__(self):
        pass

    def decide_access(self, proof_valid: bool, role_name: str) -> bool:
        """
        Decides access based on proof verification result.
        """
        if proof_valid:
            return True
        return False
