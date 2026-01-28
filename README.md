# PrivAccess - A Zero-Knowledge Framework for Role-Based Access Control

📌 **Abstract**

PrivAccess is a privacy-preserving access control framework that integrates Zero-Knowledge Proofs (ZKP) with Role-Based Access Control (RBAC) to authenticate users without revealing sensitive identity or role information. The system ensures that users can prove authorization to access protected resources while maintaining confidentiality of credentials.

🎯 **Objectives**

- Implement a Zero-Knowledge based authentication mechanism
- Enforce Role-Based Access Control without exposing user roles
- Preserve user privacy during authentication and authorization
- Prevent credential leakage and replay attacks

🧠 **Core Concepts**

- Zero-Knowledge Proofs (ZKP)
- Role-Based Access Control (RBAC)
- Privacy-Preserving Authentication
- Cryptographic Commitments
- Secure Key Management

🏗️ **System Architecture**

1. User generates a zero-knowledge proof of role possession
2. Verifier validates the proof without learning the role
3. Access Control Engine grants or denies access
4. Protected Resource is accessed only if verification succeeds

🔐 **Cryptographic Techniques Used**

- Zero-Knowledge Proofs (ZKP)
- SHA-256/SHA-512 for cryptographic hashing
- HMAC for message authentication
- Merkle trees for proof verification
- Cryptographic commitments

## 📁 Project Structure

```
PrivAccess/
├── main.py                 # Main entry point and demonstration
├── requirements.txt        # Python dependencies
├── README.md              # This file
│
├── zkp/                   # Zero-Knowledge Proof modules
│   ├── prover.py          # ZKP prover implementation
│   └── verifier.py        # ZKP verifier implementation
│
├── rbac/                  # Role-Based Access Control
│   ├── roles.py           # Role management and hierarchy
│   └── access_control.py  # Main access control logic
│
├── crypto/                # Cryptographic utilities
│   └── hash_utils.py      # Hash functions and crypto helpers
│
└── tests/                 # Test suite
    └── test_run.py        # Comprehensive tests
```

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd PrivAccess-A-Zero-Knowledge-Framework-for-Role-Based-Access-Control
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

### Running the Application

Execute the main demonstration:
```bash
python main.py
```

### Running Tests

Run the complete test suite:
```bash
python tests/test_run.py
```

## 💡 Usage Examples

### Basic Zero-Knowledge Proof Demo

```python
from rbac.roles import get_role_secret
from zkp.prover import Prover
from zkp.verifier import Verifier
from rbac.access_control import AccessControl

# Define role to test
role_name = "ADMIN"

# Get role secret
role_secret = get_role_secret(role_name)
if role_secret is None:
    print("Invalid role. Access Denied.")
else:
    # Prover generates proof
    prover = Prover(role_secret)
    proof = prover.generate_proof()
    print("Zero-knowledge proof generated")

    # Verifier verifies proof
    verifier = Verifier(role_secret)
    proof_valid = verifier.verify_proof(proof)

    # Access control decision
    access_control = AccessControl()
    access_granted = access_control.decide_access(proof_valid, role_name)

    if access_granted:
        print("Access Granted")
    else:
        print("Access Denied")
```

### Role Management

```python
from rbac.roles import get_role_secret

# Get secrets for different roles
admin_secret = get_role_secret("ADMIN")
user_secret = get_role_secret("USER")
manager_secret = get_role_secret("MANAGER")

# Check if role exists
if get_role_secret("INVALID_ROLE") is None:
    print("Role does not exist")
```

## 🔧 Configuration

### Default Roles

The system comes with pre-configured roles:
- **ADMIN**: Administrative access with secret "admin_secret_123"
- **USER**: Standard user access with secret "user_secret_456"
- **MANAGER**: Manager access with secret "manager_secret_789"

### Cryptographic Settings

Default hash algorithm: SHA-256
Proof structure: Commitment + Nonce
No time restrictions (simplified implementation)

## 🧪 Testing

The simplified test suite covers:
- Basic role secret management
- Zero-knowledge proof generation and verification
- Access control decision logic
- Hash-based commitment schemes

Run tests with detailed output:
```bash
python -m unittest tests.test_run -v
```

## 🔒 Security Features

- **Privacy-Preserving**: Users prove access without revealing role secrets
- **Cryptographic Commitments**: SHA-256 based commitment schemes
- **Simplified Architecture**: Reduced attack surface with minimal complexity
- **Role-Based Secrets**: Each role has unique cryptographic secret

## 📊 System Information

The simplified implementation provides:
- **3 predefined roles**: ADMIN, USER, MANAGER
- **Hash-based commitments**: SHA-256 cryptographic proofs
- **Minimal dependencies**: Only essential libraries required
- **Clean architecture**: Streamlined codebase for easier understanding

## 🔮 Future Enhancements

- Integration with real ZKP libraries (libsnark, py-zkp)
- Dynamic role creation and management
- Database persistence for roles and policies
- Web API interface
- Advanced policy engine
- Multi-tenancy support
- Audit logging and monitoring tools

## 📞 Support

For questions, issues, or contributions, please open an issue on the GitHub repository.

---

**Note**: This is a demonstration implementation focused on educational purposes. For production use, integrate with established ZKP libraries and undergo security audits.
