# PrivAccess - A Zero-Knowledge Framework for Role-Based Access Control

📌 **Abstract**

PrivAccess is a privacy-preserving access control framework that integrates Zero-Knowledge Proofs (ZKP) with Role-Based Access Control (RBAC) to authenticate users without revealing sensitive identity or role information. The system ensures that users can prove authorization to access protected resources while maintaining confidentiality of credentials.

🎯 **Objectives**

- Implement a Zero-Knowledge based authentication mechanism
- Enforce Role-Based Access Control without exposing user roles
- Preserve user privacy during authentication and authorization
- Prevent credential leakage and replay attacks

🧠 **Core Concepts**

- Zero-Knowledge Proofs (ZKP) (Schnorr Protocol)
- Role-Based Access Control (RBAC)
- Privacy-Preserving Authentication
- Cryptographic Commitments
- Secure Key Management

🏗️ **System Architecture**

1. **Setup**: User selects a role (e.g., ADMIN, STUDENT) and receives a cryptographic identity (Private/Public Key pair).
2. **Prover**: User generates a zero-knowledge proof of knowledge of their Private Key.
3. **Verifier**: Server validates the proof and checks if the corresponding Public Key is authorized for the requested resource.
4. **Access Control**: Access is granted only if the specific role is authorized.

🔐 **Cryptographic Techniques Used**

- Zero-Knowledge Proofs (Schnorr Non-Interactive Zero-Knowledge Proof)
- SHA-256 for cryptographic hashing
- Modular Exponentiation over Finite Fields
- Cryptographic commitments

## 📁 Project Structure

```
PrivAccess/
├── main.py                 # CLI demonstration entry point
├── app.py                  # Flask Web Application entry point
├── requirements.txt        # Python dependencies
├── README.md               # This file
│
├── zkp/                    # Zero-Knowledge Proof modules
│   ├── prover.py           # Schnorr Prover implementation
│   └── verifier.py         # Schnorr Verifier implementation
│
├── rbac/                   # Role-Based Access Control
│   ├── roles.py            # Role definitions and secret management
│   └── access_control.py   # Main access control logic
│
├── crypto/                 # Cryptographic utilities
│   └── hash_utils.py       # Hash functions (optional helper)
│   └── utils.py            # Mathematical utilities (Modular Exponentiation, Primes)
│
├── templates/              # HTML Templates for Web App
│   ├── door_display.html   # QR Code Display Page
│   └── mobile_app.html     # Mobile Client Page
│
├── static/                 # Static assets (JS, CSS, Images)
│   ├── js/                 # Client-side ZKP logic
│   ├── css/                # Stylesheets
│   └── img/                # Images (e.g., logo.jpg)
│
└── tests/                  # Test suite
    └── test_run.py         # Comprehensive tests
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

#### Option 1: Web Interface (Recommended)
This launches a web server where you can simulate a Mobile App unlocking a Door.

1. Start the Flask server:
```bash
python app.py
```
2. Open the displayed URL (e.g., `http://127.0.0.1:5000`) in your browser to see the "Door Lock" with a QR code.
3. Access the Mobile App simulation by scanning the QR code or navigating to the simulation URL.
4. **Select a Role** (e.g., ADMIN, FACULTY) to generate an identity.
5. Click **Unlock** to generate a ZKP and authenticate.

#### Option 2: CLI Demo
Run the command-line demonstration to test logic directly in the terminal.

```bash
python main.py
```
Follow the interactive prompts to generate and verify proofs.

## 🔧 Configuration

### Roles
The system comes with pre-configured roles in `rbac/roles.py`. 
*Note: In this demo, secrets are fixed integers for reproducibility.*

- **ADMIN**: Full access (read, write, delete)
- **FACULTY**: Read/Write access
- **STUDENT**: Read-only access

### Cryptographic Settings
- **Prime Group**: NIST/RFC-style safe prime grouping (simulated with smaller primes for demo speed/compatibility).
- **Proof**: Non-interactive Schnorr proof using Fiat-Shamir heuristic.

## 🔒 Security Features

- **Zero-Knowledge Property**: The Verifier checks the proof without ever seeing the User's Private Key.
- **Authorization Check**: The system validates that the Public Key used in the proof belongs to an authorized Role before granting access.
- **Role Isolation**: Different roles derive different keys, ensuring granular access control.

## 📊 System Information

The implementation provides:
- **Web-based ZKP**: JavaScript implementation of ZKP Prover running in the browser.
- **Python Verification**: robust backend verification logic.
- **Role Enforcement**: Strict checking of role permissions against requested actions.

## 📞 Support

For questions, issues, or contributions, please open an issue on the GitHub repository.

---

**Note**: This is a demonstration implementation focused on educational purposes. For production use, integrate with established ZKP libraries and undergo security audits.
