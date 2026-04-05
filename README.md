# 🚀 PrivAccess – A Zero-Knowledge Framework for Role-Based Access Control
### 🔐 Now with Zero-Touch “Just Scan” Workflow

## 📌 Abstract

PrivAccess is a privacy-preserving access control framework that combines Zero-Knowledge Proofs (ZKP) with Role-Based Access Control (RBAC).

It enables users to authenticate and gain access to protected resources without revealing their identity or role, ensuring strong confidentiality and security.

## 🎯 Objectives
- Implement a Zero-Knowledge-based authentication mechanism.
- Enforce RBAC without exposing user roles.
- Preserve user privacy during authentication and authorization.
- Prevent credential leakage and replay attacks.

## 🧠 Core Concepts
- Zero-Knowledge Proofs (ZKP) – Schnorr Protocol
- Role-Based Access Control (RBAC)
- Privacy-Preserving Authentication
- Cryptographic Commitments
- Secure Key Management

## 🏗️ System Architecture

### 1. Setup
- **User** selects a role (e.g., ADMIN, STUDENT, FACULTY).
- **Receives** a cryptographic identity (Private/Public key pair).

### 2. Prover
- **User** generates a Zero-Knowledge Proof proving ownership of their private key.

### 3. Verifier
- **Server** verifies the proof.
- **Checks** if the public key is authorized.

### 4. Access Control
- **Access** is granted only if the specific role has the appropriate permissions.

---

## 🔐 Cryptographic Techniques Used
- **Schnorr Non-Interactive Zero-Knowledge Proof (NIZK)**
- **SHA-256 hashing**
- **Modular exponentiation over finite fields**
- **Cryptographic commitments**

## 📁 Project Structure

```text
PrivAccess/
├── priv_access_rs/        # Main Rust Application
│   ├── src/               # Backend logic
│   ├── templates/         # UI templates
│   └── static/            # ZKP assets
├── zkp_circom/            # Circom/SNARK circuits
├── README.md              # Project overview
└── RUN.md                 # Setup & execution guide
```

---

## 🚀 Getting Started

### ✅ Prerequisites
- **Rust** (for backend server)
- **Node.js & npm** (for ZKP dependencies)

### ⚙️ Installation

```bash
git clone <repository-url>
cd PrivAccess-A-Zero-Knowledge-Framework-for-Role-Based-Access-Control
npm install
```

### ▶️ Running the Application (Windows Recommended)
Just run the automated script from the root:
```powershell
.\run.ps1
```
This script will:
1. Check for port 3000 conflicts and resolve them automatically.
2. Verify your Rust and Node.js environment.
3. Start the Axum server.

---

### 🌐 Manual Option: Web Interface

#### Step 1: Start Backend
```bash
cd priv_access_rs
cargo run
```

#### Step 2: Open UI (Laptop/PC)
1. Select role (Student / Faculty / Admin).
2. Enter credentials.
3. Click **INITIALIZE SESSION**.

#### Step 3: Scan QR Code 📱
1. Use your mobile phone to scan the generated QR.
2. Authentication completes automatically.

✅ **Zero interaction required on mobile!**

---

## 🔧 Configuration

### 👥 Roles
- **ADMIN** → Full access (read, write, delete)
- **FACULTY** → Read + Write access
- **STUDENT** → Read-only access

> ⚠️ **Note:** Demo uses fixed secrets for reproducibility.

### 🔑 Cryptographic Settings
- **Prime Group**: NIST/RFC-style safe primes (simplified for demo).
- **Proof Type**: Schnorr NIZK using Fiat-Shamir heuristic.

---

## 🔒 Security Features

### 🛡️ Zero-Knowledge Property
- Verifier validates the cryptographic proof without ever seeing the private key.

### 🔐 Authorization Check
- Public key must belong to an authorized role.

### 🧩 Role Isolation
- Each role uses distinct key derivation.
- Prevents cross-role privilege misuse.

---

## 📊 System Highlights
- 🌐 **Web-based ZKP Prover** (JavaScript/WASM)
- 🦀 **High-performance server & Verification** (Rust)
- 🔐 **Strict role-based enforcement**

---

## 📞 Support & Contribution

For issues, suggestions, or contributions:
👉 **Open an issue in the GitHub repository**
