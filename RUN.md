# PrivAccess - Running the Rust Project

## Project Overview

**PrivAccess** is a Zero-Knowledge Framework for Role-Based Access Control, now fully implemented in **Rust** using the Axum web framework.

- **Language**: Rust 2021 Edition
- **Web Framework**: Axum
- **Port**: 3000
- **Modules**:
  - `crypto.rs` - Cryptographic utilities (modular exponentiation, secrets)
  - `rbac.rs` - Role-Based Access Control definitions
  - `zkp.rs` - Zero-Knowledge Proof verification (Schnorr protocol)
  - `main.rs` - Web server routes and handlers

## Prerequisites

You need to install one of the following:

### Option 1: Visual Studio Build Tools (RECOMMENDED)
1. Download [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/)
2. Select "Desktop development with C++" workload
3. Install the tools

### Option 3: Node.js & NPM (REQUIRED for ZKP)
1. Download [Node.js](https://nodejs.org/)
2. Ensure `node` and `npm` are in your PATH.
3. Install dependencies: `npm install -g circom snarkjs`

## Building the Project

```bash
cd priv_access_rs
cargo build --release
```

The first build may take 2-5 minutes as it compiles all dependencies.

## Running the Project

### Option 1: Using cargo run
```bash
cd priv_access_rs
cargo run --release
```

### Option 2: Using the compiled executable
```bash
./target/release/priv_access_rs.exe
```

## Geohash ZKP Setup (New)

### 1. Circuit Compilation
Navigate to `zkp_circom/` and run (if tools are installed):
```bash
# 1. Compile Circuit
circom geohash_prefix.circom --wasm --r1cs
# 2. Trusted Setup (Groth16)
snarkjs groth16 setup geohash_prefix.r1cs powersOfTau28_hez_final_12.ptau geohash_prefix_0000.zkey
# 3. Export Verification Key
snarkjs zkey export verificationkey geohash_prefix_final.zkey verification_key.json
```
*Note: Ensure `verification_key.json` is in `zkp_circom/` and `.wasm`/.zkey are in `priv_access_rs/static/zkp/`.*

### 2. Node.js Verifier
The Rust backend calls `zkp_circom/verify_proof.js` automatically. Ensure you run `npm install snarkjs` in the project root if you haven't.

## Expected Output

When running successfully, you should see:
```
Listening on http://0.0.0.0:3000
```

## Accessing the Application

Once running, visit:
- **Door Display**: http://localhost:3000/door/101
- **Mobile App**: http://localhost:3000/mobile/scan?door=101

## Features

1. **Zero-Knowledge Proofs**: Uses both Schnorr protocol and Groth16 (SNARKs) for privacy.
2. **Geohash Geofencing**: Proves user location remains within an allowed region (e.g., specific building).
3. **Role-Based Access**: Supports ADMIN, FACULTY, and STUDENT roles.
4. **QR Code Integration**: Displays QR codes for mobile authentication and door unlocking.
5. **RESTful API**: `/verify` endpoint for SNARK proof verification via Node.js bridge.

## Project Structure

```
priv_access_rs/
├── Cargo.toml              # Project manifest
├── src/
│   ├── main.rs            # Web server & routes
│   ├── crypto.rs          # Cryptography
│   ├── rbac.rs            # Role definitions
│   └── zkp.rs             # Zero-knowledge proofs
├── templates/
│   ├── door_display.html  # Door lock UI
│   └── mobile_app.html    # Mobile scanner UI
└── static/
    ├── css/style.css
    ├── js/main.js
    └── js/zkp.js
```

## Troubleshooting

**Error: "linker `link.exe` not found"**
- Install Visual Studio Build Tools with C++ development tools

**Error: "Could not find Cargo.toml"**
- Make sure you're in the `priv_access_rs` directory

**Port 3000 already in use**
- The application will fail to bind. Change the port in `src/main.rs` line that says `bind("0.0.0.0:3000")`

## Development

To make changes to the code:

1. Edit files in `src/` directory
2. Run `cargo check` to verify compilation
3. Run `cargo run` to rebuild and run
4. Tests can be run with `cargo test`

## Cargo Commands Reference

- `cargo build` - Build in debug mode
- `cargo build --release` - Build optimized for production
- `cargo run` - Build and run in debug mode
- `cargo run --release` - Build and run optimized
- `cargo check` - Quick syntax check without building
- `cargo test` - Run tests
- `cargo clean` - Remove build artifacts
