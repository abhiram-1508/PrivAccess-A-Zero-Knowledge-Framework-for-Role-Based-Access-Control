# PrivAccess - Running the Project

## 🏗️ New Rust Implementation
The project has been migrated to **Rust** for superior performance and security. The old Python version is deprecated.

### Prerequisites
1.  **Rust**: [Install Rust](https://rustup.rs/)
2.  **Node.js**: [Install Node.js](https://nodejs.org/) (Required for QR generation)

---

## 🚀 How to Run (Demo Mode)

1.  **Navigate to the app**:
    ```bash
    cd priv_access_rs
    ```
2.  **Start the Server**:
    ```bash
    cargo run
    ```
3.  **PC Workflow**:
    - Open `http://localhost:3000` on your laptop.
    - Login as **Student** or **Faculty**.
    - Click **Initialize Session**.
4.  **Mobile Workflow ('Just Scan')**:
    - Ensure your phone is on the same Wi-Fi.
    - Scan the QR code shown on your laptop screen.
    - **That's it!** The phone will automatically verify and unlock.

---

## ⚠️ Troubleshooting: Port 3000 Conflict
If you see the error `AddrInUse` (Only one usage of each socket address is normally permitted):

**Run these two commands in PowerShell:**
1. `netstat -ano | findstr :3000`  
   *(Note the number at the far right of the line, e.g., 1234)*
2. `taskkill /F /PID <NUMBER>`

---

## 📂 Project Structure
```
priv_access_rs/
├── src/            # Backend (main.rs, rbac.rs, zkp.rs)
├── templates/      # UI (index.html, mobile_app.html)
└── static/         # Assets (zkp.js, style.css)
```

## 🔐 Zero-Knowledge Features
- **Schnorr Protocol**: Identity verification without password leakage.
- **Geohash Protection**: Location verification with 5m precision.
- **Zero-Touch**: Automated mobile flow for seamless demonstrations.
