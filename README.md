# 🔐 Crypto Toolkit

A Python cryptography toolkit built with CustomTkinter, providing a clean dark-mode GUI for performing symmetric encryption, asymmetric encryption, secure hashing, and data encoding — all in one place.

---

## 👥 Team Members

| Name | GitHub |
|------|--------|
| [Member 1 Name] | [@FarahHossam126](https://github.com/FarahHossam126) |
| [Member 2 Name] | [@hlaessam504](https://github.com/hlaessam504)       |
| [Member 3 Name] | [@menna0602](https://github.com/menna0602) |
| [Member 4 Name] | [@username](https://github.com/username) |

---

## 📌 Project Overview

This project demonstrates core concepts in modern cryptography through an interactive GUI application. It integrates four cryptographic modules under a single tabbed interface, covering both classical and modern algorithms — from legacy DES to authenticated AES-GCM and hybrid RSA encryption.

---

## 📂 Repository Structure

```
Crypto_Toolkit/
│
├── crypto_toolkit.py       # Main application source code
└── README.md               # This file
```

---

## 🖥️ Application Interface

The application uses a **dark-mode tabbed interface** (1050×850) with four tabs:

| Tab | Module |
|-----|--------|
| **Symmetric** | AES-GCM · DES-CBC · 3DES-CBC |
| **RSA** | 2048-bit RSA with Hybrid AES-GCM |
| **Hashing** | SHA-256 · SHA-512 with salting |
| **Encoding** | Base64 · Hex · URL |

---

## 🗂️ Features

### 🔒 Tab 1 — Symmetric Encryption

Supports three symmetric algorithms selectable from a dropdown menu:

| Algorithm | Mode | Key Size | Security Level |
|-----------|------|----------|---------------|
| **AES** | GCM (Authenticated) | 256-bit (32 bytes) | ✅ Modern — Recommended |
| **DES** | CBC | 56-bit (8 bytes) | ⚠️ Legacy — Educational only |
| **3DES** | CBC | 112-bit (16B) or 168-bit (24B) | ⚠️ Deprecated — Better than DES |

**How it works:**
- The secret key is entered via a password field with a **Show/Hide toggle**
- **AES-GCM**: generates a random nonce, encrypts the plaintext, and produces an authentication tag — all three are Base64-encoded together. Decryption verifies the tag before returning the plaintext
- **DES/3DES**: generates a random IV, pads the plaintext to match the block size, encrypts in CBC mode, and prepends the IV to the ciphertext before Base64 encoding

---

### 🔑 Tab 2 — Asymmetric Encryption (RSA)

Implements **Hybrid Encryption** to overcome RSA's data-size limitations:

```
Encryption:
  1. Generate random 256-bit AES key
  2. Encrypt plaintext with AES-GCM → (ciphertext + nonce + tag)
  3. Encrypt AES key with RSA public key (PKCS1-OAEP)
  4. Base64-encode: [enc_AES_key (256B)] + [nonce (16B)] + [tag (16B)] + [ciphertext]

Decryption:
  1. Base64-decode and split by byte offsets
  2. Decrypt AES key using RSA private key
  3. Decrypt ciphertext with AES-GCM and verify integrity tag
```

**Key Management:**
- **Generate** a new 2048-bit RSA key pair at runtime
- **Save** keys to a `.pem` file for reuse across sessions
- **Load** keys from an existing `.pem` file

---

### #️⃣ Tab 3 — Secure Salted Hashing

| Algorithm | Output Size | Output (hex chars) |
|-----------|-------------|-------------------|
| SHA-256 | 256 bits | 64 characters |
| SHA-512 | 512 bits | 128 characters |

- Salt is concatenated with input before hashing: `hash(salt + text)`
- Salt field is **hidden by default** with a Show/Hide toggle
- **Auto-generate** a cryptographically secure 32-character hex salt using Python's `secrets` module
- Output displays Algorithm, Salt, and Hash together for easy storage and future verification

> ⚠️ Note: Encoding is **not** encryption — it provides no confidentiality.

---

### 🔄 Tab 4 — Data Encoding / Decoding

| Method | Purpose | Example Use |
|--------|---------|-------------|
| **Base64** | Binary-to-text safe format | APIs, file attachments, email |
| **Hex** | Human-readable byte representation | Debugging, inspecting raw data |
| **URL** | Escape special characters for web | Form data, query strings |

All three methods are fully reversible and support both encode and decode operations.

---

## ⚙️ Setup & Installation

### Prerequisites
- Python 3.8+

### Install Dependencies

```bash
pip install customtkinter pycryptodome pyperclip
```

### Run the Application

```bash
python crypto_toolkit.py
```

---

## 🏗️ Code Architecture

```
UltimateCryptoToolkit (ctk.CTk)
│
├── Utilities
│   ├── make_key(raw, size)          # Pad/truncate key to required length
│   └── copy_val(widget)             # Copy output to clipboard
│
├── Symmetric Tab
│   ├── setup_symmetric()            # Build UI
│   ├── toggle_sym_key()             # Show/hide key field
│   └── process_sym(mode)            # Encrypt/decrypt with AES/DES/3DES
│
├── RSA Tab
│   ├── setup_asymmetric()           # Build UI
│   ├── gen_rsa()                    # Generate 2048-bit key pair
│   ├── save_rsa_keys()              # Export keys to .pem file
│   ├── load_rsa_keys()              # Import keys from .pem file
│   ├── rsa_enc()                    # Hybrid encrypt (AES-GCM + RSA)
│   └── rsa_dec()                    # Hybrid decrypt
│
├── Hashing Tab
│   ├── setup_hashing()              # Build UI
│   ├── toggle_h_salt()              # Show/hide salt field
│   ├── generate_random_salt()       # Generate secure random salt
│   └── run_hash()                   # Compute SHA-256/SHA-512
│
└── Encoding Tab
    ├── setup_encoding()             # Build UI
    ├── encode()                     # Base64 / Hex / URL encode
    └── decode()                     # Base64 / Hex / URL decode
```

---

## 🔑 Key Design Decisions

- **AES-GCM over CBC**: provides both confidentiality *and* integrity (authenticated encryption) — tampering with the ciphertext causes decryption to fail
- **Hybrid RSA**: RSA alone cannot encrypt large data (limited by key size), so AES handles the data while RSA protects the AES key
- **Salted hashing**: identical inputs produce different hashes, defeating rainbow table attacks
- **`secrets` for salt generation**: cryptographically secure — suitable for security-sensitive applications
- **`make_key()` helper**: ensures keys always match algorithm requirements regardless of user input length

---

## 📝 Notes

- DES is included for **educational purposes only** — its 56-bit key is considered cryptographically broken
- 3DES is deprecated by NIST (2023) — prefer AES for any production use
- RSA keys are stored in-memory during the session; use Save/Load for persistence across runs
- The `pyperclip` library is used for clipboard access with a Tkinter fallback if unavailable
