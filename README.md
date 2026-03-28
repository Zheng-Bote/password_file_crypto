# File Encryption Tool (C++23 + libsodium)

encrypts and decrypts files using a password with Argon2id

---

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [Description](#description)
- [Features](#features)
- [Project Structure](#project-structure)
- [Building the Project](#building-the-project)
- [Usage](#usage)
  - [Encrypt a file](#encrypt-a-file)
  - [Decrypt a file](#decrypt-a-file)
- [Encryption Format](#encryption-format)
- [Security Notes](#security-notes)
- [📄 License](#-license)
- [🤝 Authors](#-authors)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

---

## Description

A lightweight command‑line application for Linux that encrypts and decrypts files using a password. The project uses Argon2id for key derivation and XSalsa20‑Poly1305 for authenticated encryption via crypto_secretbox_easy. All cryptographic components are provided by libsodium, which is automatically built and bundled through CMake.

The encrypted file format is:

```Code
SALT (16 bytes) + NONCE (24 bytes) + CIPHERTEXT
```

This layout ensures that each encrypted file is self‑contained and can be decrypted without external metadata.

## Features

- Modern C++23 codebase
- Password‑based key derivation using Argon2id
- Authenticated symmetric encryption using crypto_secretbox_easy
- Sef‑contained file format with embedded salt and nonce
- Fully automated libsodium build via CMake
- No system‑wide dependencies required

## Project Structure

```Code
project/
│
├── CMakeLists.txt
└── src/
└── main.cpp
```

The root CMakeLists.txt fetches libsodium from GitHub, builds it using Autotools, and links it statically into the final executable.

## Building the Project

The build process is fully automated and works on any Linux system with a C++23 compiler and CMake installed.

```bash
mkdir -p build
cd build
cmake ..
cmake --build . -j"$(nproc)"
```

After compilation, the executable password_file_crypto will be available in the build directory.

## Usage

The application supports two modes: encrypt and decrypt.

### Encrypt a file

```bash
./password_file_crypto encrypt <input> <output> <password>
```

**Example**:

```bash
./password_file_crypto encrypt plain.txt secret.bin "myPassword123"
```

### Decrypt a file

```bash
./password_file_crypto decrypt <input> <output> <password>
```

**Example**:

```bash
./password_file_crypto decrypt secret.bin recovered.txt "myPassword123"
```

If the password is incorrect or the file is corrupted, decryption will fail with an error message.

## Encryption Format

Each encrypted file contains all necessary metadata:

| Component  | Size     | Purpose                             |
| ---------- | -------- | ----------------------------------- |
| Salt       | 16 bytes | Used for Argon2id key derivation    |
| Nonce      | 24 bytes | Required for crypto_secretbox_easy  |
| Ciphertext | variable | Encrypted data + authentication tag |

This structure ensures that files remain portable and self‑describing.

## Security Notes

- Argon2id is used with interactive‑grade parameters for strong password‑based key derivation.
- Keys are wiped from memory using sodium_memzero after use.
- Encryption is authenticated; tampering with ciphertext results in decryption failure.
- Always use strong, unique passwords for best security.

## 📄 License

This project is licensed under the **MIT** License.

Copyright (c) 2026 ZHENG Robert

## 🤝 Authors

- [![Zheng Robert - Core Development](https://img.shields.io/badge/Github-Zheng_Robert-black?logo=github)](https://www.github.com/Zheng-Bote)

---

:vulcan_salute:
