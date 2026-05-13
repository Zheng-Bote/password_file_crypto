<div id="top" align="center">
<h1>File Encryption Tool (libsodium)</h1>

<p>encrypts and decrypts files using a password with Argon2id</p>

![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/Zheng-Bote/password_file_crypto?logo=GitHub)](https://github.com/Zheng-Bote/password_file_crypto/releases)
<br/>
[Report Issue](https://github.com/Zheng-Bote/password_file_crypto/issues) · [Request Feature](https://github.com/Zheng-Bote/password_file_crypto/pulls)

</div>

---

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [Description](#description)
- [Features](#features)
- [See also](#see-also)
- [Project Structure](#project-structure)
- [Building the Project](#building-the-project)
  - [Prerequisites](#prerequisites)
  - [Build Steps](#build-steps)
- [Usage](#usage)
  - [Encrypt a file](#encrypt-a-file)
  - [Decrypt a file](#decrypt-a-file)
  - [Version and Update Information](#version-and-update-information)
- [Encryption Format](#encryption-format)
- [Security Notes](#security-notes)
- [📄 License](#-license)
- [🤝 Authors](#-authors)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

---

## Description

![Language](https://img.shields.io/badge/language-C%2B%2B23-00599C.svg)

A lightweight command‑line application for Linux and Windows that encrypts and decrypts files using a password. The project uses Argon2id for key derivation and XSalsa20‑Poly1305 for authenticated encryption via crypto_secretbox_easy. All cryptographic components are provided by libsodium. Dependency management is handled by Conan v2.

The encrypted file format is:

```Code
SALT (16 bytes) + NONCE (24 bytes) + CIPHERTEXT
```

This layout ensures that each encrypted file is self‑contained and can be decrypted without external metadata.

## Features

- Modern C++23 codebase
- Password‑based key derivation using Argon2id
- Authenticated symmetric encryption using crypto_secretbox_easy
- Self‑contained file format with embedded salt and nonce
- Dependency management via **Conan v2**
- Integrated GitHub update checker
- Cross-platform support (Linux, Windows)

## See also

| name                                                                                                         | description                                                    |
| ------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------- |
| [password_file_crypto](https://github.com/Zheng-Bote/password_file_crypto)                                   | password file encryption tool (**Cli version**)                |
| [password_file_crypto_wasm](https://github.com/Zheng-Bote/password_file_crypto_wasm)                         | password file encryption tool (**Wasm version**)               |
| [qt-desktop_file_encryption-decryption](https://github.com/Zheng-Bote/qt-desktop_file_encryption-decryption) | **strong password** file encryption tool (**Desktop version**) |
| [qt-cli_file_encryption-decryption](https://github.com/Zheng-Bote/qt-cli_file_encryption-decryption)         | **strong password** file encryption tool (**Cli version**)     |


## Project Structure

```Code
project/
│
├── CMakeLists.txt
├── conan.txt
├── configure/
│   └── rz_config.hpp.in
└── src/
    └── main.cpp
```

## Building the Project

The build process uses Conan v2 for dependencies and CMake for the build.

### Prerequisites
- Conan 2.x
- CMake 3.23+
- C++23 compliant compiler

### Build Steps

```bash
# 1. Install dependencies
conan install . -f conan.txt --output-folder=build --build=missing

# 2. Configure and build
cmake --preset conan-default
cmake --build --preset conan-release
```

After compilation, the executable `password_file_crypto` will be available in the `build/build/Release` (on Windows) or `build/build` (on Linux) directory.

## Usage

The application supports encryption, decryption, and utility flags.

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

### Version and Update Information

- **Short Version**: `./password_file_crypto -v`
- **Full Version Info**: `./password_file_crypto --version`
- **Check for Updates**: `./password_file_crypto --check-update`

## Encryption Format

Each encrypted file contains all necessary metadata:

| Component  | Size     | Purpose                             |
| ---------- | -------- | ----------------------------------- |
| Salt       | 16 bytes | Used for Argon2id key derivation    |
| Nonce      | 24 bytes | Required for crypto_secretbox_easy  |
| Ciphertext | variable | Encrypted data + authentication tag |

## Security Notes

- Argon2id is used with interactive‑grade parameters for strong password‑based key derivation.
- Keys are wiped from memory using `sodium_memzero` after use.
- Encryption is authenticated; tampering with ciphertext results in decryption failure.
- Always use strong, unique passwords for best security.

## 📄 License

This project is licensed under the **MIT** License.

Copyright (c) 2026 ZHENG Robert

## 🤝 Authors

- [![Zheng Robert - Core Development](https://img.shields.io/badge/Github-Zheng_Robert-black?logo=github)](https://www.github.com/Zheng-Bote)

---

:vulcan_salute:

<p align="right">(<a href="#top">back to top</a>)</p>
