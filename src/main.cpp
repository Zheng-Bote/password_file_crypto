/**
 * SPDX-FileComment: Entry point and core logic for password-based file encryption/decryption using libsodium
 * SPDX-FileType: SOURCE
 * SPDX-FileContributor: ZHENG Robert
 * SPDX-FileCopyrightText: 2026 ZHENG Robert
 * SPDX-License-Identifier: Apache-2.0
 *
 * @file main.cpp
 * @brief Main file for cryptographic file operations using libsodium
 * @version 1.2.0
 * @date 2026-05-13
 *
 * @author ZHENG Robert (robert@hase-zheng.net)
 * @copyright Copyright (c) 2026 ZHENG Robert
 *
 * @license Apache-2.0
 */

#include <sodium.h>
#include <rz_config.hpp>
#include <check_gh-update.hpp>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <string_view>

/**
 * @namespace
 * @brief Anonymous namespace containing utility functions for file IO and cryptography
 */
namespace {

/**
 * @brief Prints the short version string (vX.Y.Z).
 */
void print_short_version() {
    std::cout << "v" << rz::config::VERSION << std::endl;
}

/**
 * @brief Prints the full version information.
 */
void print_full_version() {
    std::cout << "Name:        " << rz::config::PROJECT_NAME << "\n"
              << "Version:     " << rz::config::VERSION << "\n"
              << "Description: " << rz::config::PROJECT_DESCRIPTION << "\n"
              << "URL:         " << rz::config::PROJECT_HOMEPAGE_URL << std::endl;
}

/**
 * @brief Checks for updates on GitHub.
 */
void check_update() {
    try {
        auto result = ghupdate::check_github_update(
            std::string(rz::config::PROJECT_HOMEPAGE_URL),
            std::string(rz::config::VERSION)
        );
        if (result.hasUpdate) {
            std::cout << "A new version is available: " << result.latestVersion << "\n"
                      << "Download it from: " << rz::config::PROJECT_HOMEPAGE_URL << "/releases" << std::endl;
        } else {
            std::cout << "You are using the latest version." << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error checking for updates: " << e.what() << std::endl;
    }
}

/**
 * @brief Reads the entire contents of a file into a byte vector.
 *
 * @param path The path to the file to be read.
 * @param data The vector where the file's binary data will be stored.
 * @return bool True if the file was read successfully, false otherwise.
 */
bool read_file(const std::string& path, std::vector<std::uint8_t>& data) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    ifs.seekg(0, std::ios::end);
    std::streamsize size = ifs.tellg();
    if (size < 0) return false;
    ifs.seekg(0, std::ios::beg);
    data.resize(static_cast<std::size_t>(size));
    if (!data.empty() && !ifs.read(reinterpret_cast<char*>(data.data()), size)) {
        return false;
    }
    return true;
}

/**
 * @brief Writes the given binary data into a file.
 *
 * @param path The path to the file to write to.
 * @param data The vector containing binary data to be written.
 * @return bool True if the write operation was successful, false otherwise.
 */
bool write_file(const std::string& path, const std::vector<std::uint8_t>& data) {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs) return false;
    if (!data.empty()) {
        ofs.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
        if (!ofs) return false;
    }
    return true;
}

/**
 * @brief Derives a cryptographic key from a password using Argon2id.
 *
 * @param password The user-provided password from which the key will be derived.
 * @param salt An array of salt bytes.
 * @param key An array where the derived key will be stored.
 * @return bool True if the key was derived successfully, false otherwise.
 */
bool derive_key_from_password(const std::string& password,
                              const std::uint8_t salt[crypto_pwhash_SALTBYTES],
                              std::uint8_t key[crypto_secretbox_KEYBYTES]) {
    if (crypto_pwhash(key, crypto_secretbox_KEYBYTES,
                      password.c_str(), password.size(),
                      salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return false;
    }
    return true;
}

/**
 * @brief Encrypts a file using a password-derived key.
 *
 * Reads the content of an input file, derives a key from the provided password
 * and a randomly generated salt, encrypts the data using symmetric encryption 
 * (libsodium secretbox), and writes the salt, nonce, and ciphertext to the output file.
 *
 * @param in_path The path to the plaintext input file.
 * @param out_path The path to the destination encrypted file.
 * @param password The password used to derive the encryption key.
 * @return bool True if the encryption and writing process is successful, false otherwise.
 */
bool encrypt_file(const std::string& in_path,
                  const std::string& out_path,
                  const std::string& password) {
    std::vector<std::uint8_t> plaintext;
    if (!read_file(in_path, plaintext)) {
        std::cerr << "Fehler beim Lesen der Eingabedatei\n";
        return false;
    }

    std::uint8_t salt[crypto_pwhash_SALTBYTES];
    std::uint8_t nonce[crypto_secretbox_NONCEBYTES];
    std::uint8_t key[crypto_secretbox_KEYBYTES];

    randombytes_buf(salt, sizeof salt);
    randombytes_buf(nonce, sizeof nonce);

    if (!derive_key_from_password(password, salt, key)) {
        std::cerr << "Key-Derivation fehlgeschlagen\n";
        return false;
    }

    std::vector<std::uint8_t> ciphertext(
        plaintext.size() + crypto_secretbox_MACBYTES);

    if (crypto_secretbox_easy(ciphertext.data(),
                              plaintext.data(), plaintext.size(),
                              nonce, key) != 0) {
        std::cerr << "Verschlüsselung fehlgeschlagen\n";
        return false;
    }

    std::vector<std::uint8_t> out;
    out.reserve(crypto_pwhash_SALTBYTES +
                crypto_secretbox_NONCEBYTES +
                ciphertext.size());

    // Format: SALT(16) + NONCE(24) + CIPHERTEXT
    out.insert(out.end(), salt, salt + crypto_pwhash_SALTBYTES);
    out.insert(out.end(), nonce, nonce + crypto_secretbox_NONCEBYTES);
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());

    if (!write_file(out_path, out)) {
        std::cerr << "Fehler beim Schreiben der Ausgabedatei\n";
        return false;
    }

    sodium_memzero(key, sizeof key);
    return true;
}

/**
 * @brief Decrypts an encrypted file using the provided password.
 *
 * Reads the salt, nonce, and ciphertext from the input file, derives the original
 * key from the given password and salt, decrypts the ciphertext, and writes the
 * plaintext to the output file.
 *
 * @param in_path The path to the encrypted input file.
 * @param out_path The path to the destination plaintext file.
 * @param password The password used to derive the decryption key.
 * @return bool True if decryption and writing was successful, false if it failed 
 *         (e.g., wrong password, corrupted file, or IO errors).
 */
bool decrypt_file(const std::string& in_path,
                  const std::string& out_path,
                  const std::string& password) {
    std::vector<std::uint8_t> in;
    if (!read_file(in_path, in)) {
        std::cerr << "Fehler beim Lesen der Eingabedatei\n";
        return false;
    }

    const std::size_t header_size =
        crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES;

    if (in.size() < header_size + crypto_secretbox_MACBYTES) {
        std::cerr << "Datei zu klein oder beschädigt\n";
        return false;
    }

    const std::uint8_t* salt = in.data();
    const std::uint8_t* nonce = in.data() + crypto_pwhash_SALTBYTES;
    const std::uint8_t* cipher = in.data() + header_size;
    const std::size_t cipher_len = in.size() - header_size;

    std::uint8_t key[crypto_secretbox_KEYBYTES];
    if (!derive_key_from_password(password, salt, key)) {
        std::cerr << "Key-Derivation fehlgeschlagen\n";
        return false;
    }

    std::vector<std::uint8_t> plaintext(
        cipher_len - crypto_secretbox_MACBYTES);

    if (crypto_secretbox_open_easy(plaintext.data(),
                                   cipher, cipher_len,
                                   nonce, key) != 0) {
        std::cerr << "Entschlüsselung fehlgeschlagen (falsches Passwort oder beschädigte Datei)\n";
        return false;
    }

    if (!write_file(out_path, plaintext)) {
        std::cerr << "Fehler beim Schreiben der Ausgabedatei\n";
        return false;
    }

    sodium_memzero(key, sizeof key);
    return true;
}

} // namespace

/**
 * @brief Main entry point of the application.
 *
 * Handles initialization of libsodium and parsing of command-line arguments.
 * Dispatches to either the encrypt_file or decrypt_file function based on user input.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of string representations of command-line arguments.
 * @return int 0 on success, 1 on failure.
 */
int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
        std::cerr << "libsodium konnte nicht initialisiert werden\n";
        return 1;
    }

    if (argc < 2) {
        std::cerr << "Usage:\n"
                  << "  " << argv[0] << " encrypt <input> <output> <password>\n"
                  << "  " << argv[0] << " decrypt <input> <output> <password>\n"
                  << "  " << argv[0] << " -v\n"
                  << "  " << argv[0] << " --version\n"
                  << "  " << argv[0] << " --check-update\n";
        return 1;
    }

    std::string_view first_arg = argv[1];

    if (first_arg == "-v") {
        print_short_version();
        return 0;
    }

    if (first_arg == "--version") {
        print_full_version();
        return 0;
    }

    if (first_arg == "--check-update") {
        check_update();
        return 0;
    }

    if (argc != 5) {
        std::cerr << "Ungültige Anzahl an Argumenten für " << first_arg << "\n";
        return 1;
    }

    std::string in_path  = argv[2];
    std::string out_path = argv[3];
    std::string password = argv[4];

    bool ok = false;
    if (first_arg == "encrypt") {
        ok = encrypt_file(in_path, out_path, password);
    } else if (first_arg == "decrypt") {
        ok = decrypt_file(in_path, out_path, password);
    } else {
        std::cerr << "Unbekannter Modus: " << first_arg << "\n";
        return 1;
    }

    return ok ? 0 : 1;
}
