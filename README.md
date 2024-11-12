# AES256-SHA256-Encryptor

This Python script provides a command-line tool for securely encrypting and decrypting files using AES-256 encryption, with SHA-256 hashing for data integrity verification. Currently, the tool supports SHA-256 for hashing and AES-256 for encryption, with plans to expand and incorporate additional encryption algorithms in the future.

## Project Inspiration

This tool was inspired by a class lab I completed on SHA-256 hashing and AES encryption. After learning the basics, I wanted to automate the process and create a tool that could handle encryption and decryption more easily. I built this project with the assistance of AI, which helped guide the structure and implementation. My goal is to expand this project over time to include more cryptographic algorithms and modular functionality.

## Features
- **AES-256 Encryption**: Uses AES-256-CBC for strong encryption, with an option to use `pbkdf2` key derivation for enhanced security.
- **SHA-256 Hashing**: Generates a SHA-256 hash of the original file to verify the integrity of the data after decryption.
- **Base64 Encoding**: Automatically encodes files in Base64 before encryption to ensure compatibility with binary files.
- **Command-Line Interface**: Provides an interactive menu for encrypting and decrypting files.

## Future Plans
Right now, this tool focuses on SHA-256 hashing and AES-256 encryption, but I’d like to expand it over time to support more types of encryption and hashing methods. Eventually, I plan to reorganize the code so each encryption and hashing function is separate, making it easier to manage and scale as new features are added.

## Prerequisites

- **Python 3.x**: Make sure Python is installed on your system.
- **OpenSSL**: This script relies on OpenSSL for encryption and decryption. You can install OpenSSL via `winget` on Windows.

### Installing OpenSSL on Windows
If you’re on Windows, you can install OpenSSL using the following command in PowerShell:

```powershell
# Check winget version (optional, to ensure winget is installed)
winget --version

# Search for available OpenSSL packages
winget search openssl

# Install OpenSSL from Shining Light Productions
winget install -e --id ShiningLight.OpenSSL

# After installation, you can verify the installation by checking the OpenSSL version:
openssl version
