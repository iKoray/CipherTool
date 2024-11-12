import os
import base64
import hashlib
import subprocess

def calculate_sha256(file_path):
    # Get a unique "fingerprint" of the file's contents with SHA-256
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()
            sha256_hash = hashlib.sha256(file_data).hexdigest()
            print(f"SHA-256 Hash of '{file_path}': {sha256_hash}")
            return sha256_hash
    except Exception as e:
        print(f"Error calculating SHA-256: {e}")
        return None

def base64_encode(input_file, base64_file):
    # Convert the file to Base64 to make it easier to work with during encryption
    with open(input_file, "rb") as f_in, open(base64_file, "wb") as f_out:
        base64_data = base64.b64encode(f_in.read())
        f_out.write(base64_data)
    print(f"File '{input_file}' encoded to Base64 as '{base64_file}'")

def base64_decode(base64_file, output_file):
    # Convert the Base64 file back to its original form
    with open(base64_file, "rb") as f_in, open(output_file, "wb") as f_out:
        binary_data = base64.b64decode(f_in.read())
        f_out.write(binary_data)
    print(f"Base64 decoded file '{base64_file}' to '{output_file}'")

def encrypt_file(input_file, encrypted_file, aes_key):
    # First, convert the file to Base64, then encrypt it with AES
    base64_file = f"{input_file}_base64"
    base64_encode(input_file, base64_file)
    
    try:
        command = [
            'openssl', 'enc', '-aes-256-cbc', '-salt', '-pbkdf2',
            '-in', base64_file, '-out', encrypted_file,
            '-k', aes_key
        ]
        subprocess.run(command, check=True)
        print(f"File '{base64_file}' encrypted successfully as '{encrypted_file}'")
    except Exception as e:
        print(f"Error encrypting file: {e}")
    finally:
        os.remove(base64_file)  # Clean up the temporary Base64 file once we're done

def decrypt_file(encrypted_file, decrypted_file, aes_key):
    # Decrypt the AES-encrypted file and then decode it from Base64
    decrypted_base64_file = f"{decrypted_file}_base64"
    try:
        decrypt_command = [
            'openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2',
            '-in', encrypted_file, '-out', decrypted_base64_file,
            '-k', aes_key
        ]
        subprocess.run(decrypt_command, check=True)
        print(f"File '{encrypted_file}' decrypted successfully as '{decrypted_base64_file}'")

        # Now that we have the Base64 version, decode it back to the original format
        base64_decode(decrypted_base64_file, decrypted_file)
    except Exception as e:
        print(f"Error decrypting file: {e}")
    finally:
        os.remove(decrypted_base64_file)  # Clean up the temporary Base64 file once we're done

def main():
    while True:
        print("\nSHA-256 Hashing & AES-256 Encryption/Decryption Tool")
        print("1. Encrypt a file (includes SHA-256 hashing and AES-256 encryption)")
        print("2. Decrypt a file (includes AES-256 decryption and SHA-256 hash check)")
        print("3. Exit")

        choice = input("Select an option (1/2/3): ").strip()

        if choice == "1":
            file_path = input("Enter the path of the file you want to encrypt: ").strip()
            if not os.path.exists(file_path):
                print("File not found! Please enter a valid file path.")
                continue

            # Step 1: Generate and display the hash of the original file
            original_hash = calculate_sha256(file_path)

            # Get the encryption key from the user (optional: require 32 characters)
            aes_key = input("Enter the AES key for encryption: ").strip()
            # To enforce a 32-character key, uncomment the following lines:
            # if len(aes_key) != 32:
            #     print("Key must be exactly 32 characters for AES-256.")
            #     continue

            # Step 2: Convert the file to Base64 and encrypt it
            encrypted_file = f"{os.path.splitext(file_path)[0]}_encrypted.txt"
            encrypt_file(file_path, encrypted_file, aes_key)

            print(f"Original SHA-256 Hash: {original_hash}")

        elif choice == "2":
            encrypted_file = input("Enter the path of the file you want to decrypt: ").strip()
            if not os.path.exists(encrypted_file):
                print("File not found! Please enter a valid file path.")
                continue

            # Get the decryption key from the user (optional: require 32 characters)
            aes_key = input("Enter the AES key for decryption: ").strip()
            # AES-256 technically requires a 256-bit (32-byte) key for full security.
            # To enforce a 32-character key for full security, uncomment the following lines:
            # if len(aes_key) != 32:
            #     print("Key must be exactly 32 characters for AES-256.")
            #     continue

            # Step 3: Decrypt the file and decode it from Base64
            decrypted_file = f"{os.path.splitext(encrypted_file)[0]}_decrypted.txt"
            decrypt_file(encrypted_file, decrypted_file, aes_key)

            # Step 4: Generate and compare the hash of the decrypted file
            decrypted_hash = calculate_sha256(decrypted_file)
            print(f"Decrypted SHA-256 Hash: {decrypted_hash}")

            # Compare the original and decrypted hashes to ensure they match
            if original_hash == decrypted_hash:
                print("Integrity check passed: The decrypted file matches the original.")
            else:
                print("Warning: Integrity check failed. The decrypted file does not match the original.")

        elif choice == "3":
            print("Exiting the tool.")
            break
        else:
            print("Invalid choice. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()
