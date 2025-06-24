import os
import time
import argparse
import getpass
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet
from tqdm import tqdm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


# === Key Derivation ===
def derive_key(password: str, salt: bytes = b'static_salt') -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))


# === Estimate Time ===
def estimate_time(size_bytes: int) -> float:
    return round(size_bytes / (10 * 1024 * 1024), 2)  # ~10MB/s


# === Encrypt File ===
def encrypt_file(filepath: str, password: str):
    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"\n[+] Estimating encryption time...")
    est_time = estimate_time(len(data))
    print(f"[+] Estimated time: ~{est_time} seconds")

    confirm = input("[?] Continue with encryption? (y/n): ").strip().lower()
    if confirm != 'y':
        print("[-] Cancelled.")
        return

    key = derive_key(password)
    fernet = Fernet(key)

    print("[*] Encrypting...")
    encrypted_data = fernet.encrypt(data)

    output_path = filepath + ".afx"
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)

    print(f"[✓] Encrypted file saved as: {output_path}")


# === Decrypt File ===
def decrypt_file(filepath: str, password: str):
    if not filepath.endswith('.afx'):
        print("[-] Error: Only .afx files can be decrypted.")
        return

    with open(filepath, 'rb') as f:
        encrypted_data = f.read()

    print(f"\n[+] Estimating decryption time...")
    est_time = estimate_time(len(encrypted_data))
    print(f"[+] Estimated time: ~{est_time} seconds")

    confirm = input("[?] Continue with decryption? (y/n): ").strip().lower()
    if confirm != 'y':
        print("[-] Cancelled.")
        return

    key = derive_key(password)
    fernet = Fernet(key)

    print("[*] Decrypting...")
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception:
        print("[-] Failed to decrypt. Wrong password or corrupted file.")
        return

    output_path = filepath.replace('.afx', '')
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

    print(f"[✓] Decrypted file saved as: {output_path}")


# === Main Entry ===
def main():
    parser = argparse.ArgumentParser(description="🔐 SecureFileX - AES-256 CLI File Encryptor/Decryptor")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Choose encrypt or decrypt")
    parser.add_argument("file", help="Path to the file")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print("[-] File not found.")
        return

    password = getpass.getpass("Enter password: ")
    if args.mode == "encrypt":
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("[-] Passwords do not match.")
            return
        encrypt_file(args.file, password)
    else:
        decrypt_file(args.file, password)


if __name__ == "__main__":
    main()
