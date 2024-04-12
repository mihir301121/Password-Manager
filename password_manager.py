from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
import random
import string
import json
import os
import base64
import re

# Constants
MASTER_PASSWORD_FILE = "master_password.txt"
PASSWORD_FILE = "passwords.json"
SALT_SIZE = 16
MASTER_PASSWORD_ITERATIONS = 100000

def generate_salt(size=SALT_SIZE):
    # Generate a random salt for key derivation
    return os.urandom(size)

def generate_encryption_key(master_password, salt):
    # Derive a key from the master password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=MASTER_PASSWORD_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())

def encrypt_password(password, key):
    # Encrypt a password using the key
    f = Fernet(key)
    return f.encrypt(password.encode())

def decrypt_password(encrypted_password, key):
    # Decrypt an encrypted password using the key
    f = Fernet(key)
    return f.decrypt(encrypted_password).decode()

def generate_random_password(length=12):
    # Generate a random password of specified length
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

def save_passwords(passwords, key):
    # Save encrypted passwords to a file
    try:
        with open(PASSWORD_FILE, 'w') as f:
            encrypted_passwords = {website: encrypt_password(password, key) for website, password in passwords.items()}
            json.dump(encrypted_passwords, f)
    except Exception as e:
        print("Error saving passwords:", e)

def load_passwords(key):
    # Load encrypted passwords from a file and decrypt them
    try:
        if not os.path.exists(PASSWORD_FILE):
            return {}
        with open(PASSWORD_FILE, 'r') as f:
            encrypted_passwords = json.load(f)
            return {website: decrypt_password(encrypted_password, key) for website, encrypted_password in encrypted_passwords.items()}
    except Exception as e:
        print("Error loading passwords:", e)
        return {}

def main():
    # Main function to manage the password manager
    if not os.path.exists(MASTER_PASSWORD_FILE):
        # Create a new master password if it doesn't exist
        print("Creating a new master password.")
        while True:
            master_password = getpass.getpass("Enter your new master password (at least 8 characters, with one uppercase, one lowercase, one digit, and one special character): ")
            if re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", master_password):
                break
            else:
                print("Password does not meet the requirements. Please try again.")
        salt = generate_salt()
        key = generate_encryption_key(master_password, salt)
        with open(MASTER_PASSWORD_FILE, 'w') as f:
            f.write(base64.urlsafe_b64encode(salt).decode())
    else:
        # Load the master password if it exists
        while True:
            master_password = getpass.getpass("Enter your master password: ")
            with open(MASTER_PASSWORD_FILE, 'r') as f:
                salt = base64.urlsafe_b64decode(f.read())
            key = generate_encryption_key(master_password, salt)
            try:
                _ = load_passwords(key)
                break
            except:
                print("Incorrect master password. Please try again.")
    
    print("Welcome to the Password Manager!")
    while True:
        # Display options for the user
        print("\nOptions:")
        print("1. View Passwords")
        print("2. Add Password")
        print("3. Generate Random Password")
        print("4. Exit")
        choice = input("Enter your choice: ")
        
        if choice == '1':
            # View saved passwords
            passwords = load_passwords(key)
            if passwords:
                print("\nYour passwords:")
                for website, password in passwords.items():
                    print(f"{website}: {password}")
            else:
                print("No passwords saved.")
        elif choice == '2':
            # Add a new password
            website = input("Enter the website: ")
            password = getpass.getpass("Enter the password: ")
            passwords = load_passwords(key)
            passwords[website] = password
            save_passwords(passwords, key)
            print("Password saved.")
        elif choice == '3':
            # Generate a random password
            password = generate_random_password()
            print(f"Generated password: {password}")
        elif choice == '4':
            # Exit the program
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
