import hashlib
import os

# user_credentials = {
#    'username': {'salt': 'hex_salt', 'hash': 'hex_hash'}
# }
user_credentials = {}

# Parameters for PBKDF2
HASH_ITERATIONS = 100000 
SALT_SIZE = 16 # 16 octets (bytes) of salt

def hash_password(password, salt=None):
    """"
    Hashes the password using PBKDF2-SHA256. 
    Generates a new salt if one is not provided.
    """
    # Generation of a new salt if not provided
    if salt is None:
        salt = os.urandom(SALT_SIZE) # 16 random bytes
    
    password_bytes = password.encode('utf-8')

    # 2. Application of algorithme PBKDF2
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',           # Algorithm of slowing hashing
        password_bytes,     # Password in bytes
        salt,               # salt in bytes
        HASH_ITERATIONS     # number of iterations
    )
    
    # 3. Return salt and hashed password in hexadecimal format
    return salt.hex(), hashed_password.hex()

def register_user():
    """Handles the user registration process, storing salt and hash."""
    username = input("Enter your username: ")

    if username in user_credentials:
        print("Username already exists. Please choose a different username.")
    else:
        password = input("Enter your password: ")
        
        # hashing the password with a new salt
        salt_hex, hash_hex = hash_password(password)
        
        # storing the salt and hash
        user_credentials[username] = {
            'salt': salt_hex,
            'hash': hash_hex
        }
        print("Registration successful (Password secured with Salting and PBKDF2).")

def login_user():
    """Handles the user login process using the stored salt."""
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    if username in user_credentials:
        # recuperation of the stored salt and hash
        stored_salt_hex = user_credentials[username]['salt']
        stored_hash_hex = user_credentials[username]['hash']

        # convert the stored salt from hex to bytes
        stored_salt_bytes = bytes.fromhex(stored_salt_hex)

        # hashing the entered password with the stored salt
        _, entered_hash_hex = hash_password(password, stored_salt_bytes)
        
        # comparison of the hashes
        if stored_hash_hex == entered_hash_hex:
            print("Welcome back! Login successful.")
        else:
            print("Invalid username or password. Please try again.")
    else:
        print("Invalid username or password. Please try again.")
    
# Main menu
def authentification_system():
    while True:
        print("\nBasic Authentification System")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        option = input("Enter your choice: ")

        if option == '1':
            register_user()
        elif option == '2':
            login_user()
        elif option == '3':
            print("Exiting the system")
            break
        else:
            print("Invalid choice. Please choose from option 1, 2 or 3")

if __name__ == "__main__":
    authentification_system()