from flask import redirect, session
from functools import wraps
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import hashlib
import requests

def check_password_breach(password):
    # Hash the password with SHA-1
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]
    
    # Make a request to the HIBP API
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    
    if response.status_code != 200:
        raise RuntimeError("Error checking HIBP API")
    
    # Check if the suffix is in the response data
    hashes = (line.split(":") for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return True  # Password has been breached
    
    return False  # Password is safe

def check_email_breach(email):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "hibp-api-key": "b50c24b80762423092dd1088f9c919d7",  # Replace this with your actual API key
        "User-Agent": "PasswordManagerApp"  # Replace with your app's name
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return True  # Email has been breached
    elif response.status_code == 404:
        return False  # Email is safe
    elif response.status_code == 429:
        raise RuntimeError("Rate limit exceeded. Try again later.")
    else:
        raise RuntimeError(f"Error checking HIBP API for email: {response.status_code}")


# Generate a 256-bit key (32 bytes) - Store this in an environment variable in production
AES_KEY = os.environ.get("AES_KEY", b'32-byte-long-key-for-256-bit-encryption')
if isinstance(AES_KEY, str):
    AES_KEY = AES_KEY.encode()  # Convert to bytes if it's a string

IV_LENGTH = 16  # AES block size in bytes (128 bits)

# Login required decorator
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return wrap

# Encryption function using AES-256 with a random IV
def encryption(message_to_encrypt):
    # Generate a new IV for each encryption
    iv = os.urandom(IV_LENGTH)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message_to_encrypt.encode()) + encryptor.finalize()
    # Store IV and encrypted message together
    return iv + encrypted_message

# Decryption function
def decryption(encrypted_message):
    # Separate IV and encrypted message
    iv = encrypted_message[:IV_LENGTH]
    encrypted_content = encrypted_message[IV_LENGTH:]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_content) + decryptor.finalize()
    return decrypted_message.decode()

