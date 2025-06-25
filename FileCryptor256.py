import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import secrets

# Constants
KEY_SIZE = 32  # AES-256
IV_SIZE = 16   # For AES CBC
SALT_SIZE = 16
ITERATIONS = 100_000

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a secure AES-256 key from a password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        plaintext = f.read()

    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    iv = secrets.token_bytes(IV_SIZE)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad plaintext to block size (16 bytes)
    padding_length = 16 - len(plaintext) % 16
    plaintext += bytes([padding_length]) * padding_length

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    encrypted_data = salt + iv + ciphertext
    with open(filepath + '.enc', 'wb') as f:
        f.write(encrypted_data)

    return filepath + '.enc'

def decrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        data = f.read()

    salt = data[:SALT_SIZE]
    iv = data[SALT_SIZE:SALT_SIZE + IV_SIZE]
    ciphertext = data[SALT_SIZE + IV_SIZE:]

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    padding_length = plaintext_padded[-1]
    plaintext = plaintext_padded[:-padding_length]

    out_path = filepath.replace('.enc', '.dec')
    with open(out_path, 'wb') as f:
        f.write(plaintext)

    return out_path

# GUI
def encrypt_action():
    filepath = filedialog.askopenfilename()
    if not filepath:
        return
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return
    try:
        out_path = encrypt_file(filepath, password)
        messagebox.showinfo("Success", f"File encrypted: {out_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_action():
    filepath = filedialog.askopenfilename()
    if not filepath or not filepath.endswith('.enc'):
        messagebox.showerror("Error", "Please select a .enc file.")
        return
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return
    try:
        out_path = decrypt_file(filepath, password)
        messagebox.showinfo("Success", f"File decrypted: {out_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI Setup
root = tk.Tk()
root.title("AES-256 File Encryptor")

tk.Label(root, text="Enter Password:").pack(pady=5)
password_entry = tk.Entry(root, show="*", width=40)
password_entry.pack(pady=5)

tk.Button(root, text="Encrypt File", command=encrypt_action, width=30).pack(pady=10)
tk.Button(root, text="Decrypt File", command=decrypt_action, width=30).pack(pady=10)

root.mainloop()

OUTPUT:

Meeting Notes - Project Athena
Date: 2025-06-20

- Discussed backend API integration timelines.
- UI/UX team will deliver Figma mockups by June 28.
- Initial testing of login module completed.
- Next meeting scheduled for June 27 at 10:00 AM.


