import hashlib
import random
from Crypto.Util.number import getPrime, inverse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# === RSA Setup ===

# def mod_inverse(a, m):
#     """Computes the modular inverse of a mod m using the Extended Euclidean Algorithm."""
#     m0, x0, x1 = m, 0, 1
#     while a > 1:
#         q = a // m  # Quotient
#         m, a = a % m, m  # Update m and a (Euclidean step)
#         x0, x1 = x1 - q * x0, x0  # Update x values

#     # Ensure x1 is positive
#     if x1 < 0:
#         x1 += m0

#     return x1 if m == 1 else None  # Return None if modular inverse does not exist

def generate_rsa_keys(bits=512):
    """Generates RSA public and private keys."""
    p, q = getPrime(bits), getPrime(bits)
    n, phi = p * q, (p - 1) * (q - 1)
    e = 65537
    d = inverse(e, phi)
    return (e, n), (d, n)


def rsa_encrypt(m, public_key):
    """RSA encryption."""
    e, n = public_key
    return pow(m, e, n)

def rsa_decrypt(c, private_key):
    """RSA decryption."""
    d, n = private_key
    return pow(c, d, n)

# === AES Encryption ===
def aes_encrypt(message, key):
    """Encrypts a message using AES-CBC."""
    cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00' * 16)
    return cipher.encrypt(pad(message.encode(), AES.block_size))

def aes_decrypt(ciphertext, key):
    """Decrypts an AES-CBC message."""
    cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00' * 16)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

# === Simulated Attack ===
# Bob generates RSA keys
public_key, private_key = generate_rsa_keys()
e, n = public_key
d, _ = private_key

# Bob's symmetric key s
s = random.randint(2, n - 1)

# Bob encrypts s using RSA
c = rsa_encrypt(s, public_key)  # c = s^e mod n

# Mallory intercepts and modifies the ciphertext
x = 3  # random multiplier
c_prime = (c * pow(x, e, n)) % n  # Modified ciphertext

# Alice decrypts c_prime
s_prime = rsa_decrypt(c_prime, private_key)  # Alice unknowingly decrypts s' = s * x mod n

# Mallory recovers s
x_inv = inverse(x, n)  # Compute modular inverse of x mod n
s_mallory = (s_prime * x_inv) % n  # Recover original s

# Mallory derives the AES key
k_mallory = hashlib.sha256(s_mallory.to_bytes((s_mallory.bit_length() + 7) // 8, 'big')).digest()

# Alice encrypts a message using the derived key
message = "Secret Message for Bob"
c0 = aes_encrypt(message, k_mallory)

# Mallory can decrypt this message!
decrypted_message = aes_decrypt(c0, k_mallory)

# === Results ===
print(f"Bob's original symmetric key (s): {s}")
print(f"Mallory's chosen x: {x}")
print(f"Mallory's modified ciphertext (c'): {c_prime}")
print(f"Alice's decrypted manipulated key (s'): {s_prime}")
print(f"Mallory extracts s: {s_mallory} (should match Bob's s)")
print(f"Decrypted Message by Mallory: {decrypted_message}")  # matches original message!
