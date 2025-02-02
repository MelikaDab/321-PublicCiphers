from Crypto.Util.number import getPrime, inverse


def extended_gcd(a, b):
    """ computes the gcd
     using the extended euclidian algorithm """
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0  # Returns gcd, x, y where ax + by = gcd(a, b)

def modular_inverse(e, phi):
    """ computes the modular inverse d 
    such that (e * d) % phi == 1 """
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("e and phi(n) are not coprime, modular inverse doesn't exist.")
    return x % phi  # ensure d is positive

def generate_keys(bits=2048):
    # generate two large primes, p and q
    p = getPrime(bits)
    q = getPrime(bits)

    # compute n and phi(n)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537  # Standard choice

    # compute d (private exponent)
    d = inverse(e, phi)  # Modular multiplicative inverse

    # public and private keys
    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key

def encrypt(message, public_key):
    e, n = public_key
    # convert message to an integer
    m = int.from_bytes(message.encode('utf-8'), byteorder='big')
    # ensure m is less than n
    if m >= n:
        raise ValueError("Message too large for encryption")
    # encrypt: c = m^e mod n
    c = pow(m, e, n)
    return c

def decrypt(ciphertext, private_key):
    d, n = private_key
    # decrypt: m = c^d mod n
    m = pow(ciphertext, d, n)
    # convert integer back to a string
    message = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big').decode('utf-8')
    return message

if __name__ == "__main__":
    public_key, private_key = generate_keys(bits=512) 

    plaintext = "Hello World!"

    ciphertext = encrypt(plaintext, public_key)
    print(f"Ciphertext: {ciphertext}")

    decrypted_message = decrypt(ciphertext, private_key)
    print(f"Decrypted Message: {decrypted_message}")
