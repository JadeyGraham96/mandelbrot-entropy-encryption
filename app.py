from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from hashlib import sha256
import numpy as np

# Function to generate RSA key pair
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Function to encrypt AES key with RSA public key
def encrypt_aes_key_with_rsa(aes_key, rsa_public_key):
    rsa_key = RSA.import_key(rsa_public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)
    return enc_aes_key

# Function to decrypt AES key with RSA private key
def decrypt_aes_key_with_rsa(enc_aes_key, rsa_private_key):
    rsa_key = RSA.import_key(rsa_private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)
    return aes_key

# Function to encrypt data with AES
def encrypt_data_with_aes(data, aes_key):
    iv = get_random_bytes(12)  # AES GCM standard IV size is 12 bytes
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    ct_bytes, tag = cipher_aes.encrypt_and_digest(pad(data, AES.block_size))
    hmac = HMAC.new(aes_key, digestmod=SHA256)
    hmac.update(iv + ct_bytes + tag)
    hmac_tag = hmac.digest()
    return iv + ct_bytes + tag + hmac_tag

# Function to decrypt data with AES
def decrypt_data_with_aes(encrypted_data, aes_key):
    try:
        iv = encrypted_data[:12]
        hmac_tag = encrypted_data[-32:]
        encrypted_content = encrypted_data[12:-32]
        
        hmac = HMAC.new(aes_key, digestmod=SHA256)
        hmac.update(iv + encrypted_content)
        hmac.verify(hmac_tag)
        
        ct = encrypted_content[:-16]
        tag = encrypted_content[-16:]
        
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        pt = unpad(cipher_aes.decrypt_and_verify(ct, tag), AES.block_size)
        return pt
    except (ValueError, KeyError, HMAC.HMACError) as e:
        print("Decryption failed:", str(e))
        return None

# Function to save key to a file
def save_key_to_file(key, filename):
    with open(filename, 'wb') as f:
        f.write(key)

# Function to load key from a file
def load_key_from_file(filename):
    with open(filename, 'rb') as f:
        key = f.read()
    return key

# Generate entropy from the Mandelbrot set
def mandelbrot(c, max_iter):
    z = c
    for n in range(max_iter):
        if abs(z) > 2:
            return n
        z = z*z + c
    return max_iter

def generate_entropy_from_mandelbrot(width, height, max_iter):
    re_min, re_max = -2, 1
    im_min, im_max = -1, 1
    entropy = []
    for y in range(height):
        for x in range(width):
            re = re_min + (x / width) * (re_max - re_min)
            im = im_min + (y / height) * (im_max - im_min)
            c = complex(re, im)
            m = mandelbrot(c, max_iter)
            entropy.append(m)
    entropy = np.array(entropy)
    entropy_bytes = entropy.tobytes()
    return sha256(entropy_bytes).digest()

# Generate RSA key pairs for sender and receiver
sender_private_key, sender_public_key = generate_rsa_key_pair()
receiver_private_key, receiver_public_key = generate_rsa_key_pair()

# Save RSA keys to files
save_key_to_file(sender_private_key, 'sender_private_key.pem')
save_key_to_file(sender_public_key, 'sender_public_key.pem')
save_key_to_file(receiver_private_key, 'receiver_private_key.pem')
save_key_to_file(receiver_public_key, 'receiver_public_key.pem')

# Load RSA keys from files
sender_private_key = load_key_from_file('sender_private_key.pem')
sender_public_key = load_key_from_file('sender_public_key.pem')
receiver_private_key = load_key_from_file('receiver_private_key.pem')
receiver_public_key = load_key_from_file('receiver_public_key.pem')

# Data to be encrypted
data = b"Sensitive data that needs encryption"

# Generate AES key
aes_key = get_random_bytes(32)

# Encrypt the AES key with the receiver's RSA public key
enc_aes_key = encrypt_aes_key_with_rsa(aes_key, receiver_public_key)

# Encrypt the data with the AES key
encrypted_data = encrypt_data_with_aes(data, aes_key)
print("Encrypted data:", encrypted_data)

# Decrypt the AES key with the receiver's RSA private key
decrypted_aes_key = decrypt_aes_key_with_rsa(enc_aes_key, receiver_private_key)

# Decrypt the data with the decrypted AES key
decrypted_data = decrypt_data_with_aes(encrypted_data, decrypted_aes_key)
if decrypted_data:
    print("Decrypted data:", decrypted_data.decode())
else:
    print("Failed to decrypt data.")
