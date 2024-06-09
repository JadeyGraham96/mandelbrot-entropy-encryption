# Mandelbrot Entropy Encryption

Implementing robust encryption with Mandelbrot-set-derived entropy, RSA, and AES.

## Introduction

This repository demonstrates the use of the Mandelbrot set to generate high-entropy cryptographic keys, enhancing the security of encryption algorithms. By leveraging the complexity and unpredictability of the Mandelbrot set, we create a robust encryption framework using RSA and AES.

## Requirements

- Python 3.x
- [pycryptodome](https://pypi.org/project/pycryptodome/)
- [numpy](https://pypi.org/project/numpy/)
- [matplotlib](https://pypi.org/project/matplotlib/)

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/mandelbrot-entropy-encryption.git
    cd mandelbrot-entropy-encryption
    ```

2.a Install the required packages:
 ```
    pip install pycryptodome numpy matplotlib
 ```
2.b Install the required packages:
```
    pip install -r requirements.txt
```

## Usage

### Generating Mandelbrot Entropy

```
from hashlib import sha256
import numpy as np

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
```
### Generating RSA Key Pairs
```
from Crypto.PublicKey import RSA

def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key
```
### Encrypting and Decrypting AES Key with RSA
```
from Crypto.Cipher import PKCS1_OAEP

def encrypt_aes_key_with_rsa(aes_key, rsa_public_key):
    rsa_key = RSA.import_key(rsa_public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)
    return enc_aes_key

def decrypt_aes_key_with_rsa(enc_aes_key, rsa_private_key):
    rsa_key = RSA.import_key(rsa_private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)
    return aes_key
```
### Encrypting and Decrypting Data with AES
```
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

def encrypt_data_with_aes(data, aes_key):
    iv = get_random_bytes(12)  # AES GCM standard IV size is 12 bytes
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    ct_bytes, tag = cipher_aes.encrypt_and_digest(pad(data, AES.block_size))
    hmac = HMAC.new(aes_key, digestmod=SHA256)
    hmac.update(iv + ct_bytes + tag)
    hmac_tag = hmac.digest()
    return iv + ct_bytes + tag + hmac_tag

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
```

## Examples
### Generate RSA key pairs for sender and receiver
```
sender_private_key, sender_public_key = generate_rsa_key_pair()
receiver_private_key, receiver_public_key = generate_rsa_key_pair()
```

### Generate AES key
```
aes_key = get_random_bytes(32)
```

### Encrypt the AES key with the receiver's RSA public key
```
enc_aes_key = encrypt_aes_key_with_rsa(aes_key, receiver_public_key)
```

### Data to be encrypted
```
data = b"Sensitive data that needs encryption"
```

### Encrypt the data with the AES key
```
encrypted_data = encrypt_data_with_aes(data, aes_key)
print("Encrypted data:", encrypted_data)
```

### Decrypt the AES key with the receiver's RSA private key
```
decrypted_aes_key = decrypt_aes_key_with_rsa(enc_aes_key, receiver_private_key)
```

### Decrypt the data with the decrypted AES key
```
decrypted_data = decrypt_data_with_aes(encrypted_data, decrypted_aes_key)
if decrypted_data:
    print("Decrypted data:", decrypted_data.decode())
else:
    print("Failed to decrypt data.")
```
## Visualisations
### Plotting the Mandelbrot Set
```
import matplotlib.pyplot as plt

def plot_mandelbrot(width, height, max_iter):
    re_min, re_max = -2, 1
    im_min, im_max = -1, 1
    image = np.zeros((height, width), dtype=np.uint8)
    for y in range(height):
        for x in range(width):
            re = re_min + (x / width) * (re_max - re_min)
            im = im_min + (y / height) * (im_max - im_min)
            c = complex(re, im)
            m = mandelbrot(c, max_iter)
            color = 255 - int(m * 255 / max_iter)
            image[y, x] = color
    plt.imshow(image, extent=(re_min, re_max, im_min, im_max), cmap='hot')
    plt.colorbar()
    plt.title('Mandelbrot Set')
    plt.show()

plot_mandelbrot(800, 600, 100)
```

## Real-World Applications
- Finance: Enhancing security of financial transactions and customer data.
- Healthcare: Protecting confidential patient records and medical information.
- Government: Securing classified communications and documents.
- Security: Implementing in security protocols to protect critical infrastructure.
- Banking: Safeguarding online services, ATM networks, and internal systems.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any changes or enhancements.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
