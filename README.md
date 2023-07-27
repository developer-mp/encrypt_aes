### Encryption / Decryption of files using AES algorithm

This is a console app that encrypts and decrypts files using the AES-128 encryption algorithm in Cipher Block Chaining (CBC) mode.

### Features

Users are prompted to enter a path to the file to encrypt. They are also provided with a hex encryption key, which is necessary for decryption.
Users need to install OpenSSL library for cryptographic operations to be able to run the application.

### What is OpenSSL

OpenSSL is a widely-used open-source cryptographic library that provides various cryptographic functions, including encryption, decryption, hashing, digital signatures, and more. It is commonly used in secure communication protocols like HTTPS, TLS/SSL, and SSH, as well as in various security-related applications.

### How AES-128 encryption algorithm in Cipher Block Chaining (CBC) mode works

AES-128 encryption algorithm in Cipher Block Chaining (CBC) mode is a widely used symmetric encryption scheme. AES (Advanced Encryption Standard) is a block cipher that operates on fixed-size blocks of data (128 bits). CBC is one of the block cipher modes of operation used to apply AES to encrypt data that is larger than a single block.

In CBC mode, each plaintext block is XORed with the previous ciphertext block before being encrypted with the AES algorithm. This introduces a dependency on the previous block during encryption, which helps to hide patterns and increase security.

Here's a step-by-step explanation of how AES-128 encryption in CBC mode works:

1. Key Setup: The encryption key used by AES-128 is derived from the original encryption key provided. The AES-128 algorithm uses a 128-bit key (16 bytes).

2. Initialization Vector (IV) Selection: CBC mode requires an Initialization Vector (IV) that is the same block size as the AES cipher (128 bits in this case). The IV should be unique for each encryption operation to ensure the security of the encryption.

3. Padding: If the plaintext data is not an exact multiple of the block size (16 bytes for AES), padding is added to make it a multiple of the block size. Common padding schemes include PKCS#5 or PKCS#7.

4. CBC Encryption: The encryption process starts with the first plaintext block. The IV is XORed with the first plaintext block to create a "modified" plaintext block, which is then encrypted using AES-128 with the encryption key. The resulting ciphertext block becomes the first block of the ciphertext.

5. Chaining: For each subsequent plaintext block, it is XORed with the previous ciphertext block, and the result is encrypted with AES-128 using the same encryption key. The new ciphertext block becomes the next block in the ciphertext sequence.

6. Finalization: Once all plaintext blocks are encrypted and linked together, the ciphertext is ready to be transmitted or stored securely.

Decryption works in reverse, where each ciphertext block is decrypted with AES-128 using the same encryption key and then XORed with the previous ciphertext block to retrieve the original plaintext block.

### Installation

This app is written in C. To encrypt a file, compile and run the 'encrypt_aes.c' file:

- gcc -o encrypt_aes encrypt_aes.c -lcrypto
- ./encrypt_aes

To decrypt a file, compile and run the 'decrypt_aes.c' file:

- gcc -o decrypt_aes decrypt_aes.c -lcrypto
- ./decrypt_aes
