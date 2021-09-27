# Metasign
A lightweight ECDH and ECDSA application/library for generating key pairs and protecting data across multiple operating systems in a more portable format. Typical usage conditions such as the act of sharing a public key with an encrypted ECDH message have been resolved with minimal modifications to the overall base cryptosystem. All messages have the sender's public key automatically appended to the ciphertext, however, another public key may be provided in the event that a key cannot be found within the message itself.

# Features
- Generation of ECDH key pairs as a string or a file
- Encryption & Decryption of data as a string or a file
- Signing & Verification of data as a string or a file
- Checksum calculations of data as a string or a file
    - MD5
    - SHA1
    - SHA224
    - SHA256
    - SHA512
- Custom logging with color support and optional output
- Dynamic garbage collection of cache files
- Dynamic loading of Python modules

# Requirements
- **Python 3.8+**  
`brew install python` or `sudo apt install python3-pip`
- **Cryptography**:  
`pip install cryptography` or `pip3 install cryptography` 

# Getting Started
### Generating a Key Pair
Currently keys are generated using a SECP384R1 curve and can be displayed as a string or written as files.

- **Generate and display keys**:  
`python3 metasign.py`
  
![MetasignKeyGen](https://user-images.githubusercontent.com/90793958/134863802-7381697f-bc35-4ac5-b3de-cb02af5a6ea2.png)

Here is the private key generated above:
```
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBOrccJLZxXmdpgGTG6
Z02rfuZD64xWhkC3AiJ5iNsTfwq5Y4qde7KDz9LJ+QWwp2qhZANiAARG+MJ9sHh0
W4Tb2mNdEjFAHZ2GM7A51bGjZDUKOt7MuI38DKzPHt7geQNSZY4Z6nfcXDnshsfK
E/p25pM6TggPyr0L9xI5LN/FjpdtJ8lLsEm4Z3J5jjt/jAHZLBH8myw=
-----END PRIVATE KEY-----
```

- **Generate and write keys to a directory**:  
`python3 metasign.py -o "./keys"`
> **Note**: Arguments do not require quotations but can be used for readability.

![MetasignKeyGenOutput](https://user-images.githubusercontent.com/90793958/134212117-da4d6c5e-2d8b-45ee-bac5-f74dadce029f.png)

### Encrypting Data
Messages and files both can be encrypted as Metasign will automatically detect if the input is a system file path or string. The encrypted data will also contain the public key associated with the private key used to actually perform the encryption, so pre-sharing, or post-sharing, of said public key is not necessary. You can just share the data!
> **Note**: Keys can be used directly in the terminal as a string rather than reading them from a file .  

> **Important**: *All* encryption functions require a private and public key to be imported, e.g. `-i or --import` and `-k or --key`, in order to work properly.

- **Encrypting a string message**:  
We'll load a private and public key assuming the key pair exists within a directory called `keys` or similar:
<br/>`python3 metasign.py -i "./keys/private.pem" -e "Hello, World!" -k "./keys/public.pem"`  

![MetasignEncryptedMessage](https://user-images.githubusercontent.com/90793958/134219465-77423986-6812-4d84-86d5-e0cbccabef08.png)

Here is the encrypted data generated above:
```
nroeb4lTcid9DiSlVlcv4g==LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVSdmpDZmJCNGRGdUUyOXBqWFJJeFFCMmRoak93T2RXeApvMlExQ2pyZXpMaU4vQXlzeng3ZTRIa0RVbVdPR2VwMzNGdzU3SWJIeWhQNmR1YVRPazRJRDhxOUMvY1NPU3pmCnhZNlhiU2ZKUzdCSnVHZHllWTQ3ZjR3QjJTd1IvSnNzCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=
```

- **Encrypting a file**:  
Import a private and public key assuming the key pair exists within a directory called `keys` and also assuming a file called `data.txt` exists. When a file is encrypted an output directory is created called `output` in order to organize and more easily identify the location of cipherdata and plaintext messages:
<br/>`python3 metasign.py -i "./keys/private.pem" -e "./data.txt" -k "./keys/public.pem"`

![MetasignEncryptedFile](https://user-images.githubusercontent.com/90793958/134219465-77423986-6812-4d84-86d5-e0cbccabef08.png)

### Decrypting Data
Messages and files both can be decrypted as Metasign will automatically detect if the input is a system file path or string. All that is required to decrypt a message or file is the private key associated with the public key that originally encrypted the data and the data itself. A public key can also be imported using `-k or --key`.

- **Decrypting a string message**:  
We'll import a private and public key assuming the key pair exists within a directory called `keys` or similar:
<br/>`python3 metasign.py -i "./keys/private.pem" -d "<ciphertext>"`  
> **Note**: Ciphertext is the encrypted data like the generated data above in the `Encrypting Data` section.

![MetasignDecryptedMessage](https://user-images.githubusercontent.com/90793958/134222422-d936c10a-affa-413f-98d3-37855e6a39ab.png)

- **Decrypting a file**:  
We'll import a private and public key assuming the key pair exists within a directory called `keys` and also assuming a file called `./output/data.txt.enc` exists:
<br/>`python3 metasign.py -i "./keys/private.pem" -d "./output/data.txt.enc"`

![MetasignDecryptedFile](https://user-images.githubusercontent.com/90793958/134223656-9dbea47a-c459-47f2-8a73-eafeaf05c6b8.png)

### Signing & Verifying Data
Messages and files both can be signed/verified as Metasign will automatically detect if the input is a system file path or string. When a file is signed an output directory is created called `output` in order to organize and more easily identify the location of the original file's signature.

- **Signing a string message**:  
We'll import a private key assuming the key pair exists within a directory called `keys` or similar:
<br/>`python3 metasign.py -i "./keys/private.pem" -s "Hello, World!"`

![MetasignSignedMessage](https://user-images.githubusercontent.com/90793958/134862982-1b0070a0-8b05-4381-8f1d-ae840ad68f2e.png)

Here is the signature generated from the above message:
```
MGYCMQClT+LWJYPYjOQj5qTIuoUjXzjEXDcGWURXafwAgohfi7hppAk9XhtVRGQD6sm/OQsCMQDLMAJOZcjzCqbHcadiR6c/zJnoMCifJgjLB5dbc+4PeOreZG7EFRRVBI+Z4OtOAHI=
```

- **Verifying a string message**:  
We'll import the public key associated with the signing private key assuming the key pair exists within a directory called `keys`, and that the signature of the signed data and the original data itself exist:
<br/>`python3 metasign.py -k "./keys/public.pem" -v "<signature>" "Hello, World!"`
> **Note**: Signature is the generated output shown about in the `Signing a string message` section above.

![MetasignVerifiedFile](https://user-images.githubusercontent.com/90793958/134862984-6028f9d4-3957-49ad-978b-d08453d11dac.png)

- **Signing a file**:  
We'll import a private key assuming the key pair exists within a directory called `keys` or similar:
<br/>`python3 metasign.py -i "./keys/private.pem" -s "./data.txt"`

![MetasignSignedFile](https://user-images.githubusercontent.com/90793958/134862978-67720c54-9f3b-47d5-a0f2-017507ec615c.png)

Here is the signature generated from the above file:
```
MGUCMAw4BiSKID6YBH6j4+pTmR7EQenMmY50zG23FpsCkrZo57ARHrQ/RuOKTitqTWmQRAIxALXIQTGbflgkppABQWEEx7jvwavDOazzlWveB2rq8SeYWfiOyCngMnSLLNNahH9t4w==
```

- **Verifiying a file**:  
We'll import the public key associated with the signing private key assuming the key pair exists within a directory called `keys` and also assuming a signature file called `./output/data.txt.sig` and the original data file called `./data.txt` exist:
<br/>`python3 metasign.py -k "./keys/public.pem" -v "./output/data.txt.sig" "./data.txt"`

![MetasignVerifiedFile](https://user-images.githubusercontent.com/90793958/134862985-e5f1553f-b3df-48fb-b9ef-58ff085c08c8.png)

### Generating Checksums
Generating a message or file is done in pure Python with the help of the `hashlib` library. Hashing data with Metasign is extremely easy and fast and requires only a few parameters such as the message, file, and the algorithm desired to be used for the calculation. Currently, only MD5, SHA1, SHA224, SHA256, SHA384, and SHA512 are supported.

- **Hashing a string message**:  
<br/>`python3 metasign.py -c "Hello, World!" -a md5`

![MetasignMessageChecksum](https://user-images.githubusercontent.com/90793958/134862988-0414ebec-dc68-442f-8259-43b6164953de.png)

Here is the checksum generated from the above message:
```
65a8e27d8879283831b664bd8b7f0ad4
```

- **Hashing a file**:
<br/>`python3 metasign.py -c "./data.txt" -a sha512`

![MetasignFileChecksum](https://user-images.githubusercontent.com/90793958/134862991-efebc511-0e04-446b-80de-895b85a87958.png)

Here is the checksum generated from the above file:
```
921618bc6d9f8059437c5e0397b13f973ab7c7a7b81f0ca31b70bf448fd800a460b67efda0020088bc97bf7d9da97a9e2ce7b20d46e066462ec44cf60284f9a7
```

### Help & Usage
Below is an image containing all of the help and usage information currently available for Metasign and the entire ECDH/ECDSA suite. There are multiple future plans for more features, options, and other updates related to the project as well. With advances in technology and the algorithms used there is also a push to become quantum resistant by implementing things such as Supersingular Isogeny Diffie-Hellman and other lattice based systems.

![MetasignHelpDocumentation](https://user-images.githubusercontent.com/90793958/134863813-c6381e0f-2849-4b6a-8e04-6fcbc42093f4.png)

# Version History
## **Version 1.1.0**
- Added signing and verifying of data from either a string message or file
- Added checksum generation of data from either a string message or file
- Updated help documentation and readme information

## **Version 1.0.0**
This was the initial release of **Metasign**! 🍀

# License
Copyright © 2021 CRash (https://github.com/crashware/Metasign)

All rights reserved.

The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Except as contained in this notice, the name of the above copyright holder
shall not be used in advertising or otherwise to promote the sale, use or
other dealings in this Software without prior written authorization.
