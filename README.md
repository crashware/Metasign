# Metasign
A lightweight ECDH and ECDSA application/library for generating key pairs and protecting data across multiple operating systems in a more portable format. Typical usage conditions such as the act of sharing a public key with an encrypted ECDH message have been resolved with minimal modifications to the overall base cryptosystem. All messages have the sender's public key automatically appended to the ciphertext, however, another public key may be provided in the event that one cannot be found within the message itself.

# Features
- Generation of ECDH key pairs as a string or a file
- Encryption & Decryption of data as a string or a file
- Custom logging with color support and optional output
- Dynamic garbage collection of cache files
- Dynamic loading of Python modules

___
> **Note**: The generation, signing, and verifying of data using ECDSA is currently unavailable and will be made so as soon as modifications have been completed.
___

# Requirements
- **Python 3.8+**  
`brew install python` or `sudo apt install python3-pip`
- **Cryptography**:  
`pip install cryptography` or `pip3 install cryptography` 

# Getting Started
### Generating a Key Pair
Currently keys are generated using a SECP384R1 curve and can be displayed as a string or written as files.

- **Generate and display keys**:  
`python3 ecdh.py`
  
![MetasignKeyGen](https://user-images.githubusercontent.com/90793958/134210025-b9680925-95f8-4efc-b3a3-748c0a36da6e.png)

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
`python3 ecdh.py -o "./keys"`
> **Note**: Arguments do not require quotations but can be used for readability.

![MetasignKeyGenOutput](https://user-images.githubusercontent.com/90793958/134212117-da4d6c5e-2d8b-45ee-bac5-f74dadce029f.png)

### Encrypting Data
Messages and files both can be encrypted as Metasign will automatically detect if the input is a file path or string. The encrypted data will also contain the public key associated with the private key used to actually perform the encryption, so pre-sharing, or post-sharing, of said public key is not necessary. You can just share the data!
> **Note**: Keys can be used directly in the terminal as a string rather than reading them from a file .  

> **Important**: *All* encryption functions require a private and public key to be imported, e.g. `-i or --import` and `-k or --key`, in order to work properly.

- **Encrypting a string message**:  
We'll load a private and public key assuming the key pair exists within a directory called `keys` or similar:
<br/>`python3 ecdh.py -i "./keys/private.pem" -e "Hello, World!" -k "./keys/public.pem"`  

![MetasignEncryptionMessage](https://user-images.githubusercontent.com/90793958/134219465-77423986-6812-4d84-86d5-e0cbccabef08.png)

Here is the encrypted data generated above:
```
nroeb4lTcid9DiSlVlcv4g==LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVSdmpDZmJCNGRGdUUyOXBqWFJJeFFCMmRoak93T2RXeApvMlExQ2pyZXpMaU4vQXlzeng3ZTRIa0RVbVdPR2VwMzNGdzU3SWJIeWhQNmR1YVRPazRJRDhxOUMvY1NPU3pmCnhZNlhiU2ZKUzdCSnVHZHllWTQ3ZjR3QjJTd1IvSnNzCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=
```

- **Encrypting a file**:  
Import a private and public key assuming the key pair exists within a directory called `keys` and also assuming a file called `data.txt` exists. When a file is encrypted an output directory is created called `output` in order to organize and more easily identify the location of cipherdata and plaintext messages:
<br/>`python3 ecdh.py -i "./keys/private.pem" -e "./data.txt" -k "./keys/public.pem"`

![MetasignEncryptionMessage](https://user-images.githubusercontent.com/90793958/134219465-77423986-6812-4d84-86d5-e0cbccabef08.png)

### Decrypting Data
Messages and files both can be decrypted as Metasign will automatically detect if the input is a file path or string. All that is required to decrypt a message or file is the private key associated with the public key that originally encrypted the data and the data itself. A public key from the sender can also be imported using `-k or --key`.

- **Decrypting a string message**:  
We'll import a private and public key assuming the key pair exists within a directory called `keys` or similar:
<br/>`python3 ecdh.py -i "./keys/private.pem" -d "<ciphertext>"`  
> **Note**: Ciphertext is the encrypted data like the generated data above in the `Encrypting Data` section .  

![MetasignEncryptionMessage](https://user-images.githubusercontent.com/90793958/134222422-d936c10a-affa-413f-98d3-37855e6a39ab.png)

- **Decrypting a file**:  
We'll import a private and public key assuming the key pair exists within a directory called `keys` and also assuming a file called `data.txt.enc` exists:
<br/>`python3 ecdh.py -i "./keys/private.pem" -d "./output/data.txt.enc"`

![MetasignEncryptionMessage](https://user-images.githubusercontent.com/90793958/134223656-9dbea47a-c459-47f2-8a73-eafeaf05c6b8.png)

### Help & Usage
Below is an image containing all of the help and usage information currently available for Metasign and the entire ECDH/ECDSA suite. There are multiple future plans for more features, options, and other updates related to the project as well. With advances in technology and the algorithms used there is also a push to become quantum resistant by implementing things such as Supersingular Isogeny Diffie-Hellman and other lattice based systems.

![MetasignEncryptionMessage](https://user-images.githubusercontent.com/90793958/134224835-0bfc65bd-7034-4a33-a4fc-b63231f0351f.png)

# Version History
## **Version 1.0.0**
This was the initial release of **Metasign**! 🍀

# License
Copyright © 2021 CRash

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
