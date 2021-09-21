# -*- coding: utf-8 -*-
# ########################################################################
# Program: Metasign
# Author: "CRash"
# Version: "1.0.0"
# Date: 09/14/21
# #########################################################################
# main.py - Encapsulates all settings for ECDH key generation, signing,
# and verifying in a multi-platform way including Windows, Linux, & macOS.
#
# Description:
# A compact module which can be utilized to generate secure ECDH key pairs
# and to sign, verify, and encrypt numerous data types. Both private and 
# public keys can be exported in PEM format and saved to a file or
# copy and pasted for ease of use within another application.
# #########################################################################
#TODO: Explore Supersingular Isogeny Diffie-Hellman once a stable formulation has been standardized.
import os
import re
import sys
import time
import getopt
import hashlib
import platform
from typing import Union
from datetime import datetime
from base64 import b64encode, b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PublicFormat, PrivateFormat
from colors import Colors
from utils import SystemUtils
from sentinel import Sentinel
from logger import Logger

#? Both the sentinel and logger are optional as they just help keep a clean environment.
sentinel = Sentinel()
log = Logger(__name__, write_output=False)
version = "1.0.0"
version_name = "Chameleon"

class DiffieHellman: #* This is where all of the real magic happens. 💖
    """A clean and simple wrapper for common ECDH functionality such as key pair generation, encryption, and decryption."""

    class Hashing:
        """A security class supporting simple data hashing and checksum operations."""
        @staticmethod
        def _get_checksum(data: bytes) -> str:
            """Calculates a SHA512 hash for a given message or data chunk.

            Parameters
            ----------
            :param data: A byte array to calculate a checksum for.
            :type data: bytes

            Returns
            -------
            :rtype: str
            :return: The hexadecimal digest of the generated data checksum.
            """
            sha512 = hashlib.sha512()
            sha512.update(data)
            return sha512.hexdigest()

    def __init__(self: "DiffieHellman", private_key: Union[str, ec.EllipticCurvePrivateKey] = None):
        """Initializes a new ECDH wrapper object with an optional private key previously generated if provided.
        
        Parameters
        ----------
        :param private_key: A ECDH private key previously generated with this script.
        :type private_key: str, optional
        """
        def _check_key(key: str) -> ec.EllipticCurvePrivateKey:
            """Returns an imported ECDH key if the provided data is valid."""
            try:
                if key is not None:
                    if isinstance(private_key, ec.EllipticCurvePrivateKey):
                        return private_key
                    else: return load_pem_private_key(str.encode(key, 'utf-8'), None, backend=default_backend())
                else: return ec.generate_private_key(ec.SECP384R1(), default_backend())
            except: raise Exception("The provided private key is invalid and could not be loaded.") 
        self.keypair = _check_key(private_key)
        self.public_key = self.keypair.public_key()
        self.private_string = self._convert_to_pem(self.keypair)
        self.public_string = self._convert_to_pem(self.keypair.public_key())
    
    def _convert_to_pem(self: "DiffieHellman", ecdh_key: Union[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]) -> str:
        """Converts a ECDH key into its PEM format equivalent.
                
        Parameters
        ----------
        :param public_key: The key to convert into a PEM format.
        :type public_key: Union[EllipticCurvePrivateKey, EllipticCurvePublicKey]
        
        Returns
        -------
        :rtype: str
        :return: The PEM formatted ECDH public key and `None` if an error occurred.
        """
        try:
            if isinstance(ecdh_key, ec.EllipticCurvePrivateKey):
                return ecdh_key.private_bytes(
                    encoding=Encoding.PEM, 
                    format=PrivateFormat.PKCS8, 
                    encryption_algorithm=NoEncryption()
                ).decode('utf-8')
            elif isinstance(ecdh_key, ec.EllipticCurvePublicKey):
                return ecdh_key.public_bytes(
                    encoding=Encoding.PEM, 
                    format=PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
            else: return None
        except: return None

    def _check_public_key(self: "DiffieHellman", public_key: object) -> ec.EllipticCurvePublicKey:
        """Checks a public key to see if it is a string or ECDH public key object.
        
        Parameters
        ----------
        :param public_key: The public key to parse or check for validity.
        :type public_key: object

        Returns
        -------
        :rtype: EllipticCurvePublicKey
        :return: The public key object for further cryptographic operations.
        """
        try:
            if isinstance(public_key, ec.EllipticCurvePublicKey): 
                return public_key
            else: return load_pem_public_key(public_key)
        except: raise Exception("The provided public key is invalid and could not be loaded.")

    def _derive_iv(self: "DiffieHellman", derived_key: bytes) -> bytes:
        """Derives an initialization vector from a derived ECDH key.
        
        Parameters
        ----------
        :param derived_key: The bytes of a derived ECDH key.
        :type derived_key: bytes

        Returns
        -------
        :rtype: bytes
        :return: The initialization vector bytes for the provided derived key.
        """
        encoded = b64encode(bytes(reversed(b64encode(derived_key))))
        checksum = self.Hashing._get_checksum(encoded)
        return str.encode(checksum)[:16]

    def encrypt(self: "DiffieHellman", public_key: Union[str, ec.EllipticCurvePublicKey], message: str) -> str:
        """Returns an encrypted ciphertext of the original plaintext message.

        Parameters
        ----------
        :param public_key: The public key of the recipient of the encrypted message.
        :type public_key: str | EllipticCurvePublicKey\n
        :param message: The message to be encrypted.
        :type message: str

        Returns
        -------
        :rtype: str
        :return: The encrypted ciphertext of the original message.
        """
        public_key = self._check_public_key(public_key)
        shared_key = self.keypair.exchange(ec.ECDH(), public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(shared_key)
        iv = self._derive_iv(derived_key)
        aes = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
        encryptor = aes.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        encoded = b64encode(encryptor.update(padded_data) + encryptor.finalize()).decode('utf-8')
        appended = encoded + b64encode(str.encode(self.public_string, 'utf-8')).decode('utf-8')
        return appended

    def decrypt(self: "DiffieHellman", message: str, public_key: Union[str, ec.EllipticCurvePublicKey] = None) -> str:
        """Returns a decrypted plaintext of the original ciphertext message.

        Parameters
        ----------
        :param message: The message to be decrypted.
        :type message: str\n
        :param public_key: The public key of the author of the encrypted message.
        :type public_key: str | EllipticCurvePublicKey

        Returns
        -------
        :rtype: str
        :return: The decrypted plaintext of the original encrypted message.
        """
        # Attemp to parse the public key from the message itself.
        data = message
        if len(message) > 288:
            appended = b64decode(message[-288:])
            data = b64decode(message[0:len(message)-288])
            try:
                loaded = load_pem_public_key(appended)
                if loaded:
                    if public_key is None:
                        public_key = loaded
            except: pass
        if public_key is None:
            raise IOError("No public key was provided and none could be found in the message.")
        # Continue with the decryption regardless if a public key was in the message or not.
        public_key = self._check_public_key(public_key)
        shared_key = self.keypair.exchange(ec.ECDH(), public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(shared_key)
        iv = self._derive_iv(derived_key)
        aes = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
        decryptor = aes.decryptor()
        decrypted_data = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(decrypted_data) + unpadder.finalize()).decode('utf-8')

    def import_from_pem(self: "DiffieHellman", filepath: str) -> Union[object, None]:
        """Reinitialize the current Elliptical Curve Diffie-Hellman instance with a private key read from a PEM formatted file.

        Parameters
        ----------
        :param filepath: The path of the ECDH private key to import.
        :type filepath: str

        Raises
        ------
        :class: `IOError`: The file could not be read.
        :class: `OSError`: The file could not opened or read.
        :class: `Exception`: The file could not be read in general.

        Returns
        -------
        :rtype: DiffieHellman | None
        :return: A `DiffieHellman` object if the import was successful, or `None` if not.
        """
        if os.path.exists(filepath):
            try:
                return DiffieHellman(SystemUtils.read_from_file(filepath))
            except IOError: raise IOError(f"The file '{filepath}' could not be read.")
            except OSError: raise OSError(f"The file '{filepath}' could not be opened or read.")
            except: log.error("The provided ECDH private key file is invalid.")
        else: log.error("The provided key file doesn't exist.")
        return False

    def save_private_to_pem(self: "DiffieHellman", filepath: str) -> bool:
        """Export the current Elliptical Curve Diffie-Hellman instance private key to a PEM formatted file.

        Parameters
        ----------
        :param filepath: The path of the private key file.
        :type filepath: str

        Returns
        -------
        :rtype: bool
        :return: A flag, `True` if the export was successful, or `False` if not.
        """
        result = SystemUtils.write_to_file(filepath, self.private_string)
        if result is not None: return True
        else: return False

    def save_public_to_pem(self: "DiffieHellman", filepath: str) -> bool:
        """Export the current Elliptical Curve Diffie-Hellman instance public key to a PEM formatted file.

        Parameters
        ----------
        :param filepath: The path of the public key file.
        :type filepath: str

        Returns
        -------
        :rtype: bool
        :return: A flag, `True` if the export was successful, or `False` if not.
        """
        result = SystemUtils.write_to_file(filepath, self.public_string)
        if result is not None: return True
        else: return False

class Program:
    def __init__(self) -> None:
        """Initialize a new instance of the ECDH main program for generating, encrypting, and decrypting data."""
        self.keypair = DiffieHellman()
        self.public_key = None

    def _set_key(self: "Program", public_key: str) -> None:
        """Checks and imports a public key from a string or from a file."""
        def _check_key(key: str) -> ec.EllipticCurvePublicKey:
            """Returns a ECDH public key as an EllipticCurvePrivateKey object."""
            try:
                if key is None:
                    raise Exception("The provided public key can't be 'None'. Please provide a valid ECDH public key.") 
                if isinstance(public_key, ec.EllipticCurvePrivateKey):
                    return public_key
                else: return load_pem_public_key(str.encode(key, 'utf-8'), backend=default_backend())
            except: raise Exception("The provided public key is invalid and could not be loaded.")
        if os.path.exists(public_key):
            self.public_key = _check_key(SystemUtils.read_from_file(public_key))
            log.success(f"The public key '{public_key}' was successfully loaded.")
        else: 
            self.public_key = _check_key(public_key)
            log.success(f"The public key was successfully loaded.")

    def _print_greeting(self: "Program") -> None:
        """Displays a welcome message for the user upon initialization of the script without parameters or during usage."""
        greeting = ("======================================\n" +
                    "✨       Welcome to: Metasign!      ✨\n" +
                    "======================================\n")
        info = [
            f'⇢ {Colors.bold}Version{Colors.reset}\t| Metasign ({Colors.Foreground.pink}v{version}{Colors.reset})[{Colors.Foreground.pink}{version_name}{Colors.reset}]',
            f'⇢ {Colors.bold}Author{Colors.reset}\t| CRash ({Colors.Foreground.pink}https://twitter.com/crashware{Colors.reset})',
            f'⇢ {Colors.bold}Platform{Colors.reset}\t| Python ({Colors.Foreground.pink}v{platform.python_version()}{Colors.reset})',
            f'⇢ {Colors.bold}Spawned{Colors.reset}\t| {Colors.Foreground.purple}{datetime.now()}{Colors.reset}',
        ]
        line_bar = ""
        line_bar_length = 0
        for bar in info:
            if len(bar) > line_bar_length:
                line_bar_length = len(bar)
        while len(line_bar) != line_bar_length:
            line_bar += "-"
        log.info('\n'+ f"{greeting}")
        print(f"{line_bar}")
        for entry in info:
            print(f"{entry}")
        print(f"{line_bar}")

    def _print_usage(self: "Program", *args) -> None:
        """Displays detailed documentation for the user upon request or misuse of the script."""
        usage = [
            "\n===========================================",
            f"Usage: {__file__}: [options] <arguments>",
            "===========================================",
            "-h or --help\t| Displays this help message.",
            "-k or --key\t| Imports a ECDH public key from a string or file.",
            "-i or --import\t| Imports a ECDH private key from a string or file.",
            "-o or --output\t| Exports a ECDH key pair to their respective files.",
            "-e or --encrypt\t| Encrypts a string message or a file with the provided public key.",
            "-d or --decrypt\t| Decrypts a string message or a file with the provided public key.",
            "\n===========================================",
            f"Examples: ",
            "===========================================",
            f"Generate key pair | {__file__} -o \"./keys\"",
            f"Encrypt a message | {__file__} -i \"./keys/private.pem\" -e \"Hello!\" -k \"./keys/public.pem\"",
            f"Encrypt a file    | {__file__} -i \"./keys/private.pem\" -e \"./test.txt\" -k \"./keys/public.pem\"",
            f"Decrypt a message | {__file__} -i \"./keys/private.pem\" -d <ciphertext>",
            f"Decrypt a file    | {__file__} -i \"./keys/private.pem\" -d \"./output/test.txt.enc\"\n",
            f"For more information please visit: https://github.com/crashware/metasign",
            f"To obtain live updates please visit: https://twitter.com/crashware"
        ]
        self._print_greeting()
        for line in usage: print(line)

    def _generate_keypair(self: "Program", *args) -> None:
        """Creates a new `EllipticCurvePrivateKey` and `EllipticCurvePublicKey` key pair and displays them in PEM format to the log."""
        log.info("Generating a new ECDH key pair!")
        self.keypair = DiffieHellman()
        log.success(f"\n{self.keypair.private_string}")
        log.success(f"\n{self.keypair.public_string}")

    def _load_keypair(self: "Program", *args) -> None:
        """Loads a ECDH private key pair from a string or specified file."""
        try:
            if os.path.exists(args[0]):
                log.info(f"Loading ECDH key pair from `{args[0]}`")
                self.keypair = DiffieHellman(SystemUtils.read_from_file(args[0]))
            else:
                log.info(f"Loading ECDH key pair from string data...")
                self.keypair = DiffieHellman(args[0])
        except Exception as e: 
            log.error(e)
            sys.exit(2)

    def _save_keypair(self: "Program", *args) -> None: 
        """Saves a newly generated ECDH key pair to the chosen directory."""
        if args[0].startswith('-') or args[0].startswith('--'):
            log.error(f"Please provide a vaid directory as '{args[0]}' is a script parameter.")
            return
        log.info("Saving new key pair files to chosen directory...")
        divider = "\\" if SystemUtils.get_system() == SystemUtils.windows else "/"
        private_saved = self.keypair.save_private_to_pem(f"{args[0]}{divider}private.pem")
        public_saved = self.keypair.save_public_to_pem(f"{args[0]}{divider}public.pem")
        if private_saved:
            log.note(f"Your new private key has been saved to '{args[0]}{divider}private.pem'!")
        else: log.error(f"Your private key couldn't be saved. Check that you provided a valid directory.")
        if public_saved:
            log.note(f"Your new public key has been saved to '{args[0]}{divider}public.pem'!")
        else: log.error(f"Your public key couldn't be saved. Check that you provided a valid directory.")
        if private_saved and public_saved:
            log.success(f"A new key pair has been saved!")
        else:
            if private_saved and not public_saved:
                log.warning(f"Your private key was saved but there was an issue saving the public key.")
            elif public_saved and not private_saved:
                log.warning(f"Your public key was saved but there was an issue saving the private key.")

    def _encrypt_data(self: "Program", *args) -> None:
        """Encrypts and saves a string message or the contents of a file into a new file."""
        def encrypt(data, filename=None):
            try:
                if self.public_key is not None:
                    encrypted = self.keypair.encrypt(self.public_key, data)
                    if filename is not None:
                        try:
                            SystemUtils.write_to_file(filename, encrypted)
                            log.note(f"Encrypted data was saved to '{filename}'!")
                        except Exception as e:
                            log.error(e)
                            sys.exit(2)
                    else: log.info(f"Displaying the encrypted message:\n{encrypted}")
                    log.success(f"Your data was successfully encrypted!")
                else: 
                    log.error("A public key is missing in order to encrypt the data.")
                    self._print_usage()
            except: log.error("The data could not be encrypted. Either the key is bad or the data encoding/padding is invalid.")
        parameter = args[0]
        if os.path.exists(parameter):
            try:
                log.info(f"Attempting to encrypt the file '{args[0]}'")
                divider = "\\" if SystemUtils.get_system() == SystemUtils.windows else "/"
                path = f"{sys.path[0]}{divider}output{divider}"
                filename = f"{path}{os.path.basename(parameter)}.enc"
                encrypt(SystemUtils.read_from_file(parameter), f"{filename}")
            except Exception as e:
                log.error(e)
                sys.exit(2)
        else:
            log.info(f"Attempting to encrypt message data...") 
            encrypt(parameter) # Just encrypt the data itself since it's not a file.
        
    def _decrypt_data(self: "Program", *args) -> None:
        """Decrypts and saves a ciphertext message or the contents of a file into a new file representing the original."""
        def decrypt(data, filename=None):
            try:
                decrypted = self.keypair.decrypt(data, self.public_key)
                if filename is not None:
                    try:
                        SystemUtils.write_to_file(filename, decrypted)
                        log.success(f"Decrypted data was saved to '{filename}'!")
                    except Exception as e:
                        log.error(e)
                        sys.exit(2)
                else: log.info(f"Displaying decrypted message:\n{decrypted}")
                log.success(f"Your data was successfully decrypted!")
            except: log.error("The data could not be decrypted. Either the key is bad or the data encoding/padding is invalid.")
        parameter = args[0]
        log.info("Attempting to decrypt data!")
        if os.path.exists(parameter):
            try:
                divider = "\\" if SystemUtils.get_system() == SystemUtils.windows else "/"
                path = f"{sys.path[0]}{divider}output{divider}"
                filename = f"{path}{os.path.basename(parameter)}"
                if filename.endswith(".enc"):
                    filename = filename.replace(".enc", "")
                decrypt(SystemUtils.read_from_file(parameter), f"{filename}")
            except Exception as e:
                log.error(e)
                sys.exit(2)
        else: return decrypt(parameter) # Just encrypt the data itself since it's not a file.

    def main(self: "Program", *args) -> None: #TODO: Refactor and optimize the whole time.sleep() thing.
        """The main initialization method for Metasign."""
        sentinel.authorized = True
        sentinel.start_resolver() #* Keep the environment clean of garbage directories and files.
        time.sleep(.25) #* Give the sentinel some time to actually clean. Usually needed only when using pure strings for operations.
        try: opts, args = getopt.getopt(sys.argv[1:], "ho:i:o:e:d:k:v:", ["help", "import=", "output=", "encrypt=", "decrypt=", "key="])
        except getopt.GetoptError as err:
            message = str(err)
            if re.match('^[A-Z][^?!.]*[?.!]$', message) is None:
                message = f"{message}." #? I like full sentences for my logging; can somebody help highlight the opt too?
            log.warning(str(message).capitalize())
            self._print_usage()
            sys.exit(2)
        parameters = {
            "-i": self._load_keypair,
            "--import": self._load_keypair,
            "-o": self._save_keypair,
            "--output": self._save_keypair,
            "-e": self._encrypt_data,
            "--encrypt": self._encrypt_data,
            "-d": self._decrypt_data,
            "--decrypt": self._decrypt_data
        }
        options = []
        error = False
        for o, a in opts:
            # If the help flag is detected anywhere just display it instead of doing anything else.
            if o == "-h" or o == "--help":
                error = True
                self._print_usage()
                break
            # Make sure there's a public key set in case the user wants to call encrypt or decrypt.
            elif o == "-k" or o == "--key":
                try: 
                    self._set_key(a)
                except Exception as e:
                    log.error(e)
                    sys.exit(2)
            else:
                # Check if there's anything more than the help flag.
                option = parameters.get(str(o), None)
                if option is not None:
                    options.append((option, a))
                else:
                    error = True
                    self._print_usage()
        # Run all of the appropriate functions provided the proper options were given.
        if not error:
            if len(options) > 0:
                for option in options:
                    method, param = option
                    method(param)
            else:
                if len(args) > 0:
                    self._print_usage()
                else: 
                    self._print_greeting()
                    self._generate_keypair()
        else: sys.exit(2)

if __name__ == "__main__":
    program = Program()
    program.main()