from random import choice

from cryptography.fernet import Fernet, InvalidToken
from string import ascii_letters
from hashlib import md5
import globals_module


#TODO -> remove prints and make here not CryptoService but encryptor

class CryptoService:
    """
    A class providing CryptoService encoding and decoding functionalities.

    Attributes:
    - base64_list (str): The CryptoService character set.
    - fernet_obj (Fernet Object): The fernet class object

    """

    base64_list = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    @staticmethod
    def generate_random_key():
        return Fernet.generate_key()

    @staticmethod
    def encrypt_string(str_to_encrypt, key=None) -> bytes | str:
        """
        Encrypt a string using CryptoService encoding.

        Parameters:
        - str_to_encrypt (str): The string to be encrypted.

        Returns:
        str: The CryptoService encoded string.
        """
        try:
            print(str_to_encrypt)
            bin_str = ''.join(str(bin(ord(i)))[2:].rjust(8, '0') for i in str_to_encrypt)
            list_to_add = []
            while len(bin_str) >= 6:
                list_to_add.append(bin_str[0:6])
                bin_str = bin_str[6:]

            if len(bin_str) > 0:
                list_to_add.append(bin_str.ljust(6, '0'))

            ascii_converter_list = [CryptoService.base64_list[int(i, 2)] for i in list_to_add]
            padding = ""

            if len(str_to_encrypt) % 3 == 1:
                padding = "=="
            elif len(str_to_encrypt) % 3 == 2:
                padding = "="

            rnd_prefix = ''.join(choice(ascii_letters) for _ in range(globals_module.RANDOM_PREFIX_LENGTH))
            if key is not None:

                return Fernet(key).encrypt((rnd_prefix + ''.join(ascii_converter_list) + padding).encode())[::-1]
            else:
                return (rnd_prefix + ''.join(ascii_converter_list) + padding)[::-1]
        except InvalidToken as e:
            print("--------------ENCRYPTION STRING ERROR-----------------------", e)

    @staticmethod
    def decrypt_string(str_to_decrypt: str, key=None) -> str:
        """
        Decrypt a CryptoService encoded string.

        Parameters:
        - str_to_decrypt (str): The CryptoService encoded string to be decrypted.

        Returns:
        str: The decrypted string.
        """
        try:
            if key is not None:
                str_to_decrypt = Fernet(key).decrypt(str_to_decrypt[::-1].encode()).decode()[
                                 globals_module.RANDOM_PREFIX_LENGTH:]
            else:
                str_to_decrypt = str_to_decrypt[::-1][globals_module.RANDOM_PREFIX_LENGTH:]
            print(str_to_decrypt)
            help_string = ""

            while str_to_decrypt != '' and str_to_decrypt[0] != '=':
                help_string += bin(CryptoService.base64_list.find(str_to_decrypt[0]))[2:].rjust(6, '0')
                str_to_decrypt = str_to_decrypt[1:]

            if str_to_decrypt.count('=') == 1:
                help_string = help_string[:-2]
            elif str_to_decrypt.count('=') == 2:
                help_string = help_string[:-4]

            help_list = [chr(int(help_string[i:i + 8], 2)) for i in range(0, len(help_string), 8)]

            return ''.join(help_list)
        except InvalidToken as e:
            print("--------------DECRYPTION STRING ERROR-----------------------", e)

    @staticmethod
    def encrypt_obj(bytes_to_encrypt, key) -> bytes:
        try:
            rnd_prefix = ''.join(choice(ascii_letters) for _ in range(globals_module.RANDOM_PREFIX_LENGTH))
            return (rnd_prefix.encode() + Fernet(key).encrypt(bytes_to_encrypt))[::-1]
        except InvalidToken as e:
            print("--------------ENCRYPTION OBJECT ERROR-----------------------", e)

    @staticmethod
    def decrypt_obj(bytes_to_encrypt, key) -> bytes:
        try:
            bytes_to_encrypt = bytes_to_encrypt[::-1]
            return Fernet(key).decrypt(bytes_to_encrypt[globals_module.RANDOM_PREFIX_LENGTH:])
        except InvalidToken as e:
            print("--------------DECRYPTION OBJECT ERROR-----------------------", e)

    @staticmethod
    def encrypt_string_hash(string_to_encrypt) -> str:
        return md5(string_to_encrypt.encode()).hexdigest()
