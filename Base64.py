class Base64:
    """
    A class providing Base64 encoding and decoding functionalities.

    Class Attributes:
    - base64_list (str): The Base64 character set.

    Methods:
    - Encrypt: Encrypt a string using Base64 encoding.
    - Decrypt: Decrypt a Base64 encoded string.

    Usage:
    base64_instance = Base64()
    encrypted_string = base64_instance.Encrypt("Hello, World!")
    decrypted_string = base64_instance.Decrypt(encrypted_string)
    """

    base64_list = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    @staticmethod
    def Encrypt(str_to_encrypt) -> str:
        """
        Encrypt a string using Base64 encoding.

        Parameters:
        - str_to_encrypt (str): The string to be encrypted.

        Returns:
        str: The Base64 encoded string.
        """
        print(str_to_encrypt)
        bin_str = ''.join(str(bin(ord(i)))[2:].rjust(8, '0') for i in str_to_encrypt)
        list_to_add = []
        while len(bin_str) >= 6:
            list_to_add.append(bin_str[0:6])
            bin_str = bin_str[6:]

        if len(bin_str) > 0:
            list_to_add.append(bin_str.ljust(6, '0'))

        ascii_converter_list = [Base64.base64_list[int(i, 2)] for i in list_to_add]
        padding = ""

        if len(str_to_encrypt) % 3 == 1:
            padding = "=="
        elif len(str_to_encrypt) % 3 == 2:
            padding = "="

        return ''.join(ascii_converter_list) + padding

    @staticmethod
    def Decrypt(str_to_decrypt: str) -> str:
        """
        Decrypt a Base64 encoded string.

        Parameters:
        - str_to_decrypt (str): The Base64 encoded string to be decrypted.

        Returns:
        str: The decrypted string.
        """
        print(str_to_decrypt)
        help_string = ""
        help_list = []

        while str_to_decrypt != '' and str_to_decrypt[0] != '=':
            help_string += bin(Base64.base64_list.find(str_to_decrypt[0]))[2:].rjust(6, '0')
            str_to_decrypt = str_to_decrypt[1:]

        if str_to_decrypt.count('=') == 1:
            help_string = help_string[:-2]
        elif str_to_decrypt.count('=') == 2:
            help_string = help_string[:-4]

        help_list = [chr(int(help_string[i:i + 8], 2)) for i in range(0, len(help_string), 8)]

        return ''.join(help_list)
