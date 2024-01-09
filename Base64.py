class Base64:
    base64_list = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    @staticmethod
    def Encrypt(str_to_encrypt) -> str:
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
    def Decrypt(str_to_decrypt) -> str:
        pass
