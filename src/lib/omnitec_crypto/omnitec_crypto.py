import random
from typing import List


class OmnitecCrypto:
    ENCRYPTION_KEY: str = "932984ff84e6f4d11b9dff0d05abe78c"
    CODEC_A: str = "BfghFGH189AxyPIoE2lmn7eKtuvCDbcd3LMYZapqrNJ56VUO"
    CODEC_B: str = "5D7C69148B2FA3E0"

    @staticmethod
    def string_to_array_bytes(text: str) -> bytes:
        """
        Convert an ASCII string into a bytes array.

        :param text: The input string.
        :return: A bytes object representing the ASCII encoding of the string.
        """
        return text.encode("ascii")

    @staticmethod
    def array_bytes_to_string(array: bytes) -> str:
        """
        Convert a bytes array into an ASCII string.

        :param array: The bytes array.
        :return: The ASCII string.
        """
        return array.decode("ascii")

    @classmethod
    def encrypt(cls, source: str) -> str:
        """
        Encrypt the given source string using XOR with a predefined encryption key.
        After XOR, it encodes the result to hex, then transforms each hex character
        based on CODEC_B and CODEC_A.

        Transformation logic:
        - For each hex character:
          - If the character is found in CODEC_B, it is replaced by a random character
            chosen from the corresponding triple in CODEC_A.
          - If not found, the character remains unchanged.

        :param source: The plain text string to encrypt.
        :return: The encrypted string.
        """
        source_bytes: bytes = cls.string_to_array_bytes(source)
        key_bytes: bytes = cls.string_to_array_bytes(cls.ENCRYPTION_KEY)

        # XOR the source with the key.
        # The index 'j' starts at 0 and increments for each byte,
        # and when it reaches the end of the key, it wraps around to 1 (not 0).
        j: int = 0
        xor_result: List[int] = []
        for byte in source_bytes:
            j += 1
            if j >= len(key_bytes):
                j = 1
            xor_result.append(byte ^ key_bytes[j])

        # Convert XOR result to uppercase hex.
        xor_bytes: bytes = bytes(xor_result)
        xor_hex: str = xor_bytes.hex().upper()

        # Transform each character based on CODEC_B and CODEC_A.
        encrypt_chars: List[str] = []
        for char in xor_hex:
            pos = cls.CODEC_B.find(char)
            if pos < 0:
                # Character not in CODEC_B, keep as is.
                encrypt_chars.append(char)
            else:
                # Map character to CODEC_A.
                random_number = random.randint(1, 3)
                start = pos * 3 + (random_number - 1)
                end = start + 1
                encrypt_chars.append(cls.CODEC_A[start:end])

        return "".join(encrypt_chars)

    @classmethod
    def decrypt(cls, cipher: str) -> str:
        """
        Decrypt the given cipher string using the reverse of the encryption process.

        The process is:
        1. Reverse the CODEC_A to CODEC_B transformation.
        2. Convert the result from hex to bytes.
        3. XOR the bytes with the key to retrieve the original source string.

        :param cipher: The encrypted string.
        :return: The decrypted plain text string.
        :raises ValueError: If the cipher does not have the expected format.
        """
        # The cipher should have an even length (since it represents hex characters).
        if len(cipher) % 2 != 0:
            raise ValueError("The cipher does not have the expected format")

        # Map characters back from CODEC_A to CODEC_B.
        xor_hex_chars: List[str] = []
        for char in cipher:
            pos = cls.CODEC_A.find(char)
            if pos < 0:
                # Character not in CODEC_A, should be a normal hex char.
                xor_hex_chars.append(char)
            else:
                # Convert CODEC_A character back to CODEC_B.
                xor_hex_chars.append(cls.CODEC_B[pos // 3])

        xor_hex: str = "".join(xor_hex_chars)

        # Convert from hex to XOR-ed bytes.
        xor_bytes: bytes = bytes.fromhex(xor_hex)

        # XOR again with the key to get the original source.
        xor_result_str: str = cls.array_bytes_to_string(xor_bytes)
        xor_result_bytes: bytes = cls.string_to_array_bytes(xor_result_str)

        key_bytes: bytes = cls.string_to_array_bytes(cls.ENCRYPTION_KEY)
        j: int = 0
        source_bytes: List[int] = []
        for byte in xor_result_bytes:
            j += 1
            if j >= len(key_bytes):
                j = 1
            source_bytes.append(byte ^ key_bytes[j])

        decrypt_value: str = cls.array_bytes_to_string(bytes(source_bytes))
        return decrypt_value


def main():
    encrypted_data: str = "VOV8fGOVUKBlUVVmOAVqVIVf"
    decrypted_data = OmnitecCrypto.decrypt(encrypted_data)
    print("------------------------------------------")
    print("OmnitecCrypto.decrypt:", decrypted_data)
    
    
    
    encrypted_data = OmnitecCrypto.encrypt("xank29")
    print("------------------------------------------")
    print("OmnitecCrypto.encrypt:", encrypted_data)


if __name__ == "__main__":
    main()
