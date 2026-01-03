# crypto/caesar.py

def caesar_encrypt(plaintext: str, k: int) -> str:
    """
    Chiffrement de César
    :param plaintext: texte clair
    :param k: clé (1..25)
    """
    result = ""

    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + k) % 26 + base)
        else:
            result += char

    return result


def caesar_decrypt(ciphertext: str, k: int) -> str:
    """
    Déchiffrement de César
    """
    return caesar_encrypt(ciphertext, -k)
