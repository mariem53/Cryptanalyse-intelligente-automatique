# crypto/bruteforce.py

from crypto.caesar import caesar_decrypt #Importe la fonction de déchiffrement de César.

def caesar_bruteforce(ciphertext: str):
    """
    Teste toutes les clés possibles (1..25)
    Retourne une liste de tuples (key, plaintext)
    """
    results = []

    for k in range(1, 26):
        plaintext = caesar_decrypt(ciphertext, k)
        results.append((k, plaintext))

    return results
