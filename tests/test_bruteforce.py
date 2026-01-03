#!/usr/bin/env python3
"""
Tests pour l'attaque brute force César
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from crypto.caesar import caesar_encrypt
from crypto.bruteforce import caesar_bruteforce


def test_bruteforce():
    print("=== Test Brute Force César ===")

    plaintext = "This is a test"
    key = 5
    ciphertext = caesar_encrypt(plaintext, key)

    results = caesar_bruteforce(ciphertext)

    # Vérifier que la bonne solution existe
    found = False
    for k, text in results:
        if text.lower() == plaintext.lower():
            found = True
            found_key = k
            break

    assert found
    assert found_key == key

    print("✓ Test brute force passé")
    print(f"  Décalage trouvé: {found_key}")
    print(f"  Texte: {plaintext}")


if __name__ == "__main__":
    test_bruteforce()
