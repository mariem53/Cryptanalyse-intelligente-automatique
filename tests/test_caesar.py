"""
Tests unitaires pour le module caesar
"""

import sys
import os

# Ajouter le dossier racine au path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from crypto.caesar import caesar_encrypt, caesar_decrypt
from crypto.bruteforce import caesar_bruteforce


def test_encrypt_basic():
    """Test basique de chiffrement"""
    plaintext = "HELLO"
    key = 3
    expected = "KHOOR"
    assert caesar_encrypt(plaintext, key) == expected


def test_decrypt_basic():
    """Test basique de déchiffrement"""
    ciphertext = "KHOOR"
    key = 3
    expected = "HELLO"
    assert caesar_decrypt(ciphertext, key) == expected


def test_roundtrip():
    """Test d'inversibilité encrypt/decrypt"""
    plaintext = "The quick brown fox jumps over the lazy dog"
    key = 13

    ciphertext = caesar_encrypt(plaintext, key)
    recovered = caesar_decrypt(ciphertext, key)

    assert plaintext == recovered


def test_preserve_case():
    """Test de conservation de la casse"""
    plaintext = "HeLLo WoRLd"
    key = 5

    ciphertext = caesar_encrypt(plaintext, key)
    recovered = caesar_decrypt(ciphertext, key)

    assert plaintext == recovered
    assert ciphertext[0].isupper()
    assert ciphertext[2].isupper()


def test_preserve_nonalpha():
    """Test de préservation des caractères non-alphabétiques"""
    plaintext = "Hello, World! 123"
    key = 7

    ciphertext = caesar_encrypt(plaintext, key)

    assert ',' in ciphertext
    assert '!' in ciphertext
    assert '123' in ciphertext


def test_empty_string():
    """Test avec chaîne vide"""
    plaintext = ""
    key = 5

    ciphertext = caesar_encrypt(plaintext, key)
    assert ciphertext == ""


def test_key_wraparound():
    """Test du wraparound pour clés > 26"""
    plaintext = "HELLO"
    key1 = 3
    key2 = 29  # 29 mod 26 = 3

    assert caesar_encrypt(plaintext, key1) == caesar_encrypt(plaintext, key2)


def test_brute_force_count():
    """Test que brute_force retourne 25 candidats"""
    ciphertext = "KHOOR"
    results = caesar_bruteforce(ciphertext)

    assert len(results) == 25


def test_brute_force_contains_solution():
    """Test que brute_force contient la bonne solution"""
    plaintext = "HELLO"
    key = 7
    ciphertext = caesar_encrypt(plaintext, key)

    results = caesar_bruteforce(ciphertext)
    found = any(text == plaintext for k, text in results)
    assert found



def test_zero_key():
    """Test avec clé = 0"""
    plaintext = "HELLO WORLD"
    key = 0

    ciphertext = caesar_encrypt(plaintext, key)
    assert ciphertext == plaintext


if __name__ == '__main__':
    print("Exécution des tests pour caesar.py...\n")

    tests = [
        test_encrypt_basic,
        test_decrypt_basic,
        test_roundtrip,
        test_preserve_case,
        test_preserve_nonalpha,
        test_empty_string,
        test_key_wraparound,
        test_brute_force_count,
        test_brute_force_contains_solution,
         
        test_zero_key,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            print(f"✅ {test.__name__}")
            passed += 1
        except Exception as e:
            print(f"❌ {test.__name__}: {e}")
            failed += 1

    print("\n================================")
    print(f"Résultats : {passed} réussis, {failed} échoués")
    print("================================")
