from collections import Counter

# ==========================
# FRÉQUENCES FRANÇAISES (%)
# ==========================
FRENCH_FREQ = {
    'a': 7.64, 'b': 0.90, 'c': 3.26, 'd': 3.67, 'e': 14.71,
    'f': 1.06, 'g': 0.87, 'h': 0.74, 'i': 7.53, 'j': 0.61,
    'k': 0.05, 'l': 5.46, 'm': 2.97, 'n': 7.10, 'o': 5.38,
    'p': 3.02, 'q': 1.36, 'r': 6.55, 's': 7.95, 't': 7.24,
    'u': 6.31, 'v': 1.84, 'w': 0.07, 'x': 0.43, 'y': 0.13, 'z': 0.33
}

# ==========================
# FRÉQUENCES ANGLAISES (%)
# ==========================
ENGLISH_FREQ = {
    'a': 8.17, 'b': 1.49, 'c': 2.78, 'd': 4.25, 'e': 12.70,
    'f': 2.23, 'g': 2.02, 'h': 6.09, 'i': 6.97, 'j': 0.15,
    'k': 0.77, 'l': 4.03, 'm': 2.41, 'n': 6.75, 'o': 7.51,
    'p': 1.93, 'q': 0.10, 'r': 5.99, 's': 6.33, 't': 9.06,
    'u': 2.76, 'v': 0.98, 'w': 2.36, 'x': 0.15, 'y': 1.97, 'z': 0.07
}


# ==========================
# FRÉQUENCE DES LETTRES
# ==========================
def letter_frequency(text):
    """
    Calcule la fréquence (%) de chaque lettre
    """
    text = [c.lower() for c in text if c.isalpha()]
    total = len(text)

    if total == 0:
        return {}

    count = Counter(text)
    return {l: round((count[l] / total) * 100, 2) for l in 'abcdefghijklmnopqrstuvwxyz'}


# ==========================
# TEST DU KHI-DEUX
# ==========================
def chi_squared_test(text, language='fr'):
    """
    Test du χ² pour mesurer la proximité avec une langue
    """
    freq_ref = FRENCH_FREQ if language == 'fr' else ENGLISH_FREQ
    freq_obs = letter_frequency(text)

    chi2 = 0
    for letter, expected in freq_ref.items():
        observed = freq_obs.get(letter, 0)
        if expected > 0:
            chi2 += (observed - expected) ** 2 / expected

    return round(chi2, 2)


# ==========================
# INDICE DE COÏNCIDENCE
# ==========================
def index_of_coincidence(text):
    """
    Mesure si le texte est mono-alphabétique ou non
    """
    text = [c.lower() for c in text if c.isalpha()]
    N = len(text)

    if N <= 1:
        return 0.0

    count = Counter(text)
    ic = sum(v * (v - 1) for v in count.values()) / (N * (N - 1))

    return round(ic, 4)


# ==========================
# DÉTECTION AUTOMATIQUE DE LANGUE
# ==========================
def detect_language(text):
    """
    Détecte la langue la plus probable (fr / en)
    """
    chi_fr = chi_squared_test(text, 'fr')
    chi_en = chi_squared_test(text, 'en')

    return 'fr' if chi_fr < chi_en else 'en'
def frequency_attack_vigenere(subtext, language='en'):
    """
    Trouve la meilleure lettre de clé pour un sous-texte Vigenère
    en testant les 26 décalages (César)
    """
    best_shift = 0
    best_chi2 = float('inf')

    for shift in range(26):
        decrypted = ""
        for c in subtext:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                decrypted += chr((ord(c) - base - shift) % 26 + base)
            else:
                decrypted += c

        chi2 = chi_squared_test(decrypted, language)
        if chi2 < best_chi2:
            best_chi2 = chi2
            best_shift = shift

    return chr(ord('a') + best_shift)
