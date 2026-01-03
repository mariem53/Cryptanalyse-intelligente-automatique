#!/usr/bin/env python3
"""
crack_caesar.py - Cryptanalyse Automatique du Chiffrement de César

Ce script implémente une attaque intelligente combinant :
- Force brute (test de toutes les clés 1-25)
- Analyse fréquentielle (Chi², Indice de Coïncidence)
- Analyse linguistique (détection de stopwords)
- Métriques secondaires (longueur mots, ratio alphabétique)

"""

import sys
import os
import argparse
import re
from collections import Counter

# Ajouter le répertoire parent au path pour importer les modules crypto
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.bruteforce import caesar_bruteforce
from crypto.scoring import load_stopwords, tokenize
from crypto.frequency import chi_squared_test, index_of_coincidence


# ═══════════════════════════════════════════════════════════════
# FONCTIONS D'ANALYSE LINGUISTIQUE
# ═══════════════════════════════════════════════════════════════

def stopwords_stats(text, stopwords):
    """
    Calcule les statistiques de stopwords dans le texte.
    
    Args:
        text (str): Le texte à analyser
        stopwords (set): Ensemble de stopwords de référence
        
    Returns:
        tuple: (nombre_stopwords, nombre_total_mots, pourcentage)
        
    Exemple:
        >>> stopwords = {"the", "and", "is"}
        >>> stopwords_stats("the cat and the dog", stopwords)
        (3, 5, 60.0)
    """
    words = tokenize(text)  # Extrait tous les mots (minuscules)
    n_total = len(words)
    
    # Compter combien de mots sont dans la liste de stopwords
    n_stop = sum(1 for w in words if w in stopwords)
    
    # Calculer le pourcentage
    pct = (n_stop / n_total * 100) if n_total > 0 else 0
    
    return n_stop, n_total, round(pct, 2)


def avg_word_length(text):
    """
    Calcule la longueur moyenne des mots dans le texte.
    
    Les langues naturelles ont une longueur moyenne de ~5 lettres.
    Un texte avec une moyenne de 2 ou 12 lettres est suspect.
    
    Args:
        text (str): Le texte à analyser
        
    Returns:
        float: Longueur moyenne arrondie à 2 décimales
    """
    words = tokenize(text)
    if not words:
        return 0
    return round(sum(len(w) for w in words) / len(words), 2)


def alpha_ratio(text):
    """
    Calcule le pourcentage de caractères alphabétiques.
    
    Un texte naturel contient généralement 80-95% de lettres.
    Un ratio de 30% indique un problème (beaucoup de chiffres/symboles).
    
    Args:
        text (str): Le texte à analyser
        
    Returns:
        float: Pourcentage de lettres (0-100)
    """
    letters = [c for c in text if c.isalpha()]
    total = len(text)
    return round(len(letters) / total * 100, 2) if total > 0 else 0


# ═══════════════════════════════════════════════════════════════
# SYSTÈME DE SCORING AMÉLIORÉ
# ═══════════════════════════════════════════════════════════════

def compute_normalized_score(n_stop, pct_stop, chi2, ic, avg_len, alpha_r):
    """
    Calcule un score normalisé combinant toutes les métriques.
    
    Args:
        n_stop (int): Nombre de stopwords détectés
        pct_stop (float): Pourcentage de stopwords (0-100)
        chi2 (float): Chi² (distance avec fréquences de référence)
        ic (float): Indice de coïncidence (0-0.1 typiquement)
        avg_len (float): Longueur moyenne des mots
        alpha_r (float): Ratio alphabétique (0-100)
        
    Returns:
        float: Score final sur 100
        
    Pondération:
        - Stopwords : 40% (le plus discriminant)
        - Chi² : 30% (solide mais peut être trompé)
        - IC : 15% (utile pour mono/poly-alphabétique)
        - Longueur mots : 10% (indicateur faible)
        - Ratio alpha : 5% (sanity check)
    """
    
    # ─────────────────────────────────────────────────────────
    # 1. NORMALISATION DES MÉTRIQUES (toutes entre 0 et 1)
    # ─────────────────────────────────────────────────────────
    
    # Stopwords : on considère 50% comme excellent
    # Un texte avec 60% de stopwords = score 1.0
    score_stopwords = min(pct_stop / 50, 1.0)
    
    # Chi² : un bon texte a χ² < 50, excellent < 20
    # On normalise avec un plafond à 200 (au-delà = bruit)
    score_chi2 = max(0, 1 - chi2 / 200)
    
    # Indice de Coïncidence : 0.065 pour anglais, 0.074 pour français
    # On normalise avec 0.070 comme référence
    score_ic = min(ic / 0.070, 1.0)
    
    # Longueur moyenne : idéal = 5 lettres
    # On pénalise les écarts (2 lettres ou 10 lettres = suspect)
    score_avg_len = max(0, 1 - abs(5 - avg_len) / 5)
    
    # Ratio alphabétique : on attend au moins 80%
    # 100% = parfait, 50% = suspect
    score_alpha = alpha_r / 100
    
    # ─────────────────────────────────────────────────────────
    # 2. COMBINAISON PONDÉRÉE
    # ─────────────────────────────────────────────────────────
    
    score_final = (
        40 * score_stopwords +  # Poids le plus fort
        30 * score_chi2 +        # Deuxième critère important
        15 * score_ic +          # Aide à différencier les types
        10 * score_avg_len +     # Critère secondaire
        5 * score_alpha          # Juste un garde-fou
    )
    
    return round(score_final, 2)


# ═══════════════════════════════════════════════════════════════
# FONCTION PRINCIPALE
# ═══════════════════════════════════════════════════════════════

def main():
    """
    Point d'entrée principal du programme.
    
    Processus:
    1. Charger le texte chiffré
    2. Charger les stopwords FR/EN
    3. Tester toutes les clés (1-25)
    4. Calculer toutes les métriques pour chaque candidat
    5. Classer les résultats par score
    6. Afficher et sélectionner le meilleur
    """
    
    # ─────────────────────────────────────────────────────────
    # PARSING DES ARGUMENTS
    # ─────────────────────────────────────────────────────────
    parser = argparse.ArgumentParser(
        description="Attaque automatique du chiffrement de César",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python crack_caesar.py --input data/challenge1.txt
  python crack_caesar.py --input data/challenge1.txt --top 3
  python crack_caesar.py --input message.txt --top 10
        """
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Chemin vers le fichier contenant le texte chiffré"
    )
    parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="Nombre de meilleurs résultats à afficher (défaut: 5)"
    )
    args = parser.parse_args()
    
    # ─────────────────────────────────────────────────────────
    # CHARGEMENT DU TEXTE CHIFFRÉ
    # ─────────────────────────────────────────────────────────
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            ciphertext = f.read()
        print(f"✅ Texte chiffré chargé ({len(ciphertext)} caractères)")
    except FileNotFoundError:
        print(f"❌ Erreur : Fichier '{args.input}' introuvable")
        sys.exit(1)
    
    # ─────────────────────────────────────────────────────────
    # CHARGEMENT DES STOPWORDS
    # ─────────────────────────────────────────────────────────
    try:
        stop_fr = load_stopwords("data/stopwords_fr.txt")
        stop_en = load_stopwords("data/stopwords_en.txt")
        print(f"✅ Stopwords chargés (FR: {len(stop_fr)}, EN: {len(stop_en)})")
    except FileNotFoundError as e:
        print(f"❌ Erreur : Fichier de stopwords manquant - {e}")
        sys.exit(1)
    
    # ─────────────────────────────────────────────────────────
    # ATTAQUE PAR FORCE BRUTE
    # ─────────────────────────────────────────────────────────
    print("\n🔓 Lancement de l'attaque par force brute...")
    candidates = caesar_bruteforce(ciphertext)
    print(f"✅ {len(candidates)} clés testées (1-25)\n")
    
    # ─────────────────────────────────────────────────────────
    # ANALYSE DE CHAQUE CANDIDAT
    # ─────────────────────────────────────────────────────────
    results = []
    
    for key, plaintext in candidates:
        # Pour chaque langue (français et anglais)
        for lang, stopwords in [("fr", stop_fr), ("en", stop_en)]:
            
            # Calcul de toutes les métriques
            n_stop, n_total, pct_stop = stopwords_stats(plaintext, stopwords)
            chi2 = chi_squared_test(plaintext, language=lang)
            ic = index_of_coincidence(plaintext)
            avg_len = avg_word_length(plaintext)
            alpha_r = alpha_ratio(plaintext)
            
            # Score normalisé amélioré
            score = compute_normalized_score(
                n_stop, pct_stop, chi2, ic, avg_len, alpha_r
            )
            
            # Stockage du résultat
            results.append({
                "key": key,
                "language": lang,
                "plaintext": plaintext,
                "n_stop": n_stop,
                "n_total": n_total,
                "pct_stop": pct_stop,
                "chi2": chi2,
                "ic": ic,
                "avg_len": avg_len,
                "alpha_ratio": alpha_r,
                "score": score
            })
    
    # ─────────────────────────────────────────────────────────
    # TRI PAR SCORE DÉCROISSANT
    # ─────────────────────────────────────────────────────────
    results_sorted = sorted(results, key=lambda x: x["score"], reverse=True)
    
    # ═════════════════════════════════════════════════════════
    # AFFICHAGE DES RÉSULTATS
    # ═════════════════════════════════════════════════════════
    
    # ─────────────────────────────────────────────────────────
    # 1️⃣ TOUS LES RÉSULTATS (pour debug/analyse)
    # ─────────────────────────────────────────────────────────
    print("\n" + "="*70)
    print("🔍 TOUS LES RÉSULTATS (50 candidats = 25 clés × 2 langues)")
    print("="*70)
    
    for r in results_sorted:
        print(f"🔑 Clé: {r['key']:2d} | 🌍 {r['language'].upper()} | "
              f"Stopwords: {r['n_stop']:3d}/{r['n_total']:3d} ({r['pct_stop']:5.1f}%) | "
              f"Chi²: {r['chi2']:6.1f} | IC: {r['ic']:.4f} | "
              f"AvgLen: {r['avg_len']:.1f} | Alpha: {r['alpha_ratio']:.0f}% | "
              f"Score: {r['score']:5.1f}/100")
        # Afficher les 150 premiers caractères du texte
        preview = r["plaintext"][:150].replace('\n', ' ')
        print(f"   {preview}...")
        print("-"*70)
    
    # ─────────────────────────────────────────────────────────
    # 2️⃣ TOP N RÉSULTATS (selon --top)
    # ─────────────────────────────────────────────────────────
    print("\n" + "="*70)
    print(f"🏆 TOP {args.top} MEILLEURS RÉSULTATS")
    print("="*70)
    
    for i, r in enumerate(results_sorted[:args.top], 1):
        print(f"\n{'─'*70}")
        print(f"RANG #{i}")
        print(f"{'─'*70}")
        print(f"🔑 Clé        : {r['key']}")
        print(f"🌍 Langue     : {r['language'].upper()}")
        print(f"📊 Score      : {r['score']:.1f}/100")
        print(f"")
        print(f"📈 MÉTRIQUES DÉTAILLÉES:")
        print(f"   • Stopwords    : {r['n_stop']}/{r['n_total']} ({r['pct_stop']:.1f}%)")
        print(f"   • Chi²         : {r['chi2']:.2f} (plus bas = mieux)")
        print(f"   • IC           : {r['ic']:.4f} (0.065 = anglais, 0.074 = français)")
        print(f"   • Longueur moy : {r['avg_len']:.1f} lettres/mot")
        print(f"   • Ratio alpha  : {r['alpha_ratio']:.1f}%")
        print(f"")
        print(f"📄 APERÇU DU TEXTE:")
        # Afficher les 400 premiers caractères
        preview = r["plaintext"][:400]
        print(f"{preview}...")
    
    # ─────────────────────────────────────────────────────────
    # 3️⃣ DÉCISION AUTOMATIQUE (meilleur score)
    # ─────────────────────────────────────────────────────────
    best = results_sorted[0]
    
    print("\n" + "="*70)
    print("✅ DÉCISION AUTOMATIQUE - RÉSULTAT FINAL")
    print("="*70)
    print(f"")
    print(f"🎯 SOLUTION RETENUE:")
    print(f"   🔑 Clé      : {best['key']}")
    print(f"   🌍 Langue   : {best['language'].upper()}")
    print(f"   📊 Score    : {best['score']:.1f}/100")
    print(f"")
    print(f"📈 JUSTIFICATION:")
    print(f"   Cette solution obtient le score le plus élevé grâce à:")
    print(f"   • {best['pct_stop']:.0f}% de stopwords reconnus ({best['n_stop']} mots)")
    print(f"   • Chi² de {best['chi2']:.1f} (proximité avec {best['language']} naturel)")
    print(f"   • Indice de coïncidence de {best['ic']:.4f}")
    print(f"")
    print(f"📄 TEXTE CLAIR COMPLET:")
    print(f"{'─'*70}")
    print(best["plaintext"])
    print(f"{'─'*70}")
    
    # ─────────────────────────────────────────────────────────
    # STATISTIQUES FINALES
    # ─────────────────────────────────────────────────────────
    print(f"\n📊 STATISTIQUES:")
    print(f"   • Candidats analysés : {len(results)}")
    print(f"   • Meilleur score     : {best['score']:.1f}/100")
    print(f"   • Écart avec 2ème    : {best['score'] - results_sorted[1]['score']:.1f} points")
    
    # Indice de confiance basé sur l'écart avec le 2ème
    gap = best['score'] - results_sorted[1]['score']
    if gap > 10:
        confidence = "TRÈS HAUTE ✅"
    elif gap > 5:
        confidence = "HAUTE ✓"
    elif gap > 2:
        confidence = "MOYENNE ~"
    else:
        confidence = "FAIBLE ⚠️ (vérifier manuellement)"
    
    print(f"   • Confiance          : {confidence}")
    print("")


# ═══════════════════════════════════════════════════════════════
# POINT D'ENTRÉE
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    main()