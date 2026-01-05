# 🔐 Breaking the Code - Cryptanalyse Intelligente Automatique

## 📋 Description

Outil de cryptanalyse automatique capable d'analyser un message chiffré **sans connaissance préalable de la clé** et de proposer automatiquement le texte clair le plus probable.

Ce projet simule le travail d'un analyste en cybersécurité face à un message intercepté, en utilisant des techniques statistiques et linguistiques avancées.

---

## 🎯 Objectifs du Projet

✅ Tester automatiquement plusieurs hypothèses de déchiffrement  
✅ Évaluer la qualité linguistique des résultats obtenus  
✅ Sélectionner automatiquement la solution la plus crédible  
✅ Fournir une décision claire et justifiée à un humain  

---

## 🏗️ Architecture du Projet

```
MINI_PROJET1/
├── crypto/                  # Modules de cryptographie
│   ├── caesar.py           # Chiffrement/déchiffrement César
│   ├── bruteforce.py       # Attaque par force brute
│   ├── frequency.py        # Analyse fréquentielle (Chi², IC)
│   └── scoring.py          # Évaluation linguistique (stopwords)
├── bin/
│   └── crack_caesar.py     # 🎯 Script principal d'attaque
├── data/
│   ├── stopwords_fr.txt    # Mots vides français (le, la, de...)
│   ├── stopwords_en.txt    # Mots vides anglais (the, and, of...)
│   ├── sample_plain.txt    # Texte d'exemple
│   └── challenge1.txt      # Message chiffré à casser
├── tests/
│   └── test_caesar.py      # Tests unitaires
└── README.md               # Ce fichier
```

---

## 🚀 Installation et Utilisation

### Prérequis
- Python 3.13.3


### Utilisation Basique

```bash
# Attaquer un message chiffré
python bin/crack_caesar.py --input data/challenge1.txt

# Afficher seulement les 3 meilleurs résultats
python bin/crack_caesar.py --input data/challenge1.txt --top 3
```


---
Projet réalisé dans le cadre du cours de Sécurité informatique  

---

