import re

def load_stopwords(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return set(word.strip().lower() for word in f)

def tokenize(text: str):
    return re.findall(r"[a-zA-Z]+", text.lower())

def stopwords_score(text: str, stopwords: set) -> int:
    words = tokenize(text)
    return sum(1 for w in words if w in stopwords)


def detect_language(text: str, stop_fr: set, stop_en: set):
    """Retourne la langue et le score le plus élevé"""
    score_fr = stopwords_score(text, stop_fr)
    score_en = stopwords_score(text, stop_en)

    if score_fr > score_en:
        return "fr", score_fr
    else:
        return "en", score_en

def score_language(text, stopwords: set) -> int:
    words = text.lower().split()
    return sum(1 for w in words if w in stopwords)
