"""
    PROJET RESEAUX
    19/10/2020

    utils.py
    
    Contient les fonctions utilitaires du projet
"""

def estHex(s: str):
    """
        Retourne True si le string fourni peut etre interprete comme un hexadeciaml, False sinon

        Verifie si la chaine de caractere fourni est la representation d'un hexadecimal
        On convertie en entier
        Si l'entier est bien cree, retourne vrai
        Sinon on attrape le ValueError et on retourne faux
    """
    try:
        int(s, 16)
        return True
    except ValueError:
        return False