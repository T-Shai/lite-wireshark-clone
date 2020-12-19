"""
    PROJET RESEAUX
    19/10/2020

    traceparser.py
    
    Lecture du fichier d'entree .txt (trace wireshark)
    Pre-analyse du fichier / verification du formatage (souleve une erreur sinon avec la ligne)
    Extraction de l'information utile
"""

import os

# import interne
from utils import estHex
from exceptions import SyntaxeErreur, FichierNonTrouverErreur


def extraireTrames(lignes: list()):
    """
        extraireTrames(List[str]) -> list[list[str]]

        Retourne une liste de trames (liste de chaines de caractere représentant un octet) 
        
        Prends en entrée un fichier trace (typiquement l'hex dump de WireShark)
        en tronquant les chaines de caractere ne respectant pas le formatage et l'offset
        Apres verification du respect du formatage ainsi que de la taille 
    """

    # Nettoyage des lignes et récupération des données utiles
    lignes_utiles = list()
    nligneSource = 0
    for l in lignes:
        nligneSource += 1  # incrémentation du compteur de ligne

        lu = l.split()  # Separation de la ligne à chaque espace

        if lu == []:  # ligne vide
            continue

        if not estHex(lu[0]):
            continue
        # Supression de la ligne si elle ne commence pas
        # par une representation hexadecimal ou
        # Si les hex qui ne sont pas l'offset sont
        # de taille différent de 2
        temp = [lu[0]]
        temp.extend([octet for octet in lu[1:]
                     if estHex(octet) and len(octet) == 2])
        lu = temp

        # Supression de la ligne ne contenant qu'un hexadecimal
        if len(lu) == 1:
            continue

        # lignes_utiles contient un tuple :  la ligne utile (list[str]) et le numéro de la ligne source (int)
        lignes_utiles.append((lu, nligneSource))
    
    # Vérification du formatage des octets
    aTraiter = list()
    nLigneTotal = len(lignes_utiles)
    for nLigneUtile in range(nLigneTotal):

        # si ce n'est pas la derniere ligne
        if nLigneUtile != nLigneTotal - 1:

            # On ne prends pas en compte la ligne avant une nouvelle trame
            if lignes_utiles[nLigneUtile+1][0][0] == "0000":
                continue

            # Taille annoncee par la différence de offset
            tailleAnnoncee = int(lignes_utiles[nLigneUtile+1][0][0], 16) - int(lignes_utiles[nLigneUtile][0][0], 16)
            # Taille actuelle de la ligne en nombre d'octet
            tailleCourant = len(lignes_utiles[nLigneUtile][0]) - 1

            # La tailles annoncée est trop grande (perte d'information)
            if tailleAnnoncee > tailleCourant:
                raise SyntaxeErreur(
                    f"\n\nLigne {lignes_utiles[nLigneUtile][1]} : taille des octets de la ligne différents de la taille annoncée par les offsets \nTaille annoncé : {tailleAnnoncee}\t Taille réelle : {tailleCourant}")

            # la taille annoncée est plsu petite (surplus d'information à supprimer)
            if tailleAnnoncee < tailleCourant:
                # ligne à raccourcir
                aTraiter.append((nLigneUtile, tailleCourant - tailleAnnoncee))
    
    for nligne, surplus in aTraiter:
        # Supression des hex en trop à la fin  de la ligne
        lignes_utiles[nligne] = (lignes_utiles[nligne][0][:len(lignes_utiles[nligne])-surplus-2], lignes_utiles[1])

    # Liste contenant les différents trames extraits
    trames = list()
    # print(len(lignes_utiles))
    temp = list()
    # Suppression des offsets 
    # Separation des trames
    for lignes, _ in lignes_utiles:
        # print(f"\ntemp {len(temp)}\n", temp, f"\ntrames {len(trames)}\n", trames)
        # Detection d'une nouvelle trame
        if lignes[0] == "0000" and temp != list():
            trames.append(temp)
            temp = list()
        # supression de l'offset
        temp.append(lignes[1:])
    trames.append(temp)

    # Distribution dans une liste des octets
    listeOctets = list()
    # Applatissement des données
    for trame in trames:
        temp = list()
        for ligne in trame:
            temp.append(" ".join(ligne))
        temp = " ".join(temp).split()
        listeOctets.append(temp)
    
    return listeOctets

def extraireTramesG(lignes: list()):
    """
        extraireTrames(List[str]) -> list[list[str]]

        Retourne une liste de trames (liste de chaines de caractere représentant un octet) 
        
        Prends en entrée un fichier trace (typiquement l'hex dump de WireShark)
        en tronquant les chaines de caractere ne respectant pas le formatage et l'offset
        Apres verification du respect du formatage ainsi que de la taille 
    """

    # Nettoyage des lignes et récupération des données utiles
    lignes_utiles = list()
    nligneSource = 0
    for l in lignes:
        nligneSource += 1  # incrémentation du compteur de ligne

        lu = l.split()  # Separation de la ligne à chaque espace

        if lu == []:  # ligne vide
            continue

        if not estHex(lu[0]):
            continue
        # Supression de la ligne si elle ne commence pas
        # par une representation hexadecimal ou
        # Si les hex qui ne sont pas l'offset sont
        # de taille différent de 2
        temp = [lu[0]]
        temp.extend([octet for octet in lu[1:]
                     if estHex(octet) and len(octet) == 2])
        lu = temp

        # Supression de la ligne ne contenant qu'un hexadecimal
        if len(lu) == 1:
            continue

        # lignes_utiles contient un tuple :  la ligne utile (list[str]) et le numéro de la ligne source (int)
        lignes_utiles.append((lu, nligneSource))
    
    # Vérification du formatage des octets
    aTraiter = list()
    nLigneTotal = len(lignes_utiles)
    for nLigneUtile in range(nLigneTotal):

        # si ce n'est pas la derniere ligne
        if nLigneUtile != nLigneTotal - 1:

            # On ne prends pas en compte la ligne avant une nouvelle trame
            if lignes_utiles[nLigneUtile+1][0][0] == "0000":
                continue

            # Taille annoncee par la différence de offset
            tailleAnnoncee = int(lignes_utiles[nLigneUtile+1][0][0], 16) - int(lignes_utiles[nLigneUtile][0][0], 16)
            # Taille actuelle de la ligne en nombre d'octet
            tailleCourant = len(lignes_utiles[nLigneUtile][0]) - 1

            # La tailles annoncée est trop grande (perte d'information)
            if tailleAnnoncee > tailleCourant:
                return False, f"\n\nLigne {lignes_utiles[nLigneUtile][1]} : taille des octets de la ligne différents de la taille annoncée par les offsets \nTaille annoncé : {tailleAnnoncee}\t Taille réelle : {tailleCourant}"

            # la taille annoncée est plsu petite (surplus d'information à supprimer)
            if tailleAnnoncee < tailleCourant:
                # ligne à raccourcir
                aTraiter.append((nLigneUtile, tailleCourant - tailleAnnoncee))
    
    for nligne, surplus in aTraiter:
        # Supression des hex en trop à la fin  de la ligne
        lignes_utiles[nligne] = (lignes_utiles[nligne][0][:len(lignes_utiles[nligne])-surplus-2], lignes_utiles[1])

    # Liste contenant les différents trames extraits
    trames = list()
    # print(len(lignes_utiles))
    temp = list()
    # Suppression des offsets 
    # Separation des trames
    for lignes, _ in lignes_utiles:
        # print(f"\ntemp {len(temp)}\n", temp, f"\ntrames {len(trames)}\n", trames)
        # Detection d'une nouvelle trame
        if lignes[0] == "0000" and temp != list():
            trames.append(temp)
            temp = list()
        # supression de l'offset
        temp.append(lignes[1:])
    trames.append(temp)

    # Distribution dans une liste des octets
    listeOctets = list()
    # Applatissement des données
    for trame in trames:
        temp = list()
        for ligne in trame:
            temp.append(" ".join(ligne))
        temp = " ".join(temp).split()
        listeOctets.append(temp)
    
    return True, listeOctets

def lectureOctets(nomFichier: str):
    """
        LectureOctets(str) -> list[str]

        Ouvre le fichier avec le nom fourni et récupération d'octet
        de façon à ne generer que des erreurs comprehensibles en francais
    """

    # Nom de fichier non fourni
    if nomFichier.strip(" ") == "":
        raise FichierNonTrouverErreur("Fichier trace non fourni.")

    # Extension de fichier different de ".txt"
    _, extension = os.path.splitext(nomFichier)
    if extension.lower().strip(" ") != ".txt":
        raise FichierNonTrouverErreur(
            f"Le fichier {nomFichier} n'est pas en .txt mais {extension}.")

    lignes = list()
    # Ouverture du fichier
    try:
        with open(nomFichier, "r") as f:
            lignes = f.readlines()  # lecture des lignes

    # Fichier inexistant
    except FileNotFoundError:
        print(
            f"FichierNonTrouverErreur : Le fichier {nomFichier} est inexistant ou n'est pas dans le repertoire du programme.", file=os.sys.stderr)
        os.sys.exit(1)
    return extraireTrames(lignes)

def lectureOctetsG(nomFichier : str):
    # Nom de fichier non fourni
    if nomFichier.strip(" ") == "":
        return False, ("Fichier trace non fourni.")

    # Extension de fichier different de ".txt"
    _, extension = os.path.splitext(nomFichier)
    if extension.lower().strip(" ") != ".txt":
        return False,(f"Le fichier {nomFichier} n'est pas en .txt mais {extension}.")

    lignes = list()
    # Ouverture du fichier
    try:
        with open(nomFichier, "r") as f:
            lignes = f.readlines()  # lecture des lignes

    # Fichier inexistant
    except FileNotFoundError:
        return False, f"FichierNonTrouverErreur : Le fichier {nomFichier} est inexistant ou n'est pas dans le repertoire du programme."
    
    return extraireTramesG(lignes)