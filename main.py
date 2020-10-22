"""
    PROJET RESEAUX
    19/10/2020

    main.py

    Fichier script permettant l'execution du programme
"""
# traceparser : récupération des trames via un fichier trace txt (hex dump de Wireshark)
from traceparser import lectureOctets

# ethernet : affichage des entêtes ethernet
from ethernet import trameEthernet
 
import os # pour la recuperation des arguments terminales

# Point d'entree du programme
def main(args : list):
    largs = len(args)
    if largs != 2:
        print(\
f"""
Usage : 
    {args[0]} <chemain/nom du fichier trace>
""")
    for trame in lectureOctets(args[1]):
        print(trame[:20])
        trameEthernet(trame)
    
if __name__ == "__main__":
    _DEBUG = True
    if not _DEBUG:
        os.sys.tracebacklimit = 0  # Permet de ne pas afficher le traceback en production

    main(os.sys.argv)