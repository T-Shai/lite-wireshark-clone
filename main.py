"""
    PROJET RESEAUX
    19/10/2020

    main.py

    test / point d'entree
"""
# traceparser : récupération des trames via un fichier trace txt (hex dump de Wireshark)
from traceparser import lectureOctets

from core import ProtocolAnalyser

import os # pour la recuperation des arguments terminales

# Point d'entree du programme
def main(args : list):
    largs = len(args)
    if largs != 2:
        print(\
f"""
Utilisation : 
    {args[0]} <chemain/nom du fichier trace>
""")
        exit(1)
    
    pa = ProtocolAnalyser(args[1])
    print(pa.analyse()[0])
        
    
if __name__ == "__main__":
    _DEBUG = True
    if not _DEBUG:
        os.sys.tracebacklimit = 0  # Permet de ne pas afficher le traceback en production

    main(os.sys.argv)