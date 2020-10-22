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

if __name__ == "__main__":
    _DEBUG = True
    if not _DEBUG:
        os.sys.tracebacklimit = 0  # Permet de ne pas afficher le traceback en production
        
    for trame in lectureOctets("tracepublic/TCP2.txt"):
        print(trame[:20])
        trameEthernet(trame)