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


def execfile(filepath, globals=None, locals=None):
    if globals is None:
        globals = {}
    globals.update({
        "__file__": filepath,
        "__name__": "__main__",
    })
    with open(filepath, 'rb') as file:
        exec(compile(file.read(), filepath, 'exec'), globals, locals)

# Point d'entree du programme
def main(args : list):
    largs = len(args)
    if largs > 2 :
        print(\
f"""
Utilisation :
    Textuel :
    {args[0]} <chemain/nom du fichier trace>

    Graphique :
    {args[0]}
""")
        exit(1)
    
    if largs == 1:
        execfile("gui.py")
    if largs == 2:
        # mode textuel
        pa = ProtocolAnalyser(args[1])
        strOuts = pa.analyse()
        s = ""
        for n, i in enumerate(strOuts):
            s+= "\nTrame n"+ str(n)+"\n"
            print("\nTrame n", n)
            s+= i
            print(i)
        
    print("\n Voulez vous sauvegarder la trame ? (y/n)\n")
    ans = input("ans : ")
    if ans.lower() == "y":
        fname ="output-"+ str(hash(s))+".txt"
        with open(fname, 'w') as f:
            f.write(s)
        print("Enregistré en tant que "+fname)
        

if __name__ == "__main__":
    _DEBUG = True
    if not _DEBUG:
        os.sys.tracebacklimit = 0  # Permet de ne pas afficher le traceback en production

    main(os.sys.argv)