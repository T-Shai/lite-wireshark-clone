"""
    PROJET RESEAUX
    19/10/2020

    core.py

    Contient la class analyser un wrapper object
    Sur les différents fonctions d'analyse
"""

from traceparser import lectureOctets   # Lecture des octets depuis un fichier
from ethernet import trameEthernet      # Recuperation des trames ethernets
from ipv4 import trameIpv4
from tcp import trameTCP
from http1 import trameHTTP1

class ProtocolAnalyser:
    """
        ProtocolAnalyser va récupérer et analyser la trame

        En utilisant les différents fonctions d'analyse
    """
    END = "\nTRAME ANALYSEE\n"
    SEPARATOR = "--"*6+"\n\t"
    def __init__(self, nomFichier : str):
        """
            ProtocolAnalyser(nomFichier : str) -> ProtocolAnalyser Object

            nomFichier
        """
        self.nFichier = nomFichier                              # Nom du fichier de trame
        self.strOut = f"Analyse du fichier {self.nFichier} :\n" # sortie fichier

        self.trames = lectureOctets(nomFichier)                 # récupere les trames sous forme d'une liste

    
    def analyse(self):
        """
            ProtocolAnalyser.analyse() -> list[str]

            Retourne une liste de str repésentant
            l'analyse
        """
        strOuts = list()
        for numTrame, trame in enumerate(self.trames):
            # Analyse de la trame ethernet
            trame, strOut, estIPV4 = trameEthernet(trame)
            strOut.replace("\n", "\n\t")
            # on verifie que la trame ip est bien de la
            # version 4
            if not estIPV4:
                strOut += "Seule la version IPV4 est implémentée :("+ProtocolAnalyser.END
                strOuts.append(strOut)
                continue    # passage a la prochaine trame
            else:
                strOut += ProtocolAnalyser.SEPARATOR
                trame, strOut, estTCP = trameIpv4(trame, strOut)
                if not estTCP:
                    strOut += "Seul le protocol TCP est implémentée :("+ProtocolAnalyser.END
                    strOuts.append(strOut)
                    continue    # passage a la prochaine trame
                else:
                    strOut += ProtocolAnalyser.SEPARATOR
                    trame, strOut = trameTCP(trame, strOut)

                    strOut += ProtocolAnalyser.SEPARATOR
                    trame, strOut, estHTTP1 = trameHTTP1(trame, strOut)
            strOuts.append(strOut)
        return strOuts