"""

    PROJET RESEAUX
    21/10/2020

    ethernet.py
    
    Fonctions permettant l'affichage de l'entete ethernet

"""

from utils import formatageMac, etherType


def trameEthernet(data: list):
    """
        trameEthernet(list[str]) -> list[str], str, bool

        Retourne la trame privee des 14 premiers bits et un string de retour
    """
    strOut = "\nEthernet :\n"
    # destination (6 bytes)
    destMac = "Destination (Adresse MAC) :\t" + formatageMac(data[:6])
    strOut += destMac+"\n"
    # source (6 bytes)
    srcMac = "Source (Adresse MAC) :\t\t"+formatageMac(data[6:12])
    strOut += srcMac+"\n"
    # type (2 bytes)
    eType, estIPV4 = etherType(data[12:14])
    strOut += eType+"\n"

    return data[14:], strOut, estIPV4

def trameEthernetG(data: list):
    """
        trameEthernetG(list[str]) -> list[str], str, bool

        Version graphique
        Retourne la trame privee des 14 premiers bits et un string de retour
    """
    
    # destination (6 bytes)
    destMac = "Destination (Adresse MAC) :\t" + formatageMac(data[:6])
    # source (6 bytes)
    srcMac = "Source (Adresse MAC) :\t\t"+formatageMac(data[6:12])
    # type (2 bytes)
    eType, estIPV4 = etherType(data[12:14])

    return data[14:], [destMac, srcMac, eType] , estIPV4