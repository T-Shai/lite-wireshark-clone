"""

    PROJET RESEAUX
    21/10/2020

    ethernet.py
    
    Fonctions permettant l'affichage de l'entete ethernet

"""

def formatageMac(mac: list):
    """
        formatageMac(list[str]) -> str

        Format les octets en format adresse mac
    """
    return ":".join(mac)



def etherType(data: list):
    """
        etherType(list[str]) -> str

        retourne les types IPV4, IPV6, ARP ou INCONNU
    """
    HexEType = "".join(data)
    strType = "INCONNU"
    if HexEType.lower() == "0800":
        strType = "IPV4"
    elif HexEType.lower() == "0806":
        strType = "ARP REQUEST/RESPONSE"
    elif HexEType.lower() == "86dd":
        strType = "IPV6"

    return f"Type Ethernet :\t\t\t{strType} (0x{HexEType})"


def trameEthernet(data: list):
    """
        trameEthernet(list[str]) -> list[str]

        Affiche l'entete Ethernet

        Retourne la trame privee des 14 premiers bits
    """

    # destination (6 bytes)
    destMac = "Destination (Adresse MAC) :\t" + formatageMac(data[:6])
    print(destMac)
    # source (6 bytes)
    srcMac = "Source (Adresse MAC) :\t\t"+formatageMac(data[6:12])
    print(srcMac)
    # type (2 bytes)
    eType = etherType(data[12:14])
    print(eType)

    return data[14:]