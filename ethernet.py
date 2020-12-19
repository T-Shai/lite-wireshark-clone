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
    strMacAdrr =  ":".join(mac)
    if strMacAdrr.lower() == "ff:ff:ff:ff:ff:ff":
        strMacAdrr += " (Broadcast)"
    
    return strMacAdrr



def etherType(data: list):
    """
        etherType(list[str]) -> str

        retourne les types IPV4, IPV6, ARP ou INCONNU
    """
    HexEType = "".join(data)
    strType = "INCONNU"
    estIPV4 = False
    if HexEType.lower() == "0800":
        strType = "IPV4"
        estIPV4 = True
    elif HexEType.lower() == "0806":
        strType = "ARP REQUEST/RESPONSE"
    elif HexEType.lower() == "86dd":
        strType = "IPV6"

    return f"Type Ethernet :\t\t{strType} (0x{HexEType})", estIPV4


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