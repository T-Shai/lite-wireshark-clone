"""
    PROJET RESEAUX
    19/10/2020

    utils.py
    
    Contient les fonctions utilitaires du projet
"""

# parser

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

# ethernet

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

# ipv4

def getId(l: list) -> str:
    """
        getId(list[str]) -> str

        Representation hex et decimale d'une trame IP 
    """
    h = "0x"+"".join(l)
    i = int(h, 16)
    return f"{h} ({str(i)})"

def getFlags(l: list) -> list:
    """
        getFlags(list[str]) -> list

        retourne une representation textuel

            - les flags en hexa
            - reserved bit
            - dont fragement
            - more fragment
            - offset
    """
    flags = "0x"+"".join(l)
    n = int(l[0][0])
    b = bin(n).split("b")[1].zfill(4)[:-1]
    rb, df, mf = ("Set" if i=="1" else "Not set" for i in b)
    offset = "0x"+l[0][1]+"".join(l[1])
    n_offset = int(offset, 16)
    return flags, rb, df, mf, f"{n_offset} ({offset})"

def formatIP(l):
    """
        formatIP(list[str]) -> str

        Formate en representation IP
    """
    return ".".join([str(int(i,16)) for i in l])