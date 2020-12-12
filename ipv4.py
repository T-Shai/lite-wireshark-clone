"""
    PROJET RESEAUX
    19/10/2020

    ipv4.py

    fonctions analyseur IPV4
"""
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

def trameIpv4(trame : list, strOut : str) ->(list, str, bool):
    """
        trameIpv4(list[str], str) -> (list[str], str, bool)

        retourne l'analyse de la trame IPV4 et retourne les données
        encapsulées
    """
    version = trame[0][0]

    header_length = str(int(trame[0][1])*4) + f" ({trame[0][1]})"

    tos = trame[1]

    total_length = str(int("".join(trame[2:4]), 16))

    identification = getId(trame[4:6])

    flags, rb, df, mf, offset = getFlags(trame[6:8])

    ttl = int("".join(trame[8:9]), 16)

    protocol = int("".join(trame[9:10]), 16)

    isTCP = False
    if protocol == 6:
        protocol = "TCP (6)"
        isTCP = True
    else:
        protocol = f"Protocole non pris en charge ({protocol})"

    checksum = "0x"+"".join(trame[10:12])

    source = formatIP(trame[12:16])

    desti = formatIP(trame[16:20])

    s=f"""\nIPV4
Version         :  {version}
Header Length   :  {header_length}
TOS             :  {tos}
Total Length    :  {total_length}
Identification  :  {identification}

Flags           : {flags}

    Reserved bit  : {rb}
    Don't Fragment: {df}
    More Fragments: {mf}


Fragment offset   : {offset}
Time to live      : {ttl}
Protocol          : {protocol}
Checksum          : {checksum}

Source            : {source}
Destination       : {desti}
"""
    strOut += s
    return trame[20:], strOut, isTCP