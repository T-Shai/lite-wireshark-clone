"""
    PROJET RESEAUX
    19/10/2020

    ipv4.py

    fonctions analyseur IPV4
"""

from utils import getId, getFlags, formatIP

def trameIpv4(trame : list, strOut : str) ->(list, str, bool):
    """
        trameIpv4(list[str], str) -> (list[str], str, bool)

        retourne l'analyse de la trame IPV4 et retourne les données
        encapsulées
    """
    version = trame[0][0]

    header_length = str(int(trame[0][1])*4) + f" ({trame[0][1]})"
    hl = int(trame[0][1])*4

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

    options_padding = trame[20:hl]

    opt = "Cette partie IPV4 ne contient pas d'options !"
    if options_padding != list():

        opt = "Cette partie IPV4 contient des options et potentionellement du bourrage !"

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

Options + padding : {opt}
"""
    strOut += s
    return trame[hl:], strOut, isTCP

def trameIpv4G(trame : list) ->(list, str, bool):
    """
        trameIpv4(list[str], str) -> (list[str], str, bool)

        VERSION GRAPHIQUE

        retourne l'analyse de la trame IPV4 et retourne les données
        encapsulées
    """
    version = trame[0][0]

    header_length = str(int(trame[0][1])*4) + f" ({trame[0][1]})"
    hl = int(trame[0][1])*4

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

    options_padding = trame[20:hl]
    
    opt = "Cette partie IPV4 ne contient pas d'options !"
    if options_padding != list():
        opt = "Cette partie IPV4 contient des options et potentionellement du bourrage !"

    s =[
        f"Version         :   \t{version}",
        f"Header Length   :   \t{header_length}",
        f"TOS             :   \t{tos}",
        f"Total Length    :   \t{total_length}",
        f"Identification  :   \t{identification}",
        f"Flags           :   \t{flags}",
        f"    Reserved bit  : \t{rb}",
        f"    Don't Fragment: \t {df}",
        f"    More Fragments: \t {mf}",
        f"Fragment offset   : \t{offset}",
        f"Time to live      : \t{ttl}",
        f"Protocol          : \t{protocol}",
        f"Checksum          : \t{checksum}",
        f"Source            : \t{source}",
        f"Destination       : \t{desti}",
        f"options + padding : \t{opt}"
    ]

    return trame[hl:], s, isTCP,source, desti