"""
    PROJET RESEAUX
    19/10/2020

    ipv4.py

    fonctions afficheurs IPV4
"""
def getId(l):
    h = "0x"+"".join(l)
    i = int(h, 16)
    return f"{h} ({str(i)})"

def getFlags(l):
    flags = "0x"+"".join(l)
    n = int(l[0][0])
    rb, df, mf = ("Set" if i=="1" else "Not set" for i in bin(n)[2:])
    offset = "0x"+l[0][1]+"".join(l[1])
    n_offset = int(offset, 16)
    return flags, rb, df, mf, f"{n_offset} ({offset})"

def formatIP(l):
    return ".".join([str(int(i,16)) for i in l])

def trameIpv4(trame : list, strOut : str) ->(list, str, bool):
    """
        trameIpv4(list[str], str) -> (list[str], str, bool)
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
    s = "\nIPV4 :\n"
    s+=f"""Version\t\t:\t{version}
Header Length\t:\t{header_length}
TOS\t\t:\t{tos}
Identification\t:\t{identification}

Flags\t\t:\t{flags}

    Reserved bit  : {rb}
    Don't Fragment: {df}
    More Fragments: {mf}


Fragment offset\t:\t{offset}
Time to live\t:\t{ttl}
Protocol\t:\t{protocol}
Checksum\t:\t{checksum}

Source\t\t:\t{source}
Destination\t:\t{desti}
"""
    strOut += s
    return trame[20:], strOut, isTCP