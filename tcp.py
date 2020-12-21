"""
    PROJET RESEAUX
    9/12/2020

    tcp.py

    fonctions analyseur de TCP
"""

def getFlags(b):
    """ 
        fonction qui prend en entre un binaire et qui renvoi les differents flags 
    """
    reserved = "Set" if int(b[:3], 2) != 0 else "Not Set"
    urg = "Set" if b[6] == "1" else "Not Set"
    ack = "Set" if b[7] == "1" else "Not Set"
    psh = "Set" if b[8] == "1" else "Not Set"
    rst = "Set" if b[9] == "1" else "Not Set"
    syn = "Set" if b[10] == "1" else "Not Set"
    fin = "Set" if b[11] == "1" else "Not Set"
    return reserved, urg, ack, psh, rst, syn, fin

def trameTCP(data : list, strOut : str) -> (list, str, bool):
    """

        trameTCP(list[str], str) -> (list[str], str, bool)

        retourne l'analyse de la trame TCP
    """
    source = int("".join(data[0:2]),16)
    desti = int("".join(data[2:4]),16)

    sequence_number = int("".join(data[4:8]),16)
    ack_number = int("".join(data[8:12]),16)

    n =  int("".join(data[12][0]),16)
    header_length = f"{4*n} bytes ({n})"
    hl = 4*n
    flags = "0x"+data[12][1]+"".join(data[13:14])
    bflag = bin(int(flags, 16))[2:].zfill(12)
    reserved, urg, ack, psh, rst, syn, fin = getFlags(bflag)
    win_size_value = int("".join(data[14:16]),16)
    checksum = "0x"+"".join(data[16:18])
    urg_ptr = int("".join(data[18:20]), 16)
    option_padding = data[20:hl]

    opt = "Cette partie tcp ne contient pas d'options !"
    if option_padding != list():

        opt = "Cette partie tcp contient des options et potentionellement du bourrage !"
    s = f"""\nTCP:
Source      : {source}
Destination : {desti}

Sequence number (raw)       : {sequence_number}
Acknowledgment number (raw) : {ack_number}

Header Length   : {header_length}


Flags           : {flags}
        
            Reserved    : {reserved}
            Urgent      : {urg}
            Acknowledgment : {ack}
            Push        : {psh}
            Reset       : {rst}
            Syn         : {syn}
            Fin         : {fin} 

Window size value       : {win_size_value}

Cheksum         : {checksum} [unverified]

Urgent pointer  : {urg_ptr}

Options + bourrages : {opt}
"""
    strOut += s
    return data[hl:], strOut

def trameTCPG(data : list) -> (list, str, bool):
    """

        trameTCP(list[str], str) -> (list[str], str, bool)
        
        VERSION GRAPHIQUE
        retourne l'analyse de la trame TCP
    """
    source = int("".join(data[0:2]),16)
    desti = int("".join(data[2:4]),16)

    sequence_number = int("".join(data[4:8]),16)
    ack_number = int("".join(data[8:12]),16)

    n =  int("".join(data[12][0]),16)
    header_length = f"{4*n} bytes ({n})"
    hl = 4*n
    flags = "0x"+data[12][1]+"".join(data[13:14])
    bflag = bin(int(flags, 16))[2:].zfill(12)
    reserved, urg, ack, psh, rst, syn, fin = getFlags(bflag)
    win_size_value = int("".join(data[14:16]),16)
    checksum = "0x"+"".join(data[16:18])
    urg_ptr = int("".join(data[18:20]), 16)

    option_padding = data[20:hl]

    opt = "Cette partie tcp ne contient pas d'options !"
    if option_padding != list():

        opt = "Cette partie tcp contient des options et potentionellement du bourrage !"

    s = [
        f"Source      : {source}",
        f"Destination : {desti}",
        f"Sequence number (raw)       : {sequence_number}",
        f"Acknowledgment number (raw) : {ack_number}",
        f"Header Length   : {header_length}",
        f"Flags           : {flags}",
        f"            Reserved    : {reserved}",
        f"            Urgent      : {urg}",
        f"            Acknowledgment : {ack}",
        f"            Push        : {psh}",
        f"            Reset       : {rst}",
        f"            Syn         : {syn}",
        f"            Fin         : {fin} ",
        f"Window size value       : {win_size_value}",
        f"Cheksum         : {checksum} [unverified]",
        f"Urgent pointer  : {urg_ptr}",
        f"Options + pad   : {opt}"
        ]
    return data[hl:], s
    # print(source, desti, sequence_number, ack_number, header_length, flags, bflag)
    # print(reserved, urg, ack, psh, rst, syn, fin)
    # print(win_size_value, checksum, urg_ptr)
