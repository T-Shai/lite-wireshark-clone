import chardet
"""
    PROJET RESEAUX
    10/12/2020

    http.py

    fonctions analyseur de HTTP
"""
METHODS = ["GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE"]

def trameHTTP1(trame : list, strOut : str) -> (list, str, bool):
    """
        trameHTTP1(list[str], str) -> (list[str], str, bool)

            retourne l'analyse de la trame http retourne l'analyse
            l'analyse complete ou partiel si la version n'est pas 1
    """

    tmp = bytearray.fromhex(("".join(trame[:])))
    http_decoded = ""
    for i in range(len(tmp)):
        try:
            http_decoded+= tmp[i:i+1].decode()
        except:
            try:
                http_decoded+= tmp[i:i+1].decode("utf-16")
            except:
                http_decoded += "."
    
    http_ascii = http_decoded[:].split()
    
    if not (http_ascii[0].upper() in METHODS or http_ascii[0].lower().startswith("http")) :
        s = "\nHTPP/1.X:\nCette partie n'est pas du HTTP ou est encodée :'(\n mais voici ce qu'on a si ça peut aider..." + http_decoded
        return trame, strOut+s, False
    reponse = False
    e1 = http_ascii[0]
    e2:str = http_ascii[1]
    if e2.isdecimal():
        reponse = True
    e3 = http_ascii[2]

    if not reponse:
        if not e3.lower().startswith("http/1"):
            s = f"""\nHTPP/1.X:\n
Methode:    {e1} 
URL:        {e2}
Version:    {e3}
Malheureusement cette version de http n'est pas pris en compte :'(\n mais voici ce qu'on a si ça peut aider... {http_decoded}"""
            return trame, strOut+s, False
    else:
        if not e1.lower().startswith("http/1"):
            s = f"""\nHTPP/1.X:\n
Version:    {e1} 
Status:     {e2}
Response:   {e3}
Malheureusement cette version de http n'est pas pris en compte :'("""
            return trame, strOut+s, False
    
    if not reponse:
        s=f"""\nHTPP/1.X:\n
Methode:    {e1} 
URL:        {e2}
Version:    {e3}
{http_ascii[3:]}
"""
    else:
        s = f"""\nHTPP/1.X:\n
Version:    {e1} 
Status:     {e2}
Response:   {e3}
{http_decoded[18:]}
"""
    return [], strOut+s, True