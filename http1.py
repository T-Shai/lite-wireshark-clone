import chardet
"""
    PROJET RESEAUX
    10/12/2020

    http.py

    fonctions analyseur de HTTP
"""
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
    http_decoded = http_decoded.split("\r\n")
    """
    Si c'est une requete :
        METHODE LIEN VERSION
    Si c'est une reponse :
        VERSION STATUS_CODE STATUS
    """

    if http_decoded[0].lower().startswith("http/1"):
        # reponse
        tmp = http_decoded[0].split(" ")
        version = tmp[0]
        status_code = tmp[1]
        status = " ".join(tmp[2:])
        data = "\n".join(http_decoded[1:])
        s = f"""\nHTTP/1.X\n
Version:    {version} 
Status:     {status_code}
Response:   {status}
{data}
"""
        return [], strOut+s, True     
    elif "http/1" in http_decoded[0].lower():
        # requete
        tmp = http_decoded[0].split(" ")
        methode = tmp[0]
        url = tmp[1]
        version = tmp[2]
        data = "\n".join(http_decoded[1:])
        
        s= f"""\nHTTP/1.X:\n
Methode:    {methode} 
URL:        {url}
Version:    {version}
{data}
"""        
        return [], strOut+s, True

    else:
        # n'est pas http
        return trame, strOut+f"\nCette partie n'est pas http/1 ou est encrypté :'(\n Voici quand meme ce qu'on a :\n"+"\n".join(http_decoded), False
    
def trameHTTP1G(trame : list) -> (list, str, bool):
    """
        trameHTTP1(list[str], str) -> (list[str], str, bool)

            VERSION GRAPHI
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
    http_decoded = http_decoded.split("\r\n")
    """
    Si c'est une requete :
        METHODE LIEN VERSION
    Si c'est une reponse :
        VERSION STATUS_CODE STATUS
    """

    if http_decoded[0].lower().startswith("http/1"):
        # reponse
        tmp = http_decoded[0].split(" ")
        version = tmp[0]
        status_code = tmp[1]
        status = " ".join(tmp[2:])
        s = [
            f"Version:    {version} ",
            f"Status:     {status_code}",
            f"Response:   {status}",
        ]
        return [], s+http_decoded[1:], True     

    elif "http/1" in http_decoded[0].lower():
        # requete
        tmp = http_decoded[0].split(" ")
        methode = tmp[0]
        url = tmp[1]
        version = tmp[2]
        data = "\n".join(http_decoded[1:])
        s= [
            f"Methode:    {methode}", 
            f"URL:        {url}",
            f"Version:    {version}",
        ]
        return [], s+http_decoded[1:], True

    else:
        # n'est pas http
        return trame, [f"Cette partie n'est pas http/1 ou est encrypté :'(\n Voici quand meme ce qu'on a :\n"+"\n".join(http_decoded)], False