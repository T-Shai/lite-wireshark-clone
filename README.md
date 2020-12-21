## PROJET RESEAUX 

Analyseur de Protocoles Réseau ‘Offline’ 

---

### Structure du projet

#### Point d'entrée
- ##### main.py
    - Fichier script
    - Recupere le chemin/nom du fichier et execute le programme
    - branchement en textuel ou graphique selon les arguments

#### Gestion in out
- #### traceparser.py :
    - Lis le fichier trace d'entrée
    - Lève des erreurs si les données ne sont pas complétes ou mal formaté
    - Récupére les données utiles
    - Sépare les différents trames
    - Retourne une liste de listes de chaine de caractére permettant une manipulation par les fonctions afficheures

- #### exceptions.py
    - Permet de lever des erreurs en français
    - Soulève exception lorsque le fichier trace est introuvable
    - Soulève exception lorsqu'il ya une mauvaise correspondance offset vs. taille des octets sur la ligne

#### Analyseur
- #### ethernet.py
    - Affiche les entetes ethernet

- #### ipv4.py

    - Affiche les entetes IPV4

- #### tcp.py

    - Affiche les entetes TCP

- #### http1.py

    - Affiche les entetes HTTP1 

