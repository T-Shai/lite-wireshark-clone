## PROJET RESEAUX 

Analyseur de Protocoles Réseau ‘Offline’ 

---

### Structure du projet

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

- #### ethernet.py

    - Affiche les entetes ethernet