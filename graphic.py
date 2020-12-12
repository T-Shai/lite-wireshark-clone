"""
    PROJET RESEAUX
    12/12/2020

    graphic.py

    gere la partie graphique du fichier
"""

from tkinter import *
from tkinter import filedialog
from tkinter import ttk

class Racine:
    
    WIDTH = 800
    HEIGHT = 300
    FRAME_PAD = 3
    TAILLE_BOUTTON = 10
    BG_COLOUR = "#282c34"
    FG_COLOUR = "#4ba2e8"
    ACTIVE_BG_COLOUR = "#2b2f38"
    
    def __init__(self, title, icon, geometry):
        self.tk = Tk()
        self.tk.title(title)
        self.tk.iconbitmap(icon)
        self.tk.geometry(geometry)
        self.tk.state('zoomed')
        self.tk.configure(background=Racine.BG_COLOUR)
        ttk.Style().configure("TNotebook", background=Racine.BG_COLOUR)
        self.nb = ttk.Notebook(self.tk)
        self.nb.pack()
        self.nb.configure()

    def createTab(self, titre):
        f = Frame(self.nb, width=Racine.WIDTH-Racine.FRAME_PAD, height=int(Racine.HEIGHT/2)-Racine.FRAME_PAD,bg =Racine.BG_COLOUR)
        f.pack(fill="both", expand=1)
        self.nb.add(f, text=titre+"\t")
        return f

    def mainloop(self):
        self.tk.mainloop()
    
    def hide(self , n):
        self.nb.hide(n)
    
    def select(self , n):
        self.nb.select(n)


class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class TextOut(Text, metaclass=Singleton):

    def write(self, s):
        self.insert(CURRENT, s)

    def flush(self):
        self.delete('1.0', END)

if __name__ == "__main__":
    import sys
    
    from traceparser import lectureOctets   # Lecture des octets depuis un fichier
    from ethernet import trameEthernet #


    r = Racine("Analyseur de Protocoles Réseau 'Offline'", "./gui/lg.ico", str(Racine.WIDTH)+"x"+str(Racine.HEIGHT))

    scrollbar = Scrollbar(r.tk)
    scrollbar.pack( side = RIGHT, fill = Y )
    
    main = r.createTab("Acceuil") # choisir le fichier avec la trame
    
    analyse = r.createTab("Analyse")    # la trame sans les détailles
    ethernet = r.createTab("Ethernet II")
    ipv4 = r.createTab("Internet Protocol Version 4")
    tcp = r.createTab("Transmission Control Protocol")
    http = r.createTab("HyperText Transfer Protocol")
    # # on cache les tab vide pour le moment
    for i in range(1, 6):
        r.hide(i)
    
    #   MAIN
    # choisir un fichier
    Label(main,bg =Racine.BG_COLOUR).pack()  # espace

    choix_fichier = Label(main, text="Choisir votre fichier .txt",bg =Racine.BG_COLOUR,fg=Racine.FG_COLOUR,font = ("arial",Racine.TAILLE_BOUTTON,"bold"))
    choix_fichier.pack()
    
    fichier_choisi = [""]
    def browse():
        fichier_choisi.pop()
        fichier_choisi.append(filedialog.askopenfilename(initialdir = ".", title = "Choisir votre fichier", filetypes = (("Text files", "*.txt*"), ("all files", "*.*"))))
        choix_fichier.configure(text="Fichier ouvert : "+fichier_choisi[0])

    Label(main,bg =Racine.BG_COLOUR).pack()  # espace
      
    parcourir = Button(main, text="\t Parcourir \t", command=browse, font = ("arial",Racine.TAILLE_BOUTTON), bg =Racine.BG_COLOUR,fg =Racine.FG_COLOUR, activebackground = Racine.ACTIVE_BG_COLOUR)
    parcourir.pack(pady = 5 )
    
    Label(main,bg =Racine.BG_COLOUR).pack()  # espace
    
    status_afficher = Label(main, text="\t Cliquer pour analyser \t",bg =Racine.BG_COLOUR, fg= Racine.FG_COLOUR,font = ("arial",Racine.TAILLE_BOUTTON,"bold"))
    status_afficher.pack(pady = 5)
    
    Label(main,bg =Racine.BG_COLOUR).pack()  # espace

    def getData(nom):
        r = ""
        with open(nom, "r") as f:
            r= f.read()
        return r
        
    def cmd_afficher():
        liste_octet = getData(fichier_choisi[0])
        text_trame.delete('1.0', END)
        text_trame.insert(END, str(liste_octet))
            
    afficher = Button(main, text="\t Afficher le fichier selectionné \t", command=cmd_afficher, font = ("arial",Racine.TAILLE_BOUTTON),bg =Racine.BG_COLOUR, fg = Racine.FG_COLOUR,activebackground = Racine.ACTIVE_BG_COLOUR)
    afficher.pack(pady = 5)
    
    text_trame = Text(main)
    text_trame.pack()
    
    Label(main,bg =Racine.BG_COLOUR).pack()  # espace

    liste_octets = list()
    def cmd_analyser():
        my_stderr = TextOut(r.tk)
        my_stderr.pack()
        sys.stderr = my_stderr
        sys.stdout = my_stderr
        if liste_octets != list():
            liste_octets.pop()
        liste_octets.append(lectureOctets(fichier_choisi[0]))
        r.select(1)
        r.hide(0)
            
    bt_analyse = Button(main, text ="\t Analyser la trame choisie \t", command=cmd_analyser,font = ("arial",Racine.TAILLE_BOUTTON),fg = Racine.FG_COLOUR , bg =Racine.BG_COLOUR,activebackground = Racine.ACTIVE_BG_COLOUR)
    bt_analyse.pack(pady=5) 
    
    StrOuts = 0
    
    ### ANALYSE
    def cmd_ethernet():
        trame, strOut, estIPV4 = trameEthernet(liste_octets[0][0])
    
    bt_ethernet = Button(analyse, text="+\tETHERNET II", command=cmd_ethernet, font = ("arial",Racine.TAILLE_BOUTTON),fg = Racine.FG_COLOUR,bg =Racine.BG_COLOUR )
    bt_ethernet.pack()

    Label(analyse,bg =Racine.BG_COLOUR).pack()
    lb_ethernet = Text(analyse)

    

    

    r.mainloop()