import sys

# graphique
from PyQt5.QtWidgets import * 
from PyQt5.QtGui import * 
from PyQt5.QtCore import Qt, QTimer

from gui.mainWindow import Ui_MainWindow
from gui.splashScreen import Ui_SplashScreen
import math
# analyseur
from traceparser import lectureOctetsG
from ethernet import trameEthernetG
from ipv4 import trameIpv4G
from tcp import trameTCPG
from http1 import trameHTTP1G

class Fenetre:
    TITRE = "ADR-Pro"
    def __init__(self):
        self.fenetre_princ = QMainWindow()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self.fenetre_princ)

        self.fenetre_princ.setWindowTitle(self.TITRE)
        self.fenetre_princ.setWindowFlag(Qt.FramelessWindowHint)
        self.fenetre_princ.setAttribute(Qt.WA_TranslucentBackground)
        self.ui.Pages.setCurrentWidget(self.ui.Acceuil)
        # menu du haut
        self.ui.Titre.setText(self.TITRE)
        self.ui.bouton_acceuil.clicked.connect(self.goToAcceuil)
        self.ui.bouton_fermer.clicked.connect(self.fenetre_princ.close)
        self.ui.bouton_reduire.clicked.connect(self.fenetre_princ.showMinimized)
        
        # acceuil
        self.ui.bouton_commencer.clicked.connect(self.goToImportation)


        # importation
        self.fichier = "chemin..."
        self.ui.text_chemin.setReadOnly(True)
        self.ui.text_chemin.setText(self.fichier)
        self.ui.bouton_parcourir.clicked.connect(self.selectFile)
        self.ui.bouton_analyser.clicked.connect(self.analyseTrame)

        # trame
        self.trames = None
        self.ui.bouton_retour_trame.clicked.connect(self.goToImportation)
        self.ui.bouton_developper.clicked.connect(self.developperTrame)
        
        # erreur
        self.ui.bouton_retour_erreur.clicked.connect(self.goToImportation)

        # analyse 
        self.strOut = "ADR-Pro Analyse :\n"
        self.fname = ""
        self.trame_actuelle = None
        self.ui.bouton_retour_analyse.clicked.connect(self.goToTrame)
        self.ui.bouton_enregistrer.clicked.connect(self.enregistrerTrame)
        self.ui.table_trame.setItem(0,0,QTableWidgetItem("Source"))
        self.ui.table_trame.setItem(0,1,QTableWidgetItem("Destination"))
        self.ui.table_trame.setItem(0,2,QTableWidgetItem("Taille"))


    def show(self):
        self.fenetre_princ.show()

    def goToAcceuil(self):
        self.ui.Pages.setCurrentWidget(self.ui.Acceuil)
    
    def goToImportation(self):
        self.ui.Pages.setCurrentWidget(self.ui.Importation)
    
    def goToTrame(self):
        self.ui.Pages.setCurrentWidget(self.ui.Trame)
    
    def selectFile(self):
        f, _ = QFileDialog.getOpenFileName(None,"Importation Trame", "","Fichiers texte (*.*)")
        if f != "":
            self.fichier = f
        self.ui.text_chemin.setText(self.fichier)
        self.ui.text_chemin_trame.setText(self.fichier)
    
    def analyseTrame(self):
        if self.fichier == "chemin...":
            self.ui.texte_erreur_fichier.setText("Nous comprenons que vous êtes impatient mais... \nveuillez choisir un fichier d'abord 😊")
        else:
            etat, data = lectureOctetsG(self.fichier)
            if etat:
                self.ui.Pages.setCurrentWidget(self.ui.Trame)
                self.trames = data
                self.ui.liste_trames.clear()
                for i in range(len(self.trames)):
                    self.ui.liste_trames.addItem(f"Trame {i}")
            else:
                self.ui.Pages.setCurrentWidget(self.ui.Erreur)
                self.ui.text_erreur.setText(f"Pendant le parsing de {self.fichier}:\n\n\t"+data)

    def developperTrame(self):
        if self.ui.liste_trames.selectedItems() != list():
            self.trame_actuelle = self.trames[int(self.ui.liste_trames.selectedItems()[0].text().split()[1])]
            self.ui.table_trame.setItem(1,2,QTableWidgetItem(f"{len(self.trame_actuelle)} byte(s)"))
            self.ui.bouton_enregistrer.setText("Enregistrer")
            self.ui.Pages.setCurrentWidget(self.ui.Analyse)
            
            # reset de l'arbre
            for it in range(4):
                parent = self.ui.arbre_trame.topLevelItem(it)
                for i in reversed(range(parent.childCount())):
                    parent.removeChild(parent.child(i))
            # peuplement de l'arbre
            self.trame_actuelle, liste_info, estIPV4 = trameEthernetG(self.trame_actuelle)
            self.strOut += "\nEthernet\n"
            for info in liste_info:
                self.ui.arbre_trame.topLevelItem(0).addChild(QTreeWidgetItem([info]))   # ethernet
                self.strOut += info+"\n"
            if estIPV4:
                self.strOut += "\nIPV4\n"
                self.trame_actuelle, liste_info, estTCP, ipsrc, ipdest = trameIpv4G(self.trame_actuelle)
                self.ui.table_trame.setItem(1,0,QTableWidgetItem(ipsrc))
                self.ui.table_trame.setItem(1,1,QTableWidgetItem(ipdest))

                for info in liste_info:
                    self.ui.arbre_trame.topLevelItem(1).addChild(QTreeWidgetItem([info]))   # ipv4
                    self.strOut += info+"\n"
                if estTCP:
                    self.strOut += "\nTCP\n"
                    self.trame_actuelle, liste_info = trameTCPG(self.trame_actuelle)
                    for info in liste_info:
                        self.ui.arbre_trame.topLevelItem(2).addChild(QTreeWidgetItem([info]))   # tcp
                        self.strOut += info+"\n"

                    self.trame_actuelle, liste_info, ok = trameHTTP1G(self.trame_actuelle)
                    if ok:
                        self.strOut += "\nHTTP 1.X\n"
                        for info in liste_info:
                            self.ui.arbre_trame.topLevelItem(3).addChild(QTreeWidgetItem([info]))   # http
                            self.strOut += info+"\n"
                    else:
                        self.strOut += liste_info[0]
                        self.ui.arbre_trame.topLevelItem(3).addChild(QTreeWidgetItem([liste_info[0]]))
                else:
                    info = "??? (seul TCP est implémenté)\n"
                    self.strOut += info+"\n"
                    self.ui.arbre_trame.topLevelItem(2).addChild(QTreeWidgetItem([info]))   # tcp
                    self.ui.arbre_trame.topLevelItem(3).addChild(QTreeWidgetItem([info]))   # http
            else:
                info = "??? (seul IPV4 est implémenté)\n"
                self.strOut += info+"\n"
                self.ui.arbre_trame.topLevelItem(1).addChild(QTreeWidgetItem([info]))   # ipv4
                self.ui.arbre_trame.topLevelItem(2).addChild(QTreeWidgetItem([info]))   # tcp
                self.ui.arbre_trame.topLevelItem(3).addChild(QTreeWidgetItem([info]))   # http

                self.ui.table_trame.setItem(1,0,QTableWidgetItem("???"))
                self.ui.table_trame.setItem(1,1,QTableWidgetItem("???"))
        else:
            self.ui.texte_erreur_trame.setText("Veuillez choisir une trame")
    

    def enregistrerTrame(self):
        h = str(hash(self.strOut))
        fname = "output-"+h+".txt"
        with open(fname, "w") as f:
            f.write(self.strOut)
        self.ui.bouton_enregistrer.setText("Enregistrée 👍")

class SplashScreen(QMainWindow):
    def __init__(self):
        QMainWindow.__init__(self)
        self.ui = Ui_SplashScreen()
        self.ui.setupUi(self)

        
        self.counter = 0

        self.setWindowFlag(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)


        self.timer = QTimer()
        self.timer.timeout.connect(self.progress)

        self.timer.start(35)


        self.show()
        ## ==> END ##

    ## ==> APP FUNCTIONS
    ########################################################################
    def progress(self):

        # SET VALUE TO PROGRESS BAR
        self.ui.progressBar.setValue(self.counter)

        # CLOSE SPLASH SCREE AND OPEN APP
        if self.counter > 100:
            # STOP TIMER
            self.timer.stop()

            # SHOW MAIN WINDOW
            self.main = Fenetre()
            self.main.show()

            # CLOSE SPLASH SCREEN
            self.close()

        # INCREASE COUNTER
        self.counter += 1



if __name__ == "__main__":
    app = QApplication(sys.argv)
    f = SplashScreen()
    f.show()
    sys.exit(app.exec_())
