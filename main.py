#!/usr/bin/env python3

# ----- Librairies ------ #
import random, subprocess, os
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import QTimer, QRunnable, QThreadPool, pyqtSlot, QFile, QIODevice, QTextStream, QRect 
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QLabel, QProgressBar, QWidget, QFileDialog, QPlainTextEdit)
# ----- Scripts ------ #
from scripts import *

# fichier lastScan.log : Va contenir provisoirement le dernier scan, le fichier est vidé à chaque debut de scan
# fichier report.log : Va contenir provisoirement le rapport final qui sera afficher à l'utilisateur à la fin du scan, le fichier est vidé à la fin du scan
# fichier history.log : Va être rempli avec les report.log à la fin de chaque scan

# ------ Globals ------ #

# Get the absolut path of the config file
ConfigPathFile = configFunctions.getConfigPathFile()

# Get the absolut path for the scan
pathUSB = configFunctions.getPathScan(ConfigPathFile)

# Get the absolut path for the source code
pathCORE = configFunctions.getPathSource(ConfigPathFile)

# Get the modules check
VirusTotalActive = configFunctions.getCheckVirusTotalScript(ConfigPathFile)
CheckExtensionsActive = configFunctions.getCheckExtensionsScript(ConfigPathFile)



# ------ Main code ------ #
class Worker(QRunnable):
    def __init__(self, fn, *args, **kwargs):
        super(Worker, self).__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    @pyqtSlot()
    def run(self):
        self.fn(*self.args, **self.kwargs)

class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)

        self.threadpool = QThreadPool()

        self.id = 0
        self.picturesDirectory = pathCORE+"/pictures/"
        self.images = ["picture1.png", "picture2.png", "picture3.png"]

        self.image = QLabel(self)

        self.updatePicturesSlide()
        self.createProgressBar()
        self.executeScan()

        layout = QVBoxLayout()

        layout.addWidget(self.image)
        layout.addWidget(self.progressBar)

        widget = QWidget()
        widget.setLayout(layout)
        self.setCentralWidget(widget)

        timerPicturesSlide = QTimer(self)
        timerPicturesSlide.timeout.connect(self.updatePicturesSlide)
        timerPicturesSlide.start(5000)

    def updatePicturesSlide(self):
        if self.id < len(self.images):
            self.image.setPixmap(QPixmap(self.picturesDirectory + self.images[self.id]))
        else:
            self.id = 0
            self.image.setPixmap(QPixmap(self.picturesDirectory + self.images[self.id]))

        self.id = self.id + 1

    def createProgressBar(self):
        self.progressBar = QProgressBar()
        self.progressBar.setRange(0, 100)
        self.progressBar.setValue(0)


    def bash_command(cmd):
        subprocess.Popen(cmd, shell=True, executable='/bin/bash')


    def scan(self):
        self.progressBar.setValue(10)
        self.progressBar.setValue(15)
        # On execute le scan et on sauvegarde l'output dans lastScan.log, le fichier est crée car il n'existe pas
        with open(pathCORE+"/logs/lastScan.log","w") as f:
            bashCommand = "clamdscan -v -i --remove "+pathUSB
            subprocess.call(bashCommand.split(), stdout=f)
        self.progressBar.setValue(35)
        with open(pathCORE+"/logs/lastScan.log") as logFile:

        	#On copie les dernières lignes de lastScan.log dans report.log
            with open(pathCORE+"/logs/report.log","w") as f:
                bashCommand = "tail -n 10 "+pathCORE+"/logs/lastScan.log"
                subprocess.call(bashCommand.split(), stdout=f)
            check = "0"
            linesLog = logFile.readlines()
            self.progressBar.setValue(40)
            with open (pathCORE+"/logs/report.log",'a+') as report:
                report.write("----------- VIRUS LIST -----------\n")
                for line in linesLog:
                    # Si la ligne est un fichier INFECTED, on la copie dans le report.log
                    if "FOUND" in line:
                        report.write(line)
                        check="1"
                if check == "0":
                    report.write("Virus : None\n")
                self.progressBar.setValue(50)
            # Execute checkVirusTotal script
            checkVirusTotal.main_checkVirusTotal()
            self.progressBar.setValue(70)

            # Execution check_ext script
            check_ext.main_checkExt()
            self.progressBar.setValue(80)
            # Execution script check Rubber et extentions
            with open (pathCORE+"/logs/report.log",'a+') as report:
                report.write("\n----------- END OF REPORT -----------\n")

            with open(pathCORE+"/logs/history.log","a") as f:
                bashCommand = "cat "+pathCORE+"/logs/report.log"
                subprocess.call(bashCommand.split(), stdout=f)

            self.progressBar.setValue(100)
            
    ## Affichage deuxième fenêtre pour le report.log
            self.dialog = Second(self)
            self.dialog.show()

    def executeScan(self):
        worker = Worker(self.scan)
        self.threadpool.start(worker)

class Second(QMainWindow):
    def __init__(self, parent=None):
        super(Second, self).__init__(parent)
        self.setFixedSize(640, 480)
        
        # Label Temps du scan
        self.time = QLabel(self)
        self.time.move(10,10)
        
        # Label Nombre de virus
        self.virus = QLabel(self)
        self.virus.move(10,25)

        # Label Nombre d'erreurs
        self.errors = QLabel(self)
        self.errors.move(10,35)

        # Label Nombre de fichiers analysés
        self.nbfile =  QLabel(self)
        self.nbfile.move(10,45)

        # Label pour afficher la liste des Virus
        self.viruslist = QLabel(self)
        self.viruslist.move(10,55)
       
        # Label pour afficher la liste VIRUS TOTAL
        self.virustotal = QLabel(self)
        self.virustotal.move(10,100)

        # Label pour afficher la liste des EXTENSIONS
        self.extensions = QLabel(self)
        self.extensions.move(10,200)
            
        # Label image Warning/ok
        self.warning = QLabel(self)
        self.warning.move(250,10)
        self.Display()
        
        # Suppression report.log et lastScan.log pour les prochains scans
        os.remove(pathCORE+"/logs/lastScan.log")
        os.remove(pathCORE+"/logs/report.log")
            
        # Umount USB
       #bashCommand = "sudo umount /media/pi/*"
       #subprocess.call(bashCommand.split())


    # Fonction qui permet d'afficher le rapport final
    def Display(self):
        with open(pathCORE+"/logs/report.log",'r') as report:
            # Initialisationd es variables
            VirusList = 0
            VirusTotal= 0
            Extensions= 0
            VirusLine = ""
            VirusTotalLine = ""
            ExtensionsLine = ""
            errors_count = "0"
            JSON_list = [] # nombre de fichiers ; nombre de virus ; temps du scan
            # Parcours du fichier report.log
            for line in report:
                
                # Récupère le nombre de fichiers
                nb_files = dataFunctions.getNumberOfFiles(pathUSB)
                self.nbfile.setText("Fichiers Analysés : "+str(nb_files))
                self.nbfile.adjustSize()

                if "Infected" in line: # Récupère le nombre de Virus
                    virusnb_split = line.split(" ")
                    virusnb = virusnb_split[2]
                    self.virus.setText("Nombre de Virus : "+virusnb)
                    self.virus.adjustSize()
                    virusnb = virusnb.rstrip("\n")
                    #Check virus et modification de l'image en conséquence
                    if int(virusnb) != 0:
                        self.warning.setPixmap(QPixmap(pathCORE+"/assets/warning.png"))
                    else:
                        self.warning.setPixmap(QPixmap(pathCORE+"/assets/ok.png"))

                if "Total errors:" in line: # Récupère les erreurs et affiche un message
                    errors_line = line.split()
                    errors_count = errors_line[2]
                    self.errors.setText("Une erreur est survenue pendant l'analyse antivirale !")
                    self.errors.adjustSize()

                if "Time:" in line: # Récupère le temps du scan
                    time_split = line.split(" ")
                    time_scan = time_split[1]
                    self.time.setText("Temps du Scan : "+time_scan+" secondes")
                    self.time.adjustSize() 
                # SI on arrive à END OD REPORT, c'est la fin
                # Du coup on setText les QLabels
                if "END OF" in line:
                    Extension = 0
                    
                    self.viruslist.setText(VirusLine)
                    self.viruslist.adjustSize()
                    
                    self.virustotal.setText(VirusTotalLine)
                    self.virustotal.adjustSize()

                    self.extensions.setText(ExtensionsLine)
                    self.extensions.adjustSize()
                # SI on arrive à la ligne EXTENSION on parcours les extensions
                # Et on mes les lignes dans ExtensionsLine
                # On passe VirusTotal à 0 pour ne par repasser dans le if VIRUS TOTAL
                if "EXTENSIONS" in line:
                    VirusTotal = 0
                    Extensions = 1
                # Extensions est à 1, on parcours les extensions est on les ajoute dans notre variable
                if Extensions == 1:
                    ExtensionsLine += line+"\n"                    
                # SI on est dans la ligne VIRUS TOTAL on parcours les lignes de VirusTotal
                # On passe VIrusList à 0 pour ne par repasser dans le if
                if "VIRUS TOTAL" in line:
                    VirusList = 0
                    VirusTotal = 1
                # On parcours les ligne VirusTotal et on les ajoute dans notre Variable
                if VirusTotal == 1:
                    VirusTotalLine += line+"\n"
                # SI on arrive dans la ligne VIRUS LIST on parcours la liste des VIRUS
                if "VIRUS LIST" in line:
                    VirusList = 1
                # ON parcours les virus et on les ajoute dans notre variable
                if VirusList == 1:
                    VirusLine += line+'\n'
        # Ajout des info dans JSON_list
        JSON_list.append(nb_files)
        JSON_list.append(virusnb)
        JSON_list.append(time_scan)
        JSON_list.append(dataFunctions.getUUID())
        JSON_list.append(errors_count)
        # On envoie la request POST au serveur
        dataFunctions.createRequest(JSON_list)



        

if __name__ == '__main__':
    import sys

    app = QApplication([])
    #app.setStyle('/opt/Code_Pr00filer/doc/dark_theme.qss')
    mainWindow = MainWindow()
    mainWindow.show()

    sys.exit(app.exec_())
