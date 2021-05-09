#!/usr/bin/env python3

# ----- Librairies ------ #
import random, subprocess, os
import json, hashlib
from datetime import date
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

        ##### ----- CLAMAV ----- #####
        option = "notdel"
        check_clamav.main_clamav(option)
        self.progressBar.setValue(20)
        
        # Parse virus from previous scan to json
        data_json = check_clamav.clamav_virus_json()
        self.progressBar.setValue(25)

        option = "del"
        check_clamav.main_clamav(option)
        self.progressBar.setValue(35)

        ##### ----- VIRUSTOTAL ----- #####
        checkVirusTotal.main_checkVirusTotal()
        self.progressBar.setValue(70)

        ##### ----- EXTENSIONS ----- #####
        check_ext.main_checkExt()  
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
        #os.remove(pathCORE+"/logs/lastScan.log")
        #os.remove(pathCORE+"/logs/report.log")
            
        # Umount USB
       #bashCommand = "sudo umount /media/pi/*"
       #subprocess.call(bashCommand.split())


    # Fonction qui permet d'afficher le rapport final
    def Display(self):
        with open(pathCORE+"/logs/history.log","a") as report:
            nbErrors=0
            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            VirusLine = "Liste des virus :\n"
            ExtensionsLine = "Liste des extenions supprimées :\n"
            datareport_array = []
            ## Info VirusTotal
            with open(pathCORE+"/logs/tmp_virustotal.log","r") as virustotal:
                line_split = ""
                count_vt = 0 # store the number of virus with VT
                for line in virustotal:
                    try:
                    # Récup nom du virus + hashline_split = line.split()
                    # line = [0]:PATH, [1]:'-', [2]:SOURCE, [3]:':', [4]:NAME
                        virus_name = line_split[4].strip() 
                        virus_path = line_split[0]
                        virus_hash = dataFunctions.get_md5_hash(virus_path)
                        print("[!] VT : "+str(count_vt)+" "+virus_name+" "+virus_path+" "+virus_hash)
                        # On ajoute le virus dans le JSON
                        data_json['viruses'].append({
                                virus_name : virus_hash
                        })

                        count_vt = count_vt + 1
                        VirusLine = VirusLine+"-- "+str(count_vt)+" : "+virus_path+" "+virus_name+"\n"
                        datareport_array.append("[VT] "+virus_path+" "+virus_name+" "+virus_hash+"\n")
                        
                        # On supprime le fichier trigger par VT
                        dataFunctions.delete_file(virus_path)
                        print("[VT] "+virus_path+" supprimé !")
                    except:
                        print("Aucun résultat VT")

            ## Info Extensions
            with open(pathCORE+"/logs/tmp_extensions.log","r") as extensions:
                line_split = ""
                nbExt = 0
                for line in extensions:
                    if "Total_ext" in line:
                        line_split = line.split(" ")
                        nbExt_str = line_split[2].strip()
                        nbExt = int(nbExt_str)

                if nbExt == 0:
                    # Aucunes Extensions supprimées
                        ExtensionsLine = ExtensionsLine+"Aucune extenions supprimées\n"
                else:
                    line_split = ""
                    for line in extensions:
                        line_split = line.split(" ")
                        if line_split[0] == "Total_ext":
                            pass 
                        else:
                            Ext_path = line_split[0].strip()
                            ExtensionsLine = ExtensionsLine+"-- "+Ext_path+"\n"
                            datareport_array.append("[EX] "+Ext_path+"\n")

                    # Tu affiche les données avec setText oklm
                    # une fois que c'est ok bah tu fais le fichier history.log pour que ce soit tout beau
                    # bisous
                
            ## Info clamav
            with open(pathCORE+"/logs/tmp_clamav.log","r") as clamav:
                # fichier
                nb_files = dataFunctions.getNumberOfFiles(pathUSB)

                counter = 0 + count_vt # If there are virus into VT scan, we add them to the clamav counter viruses

                # Temps du scan
                for line in clamav:
                    line_split = ""
                    if "Time:" in line:
                        line_split = line.split(" ")
                        time_scan = line_split[1].strip()
                        time_float = float(time_scan)
                        duration = int(time_float)
                        duration = duration + duration + 3
                # Nombre de virus    
                    if "Infected" in line:
                        line_split = line.split(" ")
                        nbVirus = line_split[-1].strip()
                        nbVirus = int(nbVirus)+count
                # Récupération des virus
                    if "FOUND" in line:
                        line_split = line.split(" ")
                        counter = counter + 1
                        # display exemple
                        # -- 2 : /path/virus NAME
                        virus_name = line_split[1] 
                        virus_path = line_split[0]
                        virus_hash = dataFunctions.get_md5_hash(virus_path)
                        VirusLine = VirusLine+"-- "+str(counter)+" : "+virus_path+" "+virus_name+"\n"
                        datareport_array.append("[AV] "+virus_path+" "+virus_name+" "+virus_hash+"\n")
                # Nombre d'erreurs
                    if "errors:" in line:
                        line_split = line.split(" ")
                        nbErrors_str = line_split[-1].strip()
                        nbErrors = int(nbErrors_str)
                # Affichage des images Warning et OK pour l'état de la clé
                if int(virusnb) != 0:
                        self.warning.setPixmap(QPixmap(pathCORE+"/assets/warning.png"))
                    else:
                        self.warning.setPixmap(QPixmap(pathCORE+"/assets/ok.png"))
                
                # On set les valeur des champs TEXT
                self.nbfile.setText("Fichiers : "+str(nb_files))
                self.nbfile.adjustSize()
                self.time.setText("Temps : "+str(duration)+" secondes")
                self.time.adjustSize()
                self.virus.setText("Virus : "+str(nbvirus))
                self.virus.adjustSize()
                if nbErrors != 0:
                    self.errors.setText("Une erreur est survenue pendant l'analyse !")
                    self.errors.adjustSize()
                self.viruslist.setText(VirusLine)
                self.viruslist.adjustSize()
                self.virustotal.setText(VirusTotalLine)
                self.virustotal.adjustSize()
                self.extensions.setText(ExtensionsLine)
                self.extensions.adjustSize()
                
            # GENERER LE REPORT
            report.write("########### Rapport du "+dt_string+" ###########\n")
            report.write("# USB\n")
            report.write("UUID = "+dataFunctions.getUUID()+"\n")  
            report.write("# CLAMAV")
            report.write("Fichiers = "+str(nbFiles))
            report.write("Erreurs = "+str(nbErrors))
            report.write("Temps = "+str(duration))
            report.write("Ingected = "+str(nbVirus))
            report.write("VirusTotal = "str(count_vt))
            report.write("Extensions = "+str(nbExt))
            for line in datareport_array:
                report.write(line)
            report.write("########### FIN ###########")

            # Ajout des info dans JSON_list
            data_json['nbFiles'] = nb_files
            data_json['nbVirus'] = virusnb
            data_json['duration'] = duration
            data_json['uuidUsb'] = dataFunctions.getUUID()
            data_json['nbErrors'] = errors_count
            # On envoie la request POST au serveur
            print(data_json)
            dataFunctions.createRequest(data_json)

if __name__ == '__main__':
    import sys

    app = QApplication([])
    #app.setStyle('/opt/Code_Pr00filer/doc/dark_theme.qss')
    mainWindow = MainWindow()
    mainWindow.show()

    sys.exit(app.exec_())
