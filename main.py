#!/usr/bin/env python3

# ----- Librairies ------ #
import random, subprocess, os
import json, hashlib
import datetime
from PyQt5.QtGui import QPixmap, QImage, QPalette, QBrush
from PyQt5.QtCore import QTimer, QRunnable, QThreadPool, pyqtSlot, QFile, QIODevice, QTextStream, QRect , QSize
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QLabel, QProgressBar, QWidget, QFileDialog, QPlainTextEdit, QDesktopWidget)
# ----- Scripts ------ #
from scripts import *
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

data_json = {}

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

## ------ Main Window ProgressBar ------ ##
class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)

        self.threadpool = QThreadPool()

        self.id = 0

        ## Pictures for prevention ##
        self.picturesDirectory = pathCORE+"/pictures/"
        self.images = ["picture1.png", "picture2.png", "picture3.png", "picture4.png"]

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

    def location_on_the_screen(self):
        """
           Description : Set the location of the main window on the screen. 
        """
        qtRectangle = self.frameGeometry() 
        centerPoint = QDesktopWidget().availableGeometry().center()
        qtRectangle.moveCenter(centerPoint)
        self.move(qtRectangle.topLeft())
    
    def updatePicturesSlide(self):
        """
            Description :Init the pictures on the mainWindow and update them.
            This also set the size of the pictures.
        """
        if self.id < len(self.images):
            pixmap = QPixmap(self.picturesDirectory + self.images[self.id])
            pixmap2 = pixmap.scaled(800,550)
            self.image.setPixmap(pixmap2)
        else:
            self.id = 0
            pixmap = QPixmap(self.picturesDirectory + self.images[self.id])
            pixmap2 = pixmap.scaled(800,550)
            self.image.setPixmap(pixmap2)

        self.id = self.id + 1

    def createProgressBar(self):
        """
        Description :
            - Create the ProgressBar
            - Init the range value of the ProgressBar : 0 to 100
            - Init the start value at 0
        """
        self.progressBar = QProgressBar()
        self.progressBar.setRange(0, 100)
        self.progressBar.setValue(0)

    def scan(self):
        """
        Description : This function start all the modules for the analysis of the USB device.
        This is the list of all the modules for now :
        - check_extensions : Delete all the file that latch the unauthorized extensions
        - check_hash : Delete all the file that match the virus hash list in the virus_hash.txt file.
        - check_clamav : Start a clamdscan in the USB devise. Return the clamab report and delete the virus.
        - check_virustotal : Get the hash of the file and then check if there is a result in VT using request. WARNING This modules can be limited because we are not using any API Token !

        """
        self.progressBar.setValue(10)

        ##### ----- EXTENSIONS ----- #####
        check_ext.main_checkExt()  
        self.progressBar.setValue(20)

        ##### ----- Check HASH ----- #####
        check_hash.main_checkHash()

        ##### ----- CLAMAV ----- #####
        option = "notdel"
        check_clamav.main_clamav(option)
        self.progressBar.setValue(40)
        # Parse virus from previous scan to json (So that way we can get the hash before the file is deleted)
        data_json = check_clamav.clamav_virus_json()
        option = "del"
        check_clamav.main_clamav(option)

        # We save the JSON so we can use it everywhere in the application code
        with open(pathCORE+"/logs/data_json.json",'w') as outfile:
            json.dump(data_json, outfile)

        ##### ----- VIRUSTOTAL ----- #####
        checkVirusTotal.main_checkVirusTotal()
        self.progressBar.setValue(70)

        ##### ----- YARA ----- #####
        check_yara.main_yara_check()
        self.progressBar.setValue(100)
            
    ## Display the seconWindow with the report
        self.dialog = Second(self)
        self.dialog.show()

    def executeScan(self):
        worker = Worker(self.scan)
        self.threadpool.start(worker)

class Second(QMainWindow):
    def __init__(self, parent=None):
        super(Second, self).__init__(parent)
        self.setFixedSize(800,550)
        
        # Label Scan Time
        self.time = QLabel(self)
        self.time.move(10,10)
        
        # Label Number Virus
        self.virus = QLabel(self)
        self.virus.move(10,35)

        # Label Number Error
        self.errors = QLabel(self)
        self.errors.move(10,45)
            
        # Label Finale picture OK / NOPE
        self.warning = QLabel(self)
        self.warning.move(0,0)
        self.Display()

    def Display(self):
        """
        Description : This is where most of the parsing is done. 
        We will parse the reports of the modules to adapt them in our final report that will be sent to the server.
        """
        # We get the data in the json saved above
        # data_json = The main JSON that will be used for the report.
        data_json = {}
        with open(pathCORE+"/logs/data_json.json","r") as json_file:
            data_json = json.load(json_file)

        # The history.log file will be open during the whole function in order to place data in it
        with open(pathCORE+"/logs/history.log","a") as report:
            nbErrors=0
            dt_string = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

            # Array used to store viruses found in the logs 
            #   ex  : [VT] virus  /path/to/virus
            datareport_array = []

            ## INFO check_HASH #################################################

            # We open the JSON that contains the viruses found in the check_hash module
            with open(pathCORE+"/logs/tmp_virus.json","r") as json_virus_file:
                virus_json = json.load(json_virus_file)
            # We add the viruses found with the check_hash module in our final data_json
            coutn_hash_virus = 0
            if not 'virus' in virus_json and len(virus_json['virus']) == 0:
                pass
            else:
                for virus in virus_json['virus']:
                    coutn_hash_virus = coutn_hash_virus +1
                    virus_name = virus['name']
                    virus_path = virus['path']
                    virus_hash = virus['hash']
                    data_json['viruses'].append({'name':virus_name ,'hash':virus_hash})
                    # We add the viruses found in the check_hash in the array that will be added to the final report
                    datareport_array.append("[HC] "+virus_path+" "+virus_name+" "+virus_hash+"\n")
            
            ## Info VirusTotal #################################################

            # Open the temporary log file of the virustotal result. 
            with open(pathCORE+"/logs/tmp_virustotal.log","r") as virustotal:
                line_split = ""
                count_vt = 0 # This variable store the number of virus found with VT (history.log)
                for line in virustotal:
                    # line = [0]:PATH, [1]:'-', [2]:SOURCE, [3]:':', [4]:NAME
                    if line[0] != "":
                        line_split = line.split(" ")
                        virus_name = line_split[4].strip() 
                        virus_path = line_split[0]
                        virus_hash = dataFunctions.get_sha256_hash(virus_path)
                        # Add the virus into the main json
                        data_json['viruses'].append({
                            'name':virus_name ,'hash':virus_hash
                        })
                        count_vt = count_vt + 1*
                        # Add the virus into the history array
                        datareport_array.append("[VT] "+virus_path+" "+virus_name+" "+virus_hash+"\n")
                        
                        # If the file match VT , it is deleted
                        dataFunctions.delete_file(virus_path)
                        print("[VT] "+virus_path+" supprimé !")
                    else:
                        # If the V report log is empty, we don't do anything
                        pass

            ## Info Extensions #################################################
            # We open the temporary log file that shows the files deleted by the module extensions
            with open(pathCORE+"/logs/tmp_extensions.log","r") as extensions:
                line_split = ""
                nbExt = 0
                for line in extensions:
                    if "Total_ext" in line:
                        # This part get the number of file removed by the module.
                        # We make a loop because the line which interests us is at the end of the file. 
                        # At the beginning we will find the deleted extensions with the absolute path of the deleted file.
                        line_split = line.split(" ")
                        nbExt_str = line_split[2].strip()
                        nbExt = int(nbExt_str)
                        break
                # Now that we have the number of deleted extensions, we can see if there are any.
                if nbExt == 0:
                    # No extensions removed
                    pass
                else:
                    line_split = ""
                    for lines in extensions:
                        line_split = lines.split(" ")
                        if line_split[0] == "Total_ext":
                            pass 
                        else:
                            Ext_path = line_split[0].strip()
                            datareport_array.append("[EX] "+Ext_path+"\n")
            ### Rapport YARA #################################################
            # We recover the temporary json file generated by the module yara-rules. 
            # It contains the files that have match on a yara-rule. 
            with open(pathCORE+"/logs/tmp_yara.json","r") as json_yara_file:
                yara_json = json.load(json_yara_file)

            # We retrieve the number of files deleted by the yara-rules. (history.log)
            nbYARA = len(yara_json['virus'])

            # If there is no virus in the json, no match yara so we do nothing.
            if not 'virus' in yara_json and len(yara_json['virus']) == 0:
                pass
            else:
                # there are one or more viruses, we willlook through them and recover the name + the hash + the path of the file.
                for virus in yara_json['virus']:
                    virus_name = virus['name']
                    virus_path = virus['path']
                    virus_hash = virus['hash']
                    data_json['viruses'].append({'name':virus_name ,'hash':virus_hash})
                    # Add the virus into the history array
                    datareport_array.append("[YR] "+virus_path+" "+virus_name+" "+virus_hash+"\n")

            ## Info clamav #################################################
            # Here we retrieve the temporary file of the clamav report.
            with open(pathCORE+"/logs/tmp_clamav.log","r") as clamav:
                # We recover the number of files present in the USB key.
                nbFiles = dataFunctions.getNumberOfFiles(pathUSB)
               
                # If there are virus into VT scan, we add them to the clamav counter viruses
                counter = 0 + count_vt + coutn_hash_virus

               # We will browse the log file to get all the information we need.
                for line in clamav:
                    line_split = ""
                    # Scanning time
                    if "Time:" in line:
                        line_split = line.split(" ")
                        time_scan = line_split[1].strip()
                        time_float = float(time_scan)
                        duration = int(time_float)
                        duration = duration + duration + 3
                # Number of viruses   
                    if "Infected" in line:
                        line_split = line.split(" ")
                        nbVirus = line_split[-1].strip()
                        nbVirus = int(nbVirus)+count_vt
                # If there is a virus, FOUND on the line
                    if "FOUND" in line:
                        line_split = line.split(" ")
                        counter = counter + 1
                        virus_name = line_split[1] # Name
                        virus_path = line_split[0] # Path
                         # Add the virus into the history array
                        datareport_array.append("[AV] "+virus_path+" "+virus_name+"\n")
                # Number of errors
                    if "errors:" in line:
                        line_split = line.split(" ")
                        nbErrors_str = line_split[-1].strip()
                        nbErrors = int(nbErrors_str)

                # Since we store the viruses in our main json, we count them to get the total number 
                nbVirus = len(data_json['viruses'])
                nbFiles = nbFiles + nbVirus

                # The final image is displayed to indicate to the user whether the USB stick is infected or not
                if int(nbVirus) != 0:
                    pixmap = QPixmap(pathCORE+"/assets/attention.png") # VIRUS
                    pixmap = pixmap.scaled(800,550)
                    self.warning.setPixmap(pixmap)
                    self.warning.setFixedSize(800,550)
                else:
                    pixmap = QPixmap(pathCORE+"/assets/scan_ok.png") # NO VIRUS
                    pixmap = pixmap.scaled(800,550)
                    self.warning.setPixmap(pixmap)
                    self.warning.setFixedSize(800,550)
                
                # The values of the text fields for the report displayed on the screen are initialized. 
                # WARNING :  with the images you can't see them.

                self.time.setText("Temps : "+str(duration)+" secondes")
                self.time.adjustSize()
                self.virus.setText("Virus : "+str(nbVirus))
                self.virus.adjustSize()
                # Set the error label with there are errors
                if nbErrors != 0:
                    self.errors.setText("Une erreur est survenue pendant l'analyse !")
                    self.errors.adjustSize()

            # Generate the report history.log
            report.write("########### Rapport du "+dt_string+" ###########\n")
            report.write("# USB\n")
            report.write("UUID = "+dataFunctions.getUUID()+"\n")  
            report.write("# Info\n")
            report.write("Fichiers = "+str(nbFiles)+"\n")
            report.write("Erreurs = "+str(nbErrors)+"\n")
            report.write("Temps = "+str(duration)+"\n")
            report.write("Virus = "+str(nbVirus)+"\n")
            report.write("VirusTotal = "+str(count_vt)+"\n")
            report.write("Extensions = "+str(nbExt)+"\n")
            report.write("Yara match = "+str(nbYARA)+"\n")
            # Put all the virus 
            for line in datareport_array:
                report.write(line)

            # We add the last values in the main JSON
            data_json['nbFiles'] = int(nbFiles) # Number of files
            data_json['nbVirus'] = nbVirus # Number of viruses
            data_json['duration'] = duration # Scanning time
            data_json['uuidUsb'] = dataFunctions.getUUID() # USB UUID
            data_json['nbErrors'] = nbErrors # Number of errors

            # Umount the USB key 
            rc = subprocess.call(pathCORE+"/scripts/umountUSB.sh")

            # Send the JSON to the server
            dataFunctions.createRequest(data_json)

if __name__ == '__main__':
    import sys

    app = QApplication([])
    mainWindow = MainWindow()
    mainWindow.location_on_the_screen()
    mainWindow.show()

    sys.exit(app.exec_())
