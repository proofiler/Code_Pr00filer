# -*- coding: utf-8 -*-
# !/usr/bin/python


# --- Script qui check recursivement les extensions des fichiers et supprime les fichiers aux extensions dangereuses ---

# -------- imports --------
import os


# -------- Programme Principal --------
def main_checkExt():
    path="/media/pi/"
    core_path="/opt/Code_Pr00filer"
    a=0
    with open(core_path+"/logs/report.log","a") as report:
        report.write("----------- EXTENTIONS -----------\n")
        #report.write("Fichiers potentiellement dangereux : \n")
        ext = [".dll", ".exe", ".pif", ".application",".msi", ".com", ".msp", ".src", ".hta", ".cpl", ".msc", ".jar", ".bat", ".cmd", ".vb", ".vbs", ".vbe", ".js", ".jse", ".wsc", ".wsh", ".ps1", ".ps1xml", ".ps2", ".ps2xml", ".psc1", ".bin", ".psc2", ".msh", ".scf", ".lnk", ".inf", ".reg", ".sh" ]
        # On parcourt tous les fichiers contenus dans le répertoire ciblé, si un fichier contient l'extension blacklistée : il est supprimé
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.endswith(tuple(ext)):
                     file_path=os.path.join(root, file)
                     report.write(file_path+"\n")
                     parent_file_path=os.path.dirname(file_path)
                     #print(parent_file_path)
                     os.chdir(parent_file_path)
                     os.remove(file)
                     a = a + 1

        # Affichage modulable selon le nombre de fichiers détectés
        if a==1:
        	report.write("\n"+str(a)+" fichier a été détecté et supprimé")
        elif a>1:
        	report.write("\n"+str(a)+" fichiers ont étés détectés et supprimés")
        else:
        	report.write("\nAucun fichier avec une extension dangeureuse n'a été détecté")

