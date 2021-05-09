# -*- coding: utf-8 -*-
# !/usr/bin/python


# --- Script qui check recursivement les extensions des fichiers et supprime les fichiers aux extensions dangereuses ---

# -------- imports -------- #
import os
from .configFunctions import *

# ------ Globals ------ #
ConfigPathFile = getConfigPathFile()
ext = []
# -------- Programme Principal --------
def main_checkExt():
    path=getPathScan(ConfigPathFile)
    core_path=getPathSource(ConfigPathFile)
    ext = getDataExtensionsDelete(ConfigPathFile)
    file_list = []
    a=0
    with open(core_path+"/logs/tmp_extensions.log","w") as report:
        # On parcourt tous les fichiers contenus dans le répertoire ciblé, si un fichier contient l'extension blacklistée : il est supprimé
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.endswith(tuple(ext)):
                     file_path=os.path.join(root, file)
                     file_list.append(file_path+"\n")
                     parent_file_path=os.path.dirname(file_path)
                     #print(parent_file_path)
                     os.chdir(parent_file_path)
                     os.remove(file)
                     a = a + 1

        # Affichage modulable selon le nombre de fichiers détectés
        report.write("Total_ext = "+str(a)+"\n")
        for elements in file_list:
            report.write(elements)

