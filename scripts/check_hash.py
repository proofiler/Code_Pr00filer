# -*- coding: utf-8 -*-
# !/usr/bin/python


# --- Script qui va vérifier les hash des fichiers présent dans la clé de manière recursive pour les comparer avec notre liste perso ---

# -------- imports -------- #
from os import walk
from .configFunctions import *
from .dataFunctions import *

# ------ Globals ------ #
ConfigPathFile = getConfigPathFile()
pathUSB = getPathScan(ConfigPathFile)
pathCORE = getPathSource(ConfigPathFile)
pathHASH = getFileVirusHash(ConfigPathFile)

# -------- Programme Principal --------
def main_checkHash():
# Creer un JSON pour stocker les virus
    virus_json = {}
    virus_json['virus'] = []

    for (repertoire, sousRepertoires, fichiers) in walk(pathUSB):
        for file in fichiers:
            #print(repertoire+"/"+file)
            path_file_to_check = repertoire+"/"+file
            file_name = file
            sha256_file = get_sha256_hash(path_file_to_check)
            if check_hash(pathHASH,sha256_file):
                 #VIRUS
                 virus_json['virus'].append({'name':file_name ,'path':path_file_to_check,'hash': sha256_file})
                 delete_file(path_file_to_check)
            else:
                 pass
    delete_file(pathCORE+"/logs/tmp_virus.json")
    with open(pathCORE+"/logs/tmp_virus.json",'w') as outfile:
            json.dump(virus_json, outfile)


