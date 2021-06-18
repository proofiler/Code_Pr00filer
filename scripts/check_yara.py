# -*- coding: utf-8 -*-
# !/usr/bin/python


# --- Script qui va vérifier les hash des fichiers présent dans la clé de manière recursive pour les comparer avec notre liste perso ---

# -------- imports -------- #
from os import walk
from .configFunctions import *
from .dataFunctions import *
import subprocess 

# ------ Globals ------ #
ConfigPathFile = getConfigPathFile()
pathUSB = getPathScan(ConfigPathFile)
pathCORE = getPathSource(ConfigPathFile)
pathHASH = getFileVirusHash(ConfigPathFile)
pathRULES = getRulesPath(ConfigPathFile)

# -------- Programme Principal --------

def main_yara_check():
    virus_json = {}
    virus_json['virus'] = []
    path_rules = pathCORE+pathRULES+"/"

    # Recup toutes les rules dans un array
    rules = next(os.walk(path_rules))[2]

    for rule in rules:
        fullpath_rule = path_rules+rule 
        # Execution yara sur toutes les rules dans path_rules
        bashCommand = "yara --fail-on-warnings "+fullpath_rule+" -r "+pathUSB+" > "+pathCORE+"logs/yara_tmp.txt"
        os.system(bashCommand)
        with open(pathCORE+"logs/yara_tmp.txt",'r') as tmpfile:
            for ligne in tmpfile:

                if ligne == "":
                    # Condition retour yara vide, pas de match
                    pass
                else:
                    # Condition match d'une yara-rule
                    l_split = ligne.split(" ")
                    virus_name = l_split[0]
                    virus_path = l_split[1].rstrip()
                    virus_hash = get_sha256_hash(virus_path)
                    virus_json['virus'].append({'name':virus_name ,'path':virus_path,'hash': virus_hash})
                    # SUppression du fichier match par la yara-rule
                    delete_file(virus_path)

    # On sauvegarde les virus trouvé avec YARA pour les ajouter dans notre rapport.
    with open(pathCORE+"/logs/tmp_yara.json",'w') as outfile:
        json.dump(virus_json, outfile)
