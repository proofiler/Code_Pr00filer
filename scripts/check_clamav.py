#!/usr/bin/env python3
#encoding: UTF-8


# -------- imports -------- #
import os
import hashlib
import requests
from .configFunctions import *
from .dataFunctions import *

# ------ Globals ------ #
ConfigPathFile = getConfigPathFile()
pathUSB=getPathScan(ConfigPathFile)
pathCORE=getPathSource(ConfigPathFile)

def main_clamav(option):
    # si option 1 --> supprime
    # si option 2 --> supprime pas
    if option == "notdel":
        with open(pathCORE+"/logs/tmp_clamav.log","w") as f:
                bashCommand = "clamdscan -v -i "+pathUSB
                subprocess.call(bashCommand.split(" "), stdout=f)
    elif option == "del":
        with open(pathCORE+"/logs/tmp_clamav.log","w") as f:
            bashCommand = "clamdscan -v -i --remove "+pathUSB
            subprocess.call(bashCommand.split(" "), stdout=f)

def clamav_virus_json():
    data_json = init_json()
    with open(pathCORE+"/logs/tmp_clamav.log","r") as log:
             ### --- Récupération des potentiels virus + hash dans un JSON --- ###
        for line in log:
            line_split = ""
            line_split = line.split(" ")
            if line_split[-1].strip() == "FOUND":
                #line = [0]:PATH,[1]:NAME,[2]:FOUND\n
                virus_name = line_split[1] # get the name of the virus from clamav log
                virus_path = line_split[0] # get the full path of the virus clamav lof
                virus_hash = get_sha256_hash(virus_path[:-1]) # Create sha256 from path [:-1] to remove the ":"
                data_json['viruses'].append({
                    'name' : virus_name , 'hash' : virus_hash
                })
            elif line_split[0] == "-----------":
                break
    return data_json

def bash_command(cmd):
    subprocess.Popen(cmd, shell=True, executable='/bin/bash')
