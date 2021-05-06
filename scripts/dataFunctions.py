#!/usr/bin/env python3
#encoding: UTF-8

import os
import hashlib
import requests
import subprocess
import json
import base64
from .configFunctions import *

# ------ Globals ------ #
ConfigPathFile = getConfigPathFile()
usb_path=getPathScan(ConfigPathFile)
core_path=getPathSource(ConfigPathFile)
hash_path=getFileAdminHash(ConfigPathFile)
admin_name=getNameAdmin(ConfigPathFile)
AddrServer = getAddrServer(ConfigPathFile)

def bash_cmd(cmd):
    """
    This function is used with subprocessing lib
    """
    subprocess.Popen(cmd, shell=True, executable='/bin/bash')

def getNumberOfFiles(a_path):
    """
    This function return the number of file in the USB scanned path.

    a_path(char) = Path to the USB scanned
    return(int) = Number of file in the USB path
    """

    count = 0

    for filename in os.listdir(a_path):
        path = os.path.join(a_path, filename)

        if os.path.isfile(path):
            count += 1
        elif os.path.isdir(path):
            count += getNumberOfFiles(path)
    return count


def getId_USB():
    """
    This function gets the vendor ID of the USB plugged.
    Since this is a low level output, we compare the output of the lsusb command with an USB plugged with the output without an usb plugged.
    The diff will be the USB device.

    return(char) = ID vendor of the usb plugged 
    """

    origin_file = "/opt/Code_Pr00filer/doc/lsusb-empty.txt"
    compare_file = "/tmp/lsusb-output.txt"
    id_origin = []
    id_compare = []
    id_USB = "none"

    # Save the lsusb output into temp file
    with open("/tmp/lsusb-output.txt","w") as f:
        bashCommand = "lsusb"
        subprocess.call(bashCommand.split(), stdout=f)
    
    with open(origin_file,'r') as file_1:
        for line in file_1:
            line_split = line.split()
            id_usb = line_split[5]
            id_origin.append(id_usb)
    with open(compare_file, 'r') as file_2:
        for line in file_2:
            line_split = line.split()
            id_usb = line_split[5]
            id_compare.append(id_usb)
    for item in id_compare:
        if item not in id_origin:
            id_USB = item
    return id_USB

def getUUID():
    """
    This function return the Unique UUID of the USB key plugged.
    Return : string
    """
    lsblk = subprocess.Popen(('lsblk', '-f'), stdout=subprocess.PIPE)
    output = subprocess.check_output(('grep', usb_path), stdin=lsblk.stdout)
    lsblk.wait()

    output_command = output.decode()
    output_split = output_command.split(" ")
    output_list = list(dict.fromkeys(output_split))
    uuid_usb = output_list[4]
    
    return uuid_usb

def createRequest(JSON_list):

    nbfile = JSON_list[0]
    nbVirus = JSON_list[1]
    time_scan = JSON_list[2]
    uuid_usb = JSON_list[3]
    errors_scan = JSON_list[4]

    file_open = open(core_path+"/doc/hash_user.txt")
    hash_user = file_open.read().strip()
    file_open.close()
    time_float = float(time_scan)
    time_int = int(time_float)
    payload = {}
    payload['login'] = admin_name
    payload['hash'] = hash_user 
    payload['nbFiles'] = int(nbfile)
    payload['nbVirus'] = int(nbVirus)
    payload['duration'] = int(time_int) 
    payload['uuidUsb'] = uuid_usb
    payload['nbErrors'] =  int(errors_scan)
    
    print(payload)
        
    json_data = json.dumps(payload)
    json_byte = json_data.encode("ascii")
    json_base64 = base64.b64encode(json_byte)
    json_base64 = json_base64.decode("ascii")

    mydata = { 'data' : json_base64 }
    print(AddrServer)
    print(mydata)
    #try:
    r = requests.post(AddrServer, mydata)
    #except:
    #print("Requests.post : Error")
