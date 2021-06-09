#!/usr/bin/env python3
#encoding: UTF-8

import os
import hashlib
import requests
import subprocess
import json
import base64

# ------ Crypto ------ #
import binascii
from Crypto.Cipher import AES
from Crypto import Random
# ------ Scripts ------ #
from .configFunctions import *

# ------ Globals ------ #
ConfigPathFile = getConfigPathFile()
usb_path=getPathScan(ConfigPathFile)
core_path=getPathSource(ConfigPathFile)
hash_path=getFileAdminHash(ConfigPathFile)
admin_name=getNameAdmin(ConfigPathFile)
AddrServer = getAddrServer(ConfigPathFile)


def my_encrypt(data, passphrase):
    """
         Encrypt using AES-256-CBC with random/shared iv
        'passphrase' must be in hex, generate with 'openssl rand -hex 32'
    """
    try:
        key = binascii.unhexlify(passphrase)
        pad = lambda s : s+chr(16-len(s)%16)*(16-len(s)%16)
        iv = Random.get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_64 = base64.b64encode(cipher.encrypt(pad(data))).decode('ascii')
        iv_64 = base64.b64encode(iv).decode('ascii')
        json_data = {}
        json_data['iv'] = iv_64
        json_data['data'] = encrypted_64
        clean = base64.b64encode(json.dumps(json_data).encode('ascii'))
    except Exception as e:
        print("Cannot encrypt datas...")
        print(e)
        exit(1)
    return clean



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

def createRequest(data_json):
    
    file_open = open(core_path+"/doc/hash_user.txt")
    hash_user = file_open.read().strip()
    file_open.close()
    data_json['login'] = admin_name
    data_json['hash'] = hash_user 
    json_data = json.dumps(data_json)
    print(data_json)

    # JSON to BASE64
    json_byte = json_data.encode("ascii")
    json_base64 = base64.b64encode(json_byte)
    json_base64 = json_base64.decode("ascii")
    #print(json_base64)

    # Encrypt JSON
    encrypted = my_encrypt(json_base64,"5cd10f8a394a241beae003415a1b4569672696468c5aec18f880d1eb2043ad0c")
    #print(encrypted)

    # Create POST
    mydata = { 'data' : encrypted }
    try:
        r = requests.post(AddrServer, mydata)    
        if r.status_code == 200:
        # Send OK
            with open(core_path+"/logs/history.log",'a') as report:
                report.write("[+] Rapport envoyé au serveur\n")
        else:
        # Send not OK
            with open(core_path+"logs/history.log",'a') as report:
                report.write("[!] Impossible de contacter le serveur - Not 200\n")
    except requests.exceptions.Timeout:
        with open(core_path+"logs/history.log",'a') as report:
            report.write("[!] Impossible de contacter le serveur - Timeout\n")
    except requests.exceptions.HTTPError:
        with open(core_path+"logs/history.log",'a') as report:
            report.write("[!] Impossible de contacter le serveur - HTTPError\n")
    except requests.exceptions.RequestException:
        with open(core_path+"logs/history.log",'a') as report:
            report.write("[!] Impossible de contacter le serveur - RequestException\n")
    except requests.exceptions.ConnectionError :
        with open(core_path+"logs/history.log",'a') as report:
            report.write("[!] Impossible de contacter le serveur - ConnectionError\n")

    with open(core_path+"/logs/history.log",'a') as report:
        report.write("########### FIN ############ \n")

def file_as_byte(file):
    """
    This function is used to return the content of a file as byte. Used for the MD5 hash of the file in main.py
    """
    with file:
        return file.read()

def get_sha256_hash(path):
    """
    """
    return hashlib.sha256(file_as_byte(open(path, 'rb'))).hexdigest()

def init_json():
    """
    This function init the JSON dict.
    Return : Dictionnary
    """
    data_json = {}
    data_json['login'] = ""
    data_json['hash'] = ""
    data_json['duration'] = 0
    data_json['nbFiles'] = 0
    data_json['nbVirus'] = 0
    data_json['nbErrors'] = 0
    data_json['uuidUsb'] = ""
    data_json['viruses'] = []
    return data_json

def delete_file(path):
    """
    This function
    """
    bashCommand = "rm -f "+path
    subprocess.call(bashCommand.split())

def check_hash(pathHashFile, hash):
    """
    Check if the hash is in the hashfile
    Return True if the hash is in the file
    Return False if not.
    """
    with open(core_path+pathHashFile) as f:
        all_file = f.read()
        if hash in all_file:
            return True
        else:
            return False
            