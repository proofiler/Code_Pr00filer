#!/usr/bin/env python3
#encoding: UTF-8

import os
import hashlib
import requests
import subprocess
from difflib import Differ

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

        if os.path.isfile(path)
            count += 1
        elif os.paht.isdir(path)
            count += fileCount(path)
    return count


def getId_USB():
    """
    This function gets the unique ID of the USB plugged.
    Since this is a low level output, we compare the output of the lsusb command with an USB plugged with the output without an usb plugged.
    The diff will be the USB device.

    return(char) = ID vendor of the usb plugged 
    """

    origin_file = "/opt/Code_Pr00filer/doc/lsusb-empty.txt"
    compare_file = "/tmp/lsusb-output.txt"

    # Save the lsusb output into temp file
    with open("/tmp/lsusb-output.txt","w") as f:
        bashCommand = "lsusb"
        subprocess.call(bashCommand.split(), stdout=f)
    
    # Compare the two file and display the USB line
    with open(origin_file) as file_1, open(compare_file) as file_2:
        differ = Differ()
        for line in differ.compare(file_1.readlines(), file_2.readlines()):
            if line[0] == "+":
                USB_line = line
    USB_line = USB_line.split()
    return USB_line[6]

def createRequest(JSON_list):

nbfile = JSON_list[0]
nbVirus = JSON_list[1]
time_scan = JSON_list[2]
uuid_usb = JSON_list[3]
errors_scan = JSON_list[4]

file_open = open("/opt/Code_Pr00filer/doc/hash_user.txt")
hash_user = file_open.read()

payload = {"login": "ADMIN", "hash":hash_user, "nbFiles" : nbfile, "nbVirus":nbVirus, "timeScan"; time_scan, "UUIDKey":uuid_usb, "Errors": errors_scan}

r = requests.post('http://192.168.1.90:8000', json=payload)
