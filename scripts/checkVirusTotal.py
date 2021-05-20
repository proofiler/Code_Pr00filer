#!/usr/bin/env python3
#encoding: UTF-8


# -------- imports -------- #
import os
import hashlib
import requests
from .configFunctions import *

# ------ Globals ------ #
ConfigPathFile = getConfigPathFile()
pathUSB=getPathScan(ConfigPathFile)
pathCORE=getPathSource(ConfigPathFile)

def get_files(a_directory_name):
	'''Get all files of the USB

	Args:
		a_directory_name (string): The USB key full path

	Return:
		files (array of strings): All files name (full path) of the USB key
	'''

	files = []

	for root, directories, filenames in os.walk(a_directory_name):
		for filename in filenames:
			files.append(os.path.join(root, filename))

	return files

def get_sha256_hash(a_file):
	'''Get the SHA-256 hash of a file

		Args:
			a_file (string): The full path file

		Return:
			sha256_hash (string): The SHA-256 of a file
	'''

	sha256_hash = hashlib.sha256()

	with open(a_file, "rb") as f:
		for byte_block in iter(lambda: f.read(4096), b""):
			sha256_hash.update(byte_block)
	return sha256_hash.hexdigest()

def check_virus_total(an_hash):
    '''Send the hash of the file on VirusTotal to check if it is a virus

        Args:
            an_hash (string): The hash of a file

        Return:
            ?
    '''

    result = {}

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "content-type": "application/json",
        "X-Tool": "vt-ui-main",
        "X-VT-Anti-Abuse-Header": "a",
        "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8"
    }

    r = requests.get("https://www.virustotal.com/ui/files/" + an_hash, headers=headers)

    if r.status_code == 200:
        result_request = r.json()
        if result_request["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
            verificator = 0

            for key, value in result_request["data"]["attributes"]["last_analysis_results"].items():
                if value["result"] != None:
                    verificator = verificator + 1

                    result[key] = value["result"]

                    if verificator == 1:
                        break
    else:
        print(r.status_code)
    return result
def main_checkVirusTotal():
	with open(pathCORE+"/logs/tmp_virustotal.log","w") as report:
            for item in get_files(pathUSB):
                for key, value in check_virus_total(get_sha256_hash(item)).items():
                    report.write("{file} - {key} : {value}\n".format(file=item, key=key, value=value))
                    print("{file} - {key} : {value}\n".format(file=item, key=key, value=value))

