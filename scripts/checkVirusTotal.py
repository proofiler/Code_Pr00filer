#!/usr/bin/env python3
#encoding: UTF-8


# -------- imports -------- #
import os
import hashlib
import requests
from .configFunctions import *

# ------ Globals ------ #
ConfigPathFile = getConfigPathFile()
usb_path=getPathScan(ConfigPathFile)
core_path=getPathSource(ConfigPathFile)

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

	r = requests.get("https://www.virustotal.com/ui/files/" + an_hash, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36"})

	if r.status_code == 200:
		result_request = r.json()
		if result_request["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
			verificator = 0

			for key, value in result_request["data"]["attributes"]["last_analysis_results"].items():
				if value["result"] != None:
					verificator = verificator + 1

					result[key] = value["result"]

					if verificator == 7:
						break

	return result
def main_checkVirusTotal():
	with open(core_path+"/logs/report.log","a") as report:
		report.write("----------- VIRUS TOTAL -----------\n")
		for item in get_files(usb_path):
			for key, value in check_virus_total(get_sha256_hash(item)).items():
				report.write("{file} - {key} : {value}\n".format(file=item, key=key, value=value))
