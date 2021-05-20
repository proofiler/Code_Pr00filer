import socket
import base64
import json
import os
import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO

## --- Scripts --- ##
from scripts import *

## --- Globals -- ##

# Path of the configFile
ConfigPathFile = configFunctions.getConfigPathFile()
# Path of the main CORE
pathCORE = configFunctions.getPathSource(ConfigPathFile)
# Path of the virus hash file
pathVirusFile = configFunctions.getFileVirusHash(ConfigPathFile)
#Path of the config hash file
pathConfigHashFile = configFunctions.getFileConfigHash(ConfigPathFile)

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Hello, world!')

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        ip_from = self.client_address[0]
        # Reception du message en post
        body = self.rfile.read(content_length)
        self.send_response(200)
        self.end_headers()
        response = BytesIO()
        # envoie de la réponse au serveur OK
        # Décodage byte vers str
        data_raw = body.decode()
        data_split = data_raw.split("=")
        if data_split[0] == "data":
            
            # Récupération du base64 en retirant 'data=' au début
            data_64 = data_raw[5:]
            # Décodage du base64, try except car si c'est pas du b64 il y aura une erreur
            data_decode = base64.b64decode(data_64)
            data_decode = data_decode.decode()
            # Forge au format JSON
            data_json = json.loads(data_decode)
            # Récupère le hash et check si correcpond au hash dans le fichier
            hash_check = data_json['hash']

            ## --- Lecture du fichier ConfigHashFile qui contient le hash à tester
            with open(pathCORE+pathConfigHashFile,'r') as hashfile:
                hash_origin = hashfile.read()
            if hash_check.rstrip() == hash_origin.rstrip():
                ## --- ADDR_SERVER
                new_server = data_json['ip']
                true_server = "http://"+new_server+"/Web_Pr00filer/data"
                bashCommand = "sed -i '/ADDR_SERVER /c\ADDR_SERVER = "+true_server+"'"+" "+ConfigPathFile
                os.system(bashCommand)
               
                ## --- DATA_EXTENSIONS_DELETE
                check =  0 # Sert à ne pas mettre de virgule au début pour pas casser le parsage des extenions
                for extension in data_json['extensions']:
                    if check == 0:
                        ext_parse = "."+extension
                        check = 1
                    else:
                        ext_parse += ",."+extension
                bashCommand = "sed -i '/DATA_EXTENSIONS_DELETE /c\DATA_EXTENSIONS_DELETE = "+ext_parse+"'"+" "+ConfigPathFile
                os.system(bashCommand)

                ## --- Virus Hash File 
                with open(pathCORE+pathVirusFile,'w') as virus_list:
                    for sha2hash in data_json['viruses']:
                        virus_list.write(sha2hash+"\n")
                
                response.write(b'Received: Config Updated')
                self.wfile.write(response.getvalue())
                ## --- History.log
                with open(pathCORE+'/logs/history.log','a') as report:
                    dt_string = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                    report.write("########### Config Update : "+dt_string+" ##########\n")
                    report.write("From : "+ip_from+"\n")
                    report.write("ADDR_SERVER : "+true_server+"\n")
                    report.write("DATA_EXTENSIONS_DELETE : "+ext_parse+"\n")
                    report.write("[!] Virus Hash List Updated\n")
                    report.write("########### Config Update END ###########\n")

            else:
                response.write(b'Received: Wrong Hash')
                self.wfile.write(response.getvalue())
        else:
            response.write(b'Received: POST error')
            self.wfile.write(response.getvalue())

ipv4 = get_ip_address()
print(ipv4)
httpd = HTTPServer((ipv4, 8000), SimpleHTTPRequestHandler)
httpd.serve_forever()
