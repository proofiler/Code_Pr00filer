#!/usr/bin/env python3
#encoding: UTF-8

# This file is used to parse data within the config file.
# Those functions are moslty used to get informations.



def getConfigPathFile():
    ConfigPathFile = "/opt/Code_Pr00filer/config"
    return ConfigPathFile

def getVersion(ConfigPathFile):
    """
    return the VERSION number : string
    """
    version = "none"
    line = ""
    line_split = ""
    with open(ConfigPathFile) as conf:
        for line in conf:
            line_split = line.split()
            if line_split[0] == "VERSION":
                version = line_split[2]
    return version

def getPathSource(ConfigPathFile):
    """
    return the Path of the code source (default /opt/Code_Pr00filer/) : string
    """
    PathSource = "/opt/Code_Pr00filer/"
    line = ""
    line_split = ""
    with open(ConfigPathFile) as conf:
        for line in conf:
            line_split = line.split()
            if line_split[0] == "PATH_SOURCE":
                PathSource = line_split[2]
    return PathSource

def getPathScan(ConfigPathFile):
    """
    return the absolut path in wich the usb is mounted and scanned : string
    """
    PathScan = "/media/pi/"
    line = ""
    line_split = ""
    with open(ConfigPathFile) as conf:
        for line in conf:
            line_split = line.split()
            if line_split[0] == "PATH_SCAN":
                PathScan = line_split[2]
    return PathScan

def getAddrServer(ConfigPathFile):
    """
    return the server address : string
    """
    AddrServer = "none"
    line = ""
    line_split = ""
    with open(ConfigPathFile) as conf:
        for line in conf:
            line_split = line.split()
            if line_split[0] == "ADDR_SERVER":
                AddrServer = line_split[2]
    return AddrServer

def getNameAdmin(ConfigPathFile):
    """
    return the admin name used to send data to the database : string
    """
    NameAdmin = "admin"
    line = ""
    line_split = ""
    with open(ConfigPathFile) as conf:
        for line in conf:
            line_split = line.split()
            if line_split[0] == "NAME_ADMIN":
                NameAdmin = line_split[2]
    return NameAdmin

def getFileAdminHash(ConfigPathFile):
    """
    return the path where is stored the admin hash used to send data to the database : string
    """
    FileAdminHash = "doc/hash_user.txt"
    line = ""
    line_split = ""
    with open(ConfigPathFile) as conf:
        for line in conf:
            line_split = line.split()
            if line_split[0] == "FILE_ADMIN_HASH":
                FileAdminHash = line_split[2]
    return FileAdminHash

def getFileConfigHash(ConfigPathFile):
    """
    return the path where is stored the hash used to received data from the server : string
    """
    FileConfigHash = "doc/hash_config.txt"
    line = ""
    line_split = ""
    with open(ConfigPathFile) as conf:
        for line in conf:
            line_split = line.split()
            if line_split[0] == "FILE_CONFIG_HASH":
                FileConfigHash = line_split[2]
    return FileConfigHash

def getFileVirusHash(ConfigPathFile):
    """
    return the path where is stored the hash of the virus : string
    """
    FileVirusHash = "doc/hash_virus.txt"
    line = ""
    line_split = ""
    with open(ConfigPathFile) as conf:
        for line in conf:
            line_split = line.split()
            if line_split[0] == "FILE_VIRUS_HASH":
                FileVirusHash = line_split[2]
    return FileVirusHash

def getCheckVirusTotalScript(ConfigPathFile):
    """
    return the value True or False for CheckVirusTotal Script : Boolean
    """
    CheckVirusTotalScript = "True"
    line = ""
    line_split = ""
    with open(ConfigPathFile) as conf:
        for line in conf:
            line_split = line.split()
            if line_split[0] == "CHECK_VIRUSTOTAL_SCRIPT":
                if line_split[2] == "True":
                    CheckVirusTotalScript = True
                else:
                    CheckVirusTotalScript = False

    return CheckVirusTotalScript

def getCheckExtensionsScript(ConfigPathFile):
    """
    return the value True or False for CheckExtenions Script : Boolean
    """
    CheckExtensionsScript = "True"
    line = ""
    line_split = ""
    with open(ConfigPathFile) as conf:
        for line in conf:
            line_split = line.split()
            if line_split[0] == "CHECK_EXTENSIONS_SCRIPT":
                if line_split[2] == "True":
                    CheckExtensionsScript = True
                else:
                    CheckExtensionsScript = False

    return CheckExtensionsScript

def getDataExtensionsDelete(ConfigPathFile):
    """
    return all the extenions checked into the CheckExtensions Script : array
    """
    DataExtensionsDelete = []
    line = ""
    line_split = ""
    Temp_split = ""
    with open(ConfigPathFile) as conf:
        for line in conf:
            line_split = line.split()
            if line_split[0] == "DATA_EXTENSIONS_DELETE":
                Temp_split = line_split[2]
                DataExtensionsDelete = Temp_split.split(",")
    return DataExtensionsDelete
