# Pr00filer - Station Blanche / Station de décontamination des clés USB

## À savoir :
Ce projet est toujours en cours de développement.  
Les images de sensibilation utilisée pour le moment proviennent du projet [USBGuardian](https://github.com/USBGuardian/USBGuardian) afin de servir d'exemple.


## Contexte :

Réalisation d'une station de décontamination automatique des clés USB.  

- Vérification des fichiers malveillant avec l'anti-virus clamAV.
- Vérification des hashs de fichiers avec VirusTotal.
- Vérification des extensions des fichiers pr"sent sur la clé USB.

Tous les fichiers non conformes seront supprimés sans confirmation.  

## Pré-requis :
- Raspbian Buster
- Raspberry Pi4 (2GB ou plus)
- Connexion Internet (Wi-Fi ou Ethernet)
- Avoir les droits root

## Procédure d'installation avec un script :

Il vous suffit d'executer le scripts `install.sh` dans `scripts/`

## Procédure d'installation manuelle :

**Installation PyQt5**
```
$ sudo apt-get install build-essential checkinstall
$ sudo apt-get install libreadline-gplv2-dev libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev
$ sudo apt-get install python3-pyqt5  
$ sudo apt-get install pyqt5-dev-tools
$ sudo apt-get install qttools5-dev-tools
```

---

**Installation  librairies Python3**
```
pi@raspberrypi:$ pip3 install sip
pi@raspberrypi:$ pip3 install --upgrade pip
pi@raspberrypi:$ pip3 install requests
```

---


**Gestion des droits sur /media/pi**
```
pi@raspberrypi:$ cd /media
pi@raspberrypi:/media $ sudo mkdir pi 
pi@raspberrypi:/media $ sudo chmod a+rwx pi/
```

---

**Installation de l'application avec git**
```
cd /opt/
sudo git clone https://github.com/Pr00filer/Code_Pr00filer.git
sudo chown -R pi Code_Pr00filer
```

---

**Installation ClamScan avec le daemon**
```
sudo apt install clamav clamdscan clamav-daemon -y
sudo killall freshclam
sudo freshclam
sudo service clamav-daemon start
```

---

**Création de la règle UDEV au montage de la clé**
```
sudo vim /etc/udev/rules.d/11-insert.rules
```

```
ACTION=="add", SUBSYSTEM=="block", ENV{SYSTEMD_WANTS}+="insertUSB.service"
```

**Création de la règle UDEV au démontage de la clé**
```
sudo vim /etc/udev/rules.d/11-remove.rules
```

```
ACTION=="remove", SUBSYSTEM=="block",RUN+="/opt/Code_Pr00filer/scripts/removeUSB.sh"
```

```
sudo udevadm control --reload
```

---

**Création du service insertUSB.sh**
```
sudo vim  /etc/systemd/system/insertUSB.service
```

```
[Unit]
Description= When a USB stick is plugged

[Service]
Type=oneshot

Environment=DISPLAY=:0
ExecStart=/opt/Code_Pr00filer/scripts/insertUSB.sh

[Install]
WantedBy=multi-user.target
```

```
sudo systemctl enable insertUSB.service
sudo service insertUSB start
```

---

**Autoriser Montage automatique des clés USB**
Allez dans les préférences de l'explrateur de fichiers:
- Cochez seulement le montage automatique.


