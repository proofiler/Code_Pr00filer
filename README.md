# Projet Annuel : Réalisation d'un station blanche

## Groupe 20 - 4SI4:

- Jennifer BONILLO
- Kevin PETTA
- Joris VAILLAND
- Adrien LASALLE

## Contexte :

Réalisation d'un station de décontamination automatique des clés USB.  

- Vérification des virus avec clamAV
- Vérification des hashs de fichiers avec VirusTotal
- Vérification des extensions de fichiers

Tous les fichiers non conformes sont supprimés.  

## Procédure d'installation :

**Pré-requis**
- Raspbian Buster
- Raspberry Pi4 (2GB ou plus)
- Connexion Internet
- Avoir les droits root

---

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

**Installation ClamScan avec le script**
```
i@raspberrypi:/opt/ProjetAnnuel/scripts $ ./install_conf_clamav.sh 
```
---

**Installation de l'application avec git**
```
cd /opt/
sudo git clone https://github.com/Pr00filer/Code_Pr00filer.git
sudo chown -R pi Code_Pr00filer
```

---

**Création de la règle UDEV**
```
sudo vim /etc/udev/rules.d/11-automout.rules
```

```
ACTION=="add", SUBSYSTEM=="block", ENV{SYSTEMD_WANTS}+="insertUSB.service"
ACTION=="remove", SYBSYSTEM=="block", RUN+="/opt/Code_Pr00filer/scripts/removeUSB.sh"
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
ExecStart=/opt/ProjetAnnuel/scripts/insertUSB.sh

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


