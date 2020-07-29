#!/bin/bash

# Script d'installation de la station blanche
echo "update du système"
sudo apt update -y
sudo apt upgrade -y

# PyQT5
echo "Installation de PyQt5"
sudo apt-get install build-essential checkinstall -y
sudo apt-get install libreadline-gplv2-dev libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev -y
sudo apt-get install python3-pyqt5 -y
sudo apt-get install pyqt5-dev-tools -y
sudo apt-get install qttools5-dev-tools -y

# Python3 libraries
echo "Installation des librairies Python3"
pip3 install sip
pip3 install --upgrade pip
pip3 install requests

# Création du dossier pi dans media avec les bons droits
echo "Configuration de /media"
cd /media
sudo mkdir pi
sudo chmod a+rwx pi/

# Installation du Code avec GIT
echo "Installation de Pr00filer"
cd /opt/
sudo git clone https://github.com/Pr00filer/Code_Pr00filer.git
sudo chown -R pi Code_Pr00filer

# Installation de clamav 
echo "Installation de clamav"
sudo apt install clamav -y
sudo killall freshclam
sudo freshclam

# Creation de la règle UDEV
echo "Creation de la règle UDEV"
sudo cp /opt/Code_Pr00filer/doc/11-insert-remove-USB.rules /etc/udev/rules.d/11-insert-remove-USB.rules
sudo udevadm control --reload

# Création du SERVICE insertUSB
echo "Creation du SERVICE insertUSB"
sudo cp /opt/Code_Pr00filer/doc/insertUSB.service /etc/systemd/system/insertUSB.service
sudo systemctl enable insertUSB.service
sudo service insertUSB start


