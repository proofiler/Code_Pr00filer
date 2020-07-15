#!/bin/bash

echo "Afficher l'output des commandes ? [o/n]"
read inputuser

output=""

if [ "$inputuser" == "o" ]; then
        output=""
elif [ "$inputuser" == "n" ]; then
        output=" > /dev/null 2>&1"
else
        echo "ERREUR : <usage> [o/n]"
        exit
fi

#Mise à jour
eval sudo apt update $output
eval sudo apt upgrade $output
echo "[+] Mise à jour du système"

# Installation de clamav
eval sudo apt install clamav $output
echo "[+] Installation de clamav"

# Mise à jour de la base viral
eval sudo killall freshclam $output
eval sudo freshclam $output
echo "[+] Base Virale mise à jour"

# Freshclam 1 fois par jour
eval sudo sed -i '/s/24/1/g' /etc/clamav/freshclam.conf $output
echo "[+] Modification freshclam.conf"
