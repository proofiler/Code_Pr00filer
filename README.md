# Pr00filer - Station Blanche / Station de décontamination des clés USB


## À savoir :
Ce projet a été réalisé pour notre projet final d'études.
Il est fontionnel mais pas optimal, vous etes libre d'y contribuer afin de l'améliorer.

## Contexte :

Réalisation d'une station de décontamination automatique des clés USB.
Il y a la possibilité d'ajouter un serveur qui fera office de master pour controler plusieurs station.

**Code du serveur** : https://github.com/proofiler/Proofiler_web

Fonctionnement Raspberry : 
- Monte la clé automatiquement et lance l'application graphique.
- Supprime les fichiers qui ont une extensions interdite dans le fichier de configuration.
- Supprime les fichiers qui ont le même hash déjà détecté comme malveillant par d'autres scan.(Fonctionnalité disponible avec le master)
- Analyse anti-virus avec **ClamAV** ( Utilisation de daemon pour une analyse rapide)
- Vérification et suppression des fichiers avec un check sur **VirusTotal** ( Limité à un certains nombres de requêtes)
- Vérification et suppression des fichiers qui match des **yara-rules**.


Tous les fichiers non conformes seront supprimés sans confirmation.  

## Pré-requis :
- Raspbian Buster
- Raspberry Pi4 (2GB ou plus)
- Connexion Internet (Wi-Fi ou Ethernet)
- Avoir les droits root

## Procédure d'installation avec un script :

Il vous suffit d'executer le scripts `install.sh` dans `scripts/`

**Autoriser Montage automatique des clés USB**
Allez dans les préférences de l'explrateur de fichiers:
- Cochez seulement le montage automatique.

## Config

Un fichier de configuration est présent pour la config de base de l'application.

Il est présent dans : **Code_Pr00filer/config**  
Toutes les informations présentes sont les options par défaut.  **Les modifiers peut compromettre le fonctionnement de l'application pour le moment**

Il contient :
- **VERSION** = La version de l'application (pas utilisé)
- **PATH_SOURCE** = Le chemin absolue vers l'application 
- **PATH_SCAN** = Chemin où la clé USB est analysée.
- **NAME_USER** = Nom de l'utilisateur principal (pas utilisé)
- **ADDR_SERVER** = Contient l'adresse sur serveur master
- **NAME_ADMIN** = Contient le nom de l'utilisateur qui va permettre l'envoie des données dans la Base de données du master.
- **FILE_ADMIN_HASH** =  Chemin vers le fichier qui contient le hash pour l'envoie dans la base de données du master.
- **FILE_CONFIG_HASH** = Contient le hash pour l'authentification de la requête qui est reçu par la raspberry par le serveur.
- **FILE_VIRUS_HASH** = Chemin vers le fichier qui contient les hash des virus utilisé par le module check_hash.
- **CHECK_VIRUSTOTAL_SCRIPT** =  Indique si le module VT est activé (pas utilisé)
- **CHECK_EXTENSIONS_SCRIPT** = Indique si le module Extensions est activé (pas utilisé)
- **DATA_EXTENSIONS_DELETE** = Indique les extensions supprimées par le module check_extensions.
- **YARA_RULES_PATH** = Chemin où se trouvent les yara-rules

## Serveur Raspberry
La raspberry possède un mini serveur python qui sert à récupérer les nouvelles configuration du serveur master.  
Pour le moment, ce serveur récupère et change les options:
- **ADDR_SERVER**
- **DATA_EXTENSIONS_SCRIPT**
- Met à jour les hash présents dans **FILE_VIRUS_HASH**

Le serveur python (server.py) est executé au démarrage de la station et toune en écoute sur le port 8000.   
Il ne reçois les requêtes POST qui contiennent le hash présent dans **FILE_CONFIG_HASH**. Ce hash est unique pour chaque raspberry.  

## Chiffrement
Les communications avec le serveur et la raspberry utilise du chiffrement symétrique AES.

## TO-DO :
[ ] Revoir le script d'installation rapsberry  
[ ] Revoir l'optimisation des modules (dossiers modules)
[ ] Avoir la possibilité d'ajouter ou supprimer des modules facilement
[ ] Revoir la personnalisation du fichier de config(avec install)

Contributeurs:

    Morrigan
    Nyxott
    AlrikRr
    jvallend
