#!/bin/bash

# Execution main.py avec DISPLAY:0
su - pi -c 'export DISPLAY=:0; bash -c "python3 /opt/Code_Pr00filer/main.py"'


