#!/bin/bash

#Kill the main script but not the server
#pkill -9 python
ps aux |grep python |grep -v '/opt/Code_Pr00filer/server.py' |awk '{print $2}' |xargs kill
