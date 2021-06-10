#!/bin/bash


# Get Mounted device path
mount_point=$(mount -l | grep /media/pi | cut -d " " -f 3)

# Umount 
sudo umount $mount_point


