#!/bin/bash
if [ "$(id -u)" != "0" ]; then
   echo "Please run as root" 1>&2
   exit 1
fi
echo '[!] Updating 3viltwinAttacker'
git pull