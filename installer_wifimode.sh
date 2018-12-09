#!/bin/bash
#---------------------------------------
txtund=$(tput sgr 0 1)
txtbld=$(tput bold)
green=$(tput setaf 2)
bldred=${txtbld}$(tput setaf 1)
red_color=$(tput setaf 1)
color_y=$(tput setaf 3)
bldblu=${txtbld}$(tput setaf 4)
bldwht=${txtbld}$(tput setaf 7)
txtrst=$(tput sgr0)
#---------------------------------------


#TODO:  include support to Hostapd-Karma

BIN_DIR="/plugins/bin/hostapd-mana"
INSTALL_DIR="/usr/share/WiFi-Pumpkin$BIN_DIR"
CURRENT_DIR="$(pwd)$BIN_DIR"



func_Banner(){
	clear
	echo '   ============================='
	echo "   |$bldred wifi-pumpkin wireless mode $txtrst|"
	echo '   ============================='
	echo "          Version: $(tput setaf 5)1.0 $txtrst"
}

func_Banner


if [ "$(id -u)" != "0" ]; then
    echo -e "$(tput setaf 6)[-] This script must be run as root$(tput sgr0)" 1>&2
    exit 1
fi

echo "Downloading Hostapd/Mana..."
cd /tmp/

apt-get install -y git
git clone https://github.com/sensepost/hostapd-mana


command=`lsb_release -c |grep -iEe "jessie|kali|sana"`
if [[ ! -z $command ]] 
then
    echo "[$green+$txtrst] CONFIG_LIBNL32=y (Debian Jessie|Kali patch)"

    apt-get -y install libnl-3-dev libnl-genl-3-dev
    
    EXEC="s,^#CONFIG_LIBNL32=y,CONFIG_LIBNL32=y,g"
    sed -i $EXEC hostapd-mana/hostapd/.config
	
	EXEC="s,^#CONFIG_DEBUG_FILE=y,CONFIG_DEBUG_FILE=y,g"
    sed -i $EXEC hostapd-mana/hostapd/.config
    
    echo "[$green+$txtrst] CONFIG_LIBNL32 => $green Ok$txtrst"
    echo
fi

echo "[$bldblu-$txtrst] Compiling binary hostapd-mana"
cd hostapd-mana/hostapd
make


echo "[$green+$txtrst] Install binary hostapd-mana..."

cp hostapd $CURRENT_DIR
cp hostapd_cli $INSTALL_DIR

echo "[$green+$txtrst] hostapd-mana successful installation..."