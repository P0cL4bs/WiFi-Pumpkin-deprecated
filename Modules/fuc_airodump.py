from BeautifulSoup import BeautifulSoup
from os import popen
def airdump_start():
    get = (popen("""sudo xterm -geometry 85x15-1+250 -T "Scan Networks Airodump-ng" -e airodump-ng mon0 --write \
     Settings/Dump/networkdump & airodump=$!""").read()) + "exit"
    while get != "dsa":
        if get == "exit":
            break
    return None

def get_network_scan():
    list_scan = []
    try:
        xml = BeautifulSoup(open("Settings/Dump/networkdump-01.kismet.netxml", 'r').read())
        for network in xml.findAll('wireless-network'):
                essid = network.find('essid').text
                if not essid:
                        essid = 'Hidden'
                channel = network.find('channel').text
                bssid = network.find('bssid').text
                list_scan.append(channel + "||" + essid + "||" + bssid)
        popen("rm Settings/Dump/networkdump-01.*")
        return list_scan
    except IOError:
        return None