rm -rf lamb_braai/* 
python firelamb-singe.py -f ~/code/traffic-tracking/wpa/wolves-jun26-1pm-01-dec-carved.cap 
find lamb_braai|grep -i visited|xargs -n1 lynx -dump|grep "\["|cut -d\] -f2|sort| uniq -c|sort -r
