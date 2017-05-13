from random import randint
from scapy.all import *
from default import PSniffer
from urllib import urlretrieve
from scapy_http import http
from os.path import splitext
from string import ascii_letters

class ImageCap(PSniffer):
    ''' capture image content http'''
    _activated     = False
    _instance      = None
    meta = {
        'Name'      : 'imageCap',
        'Version'   : '1.0',
        'Description' : 'capture image content http',
        'Author'    : 'Pumpkin-Dev',
    }
    def __init__(self):
        for key,value in self.meta.items():
            self.__dict__[key] = value

    @staticmethod
    def getInstance():
        if ImageCap._instance is None:
            ImageCap._instance = ImageCap()
        return ImageCap._instance

    def filterPackets(self,pkt):
        if not pkt.haslayer(http.HTTPRequest):
            return

        http_layer = pkt.getlayer(http.HTTPRequest)
        ip_layer = pkt.getlayer(IP)

        xt = ['.png','.jpg']
        filename, file_extension = splitext(http_layer.fields['Path'])
        if file_extension in xt:
            file_name = 'logs/ImagesCap/%s_%s%s' % (self.session,self.random_char(5), file_extension)
            urlretrieve('http://{}{}'.format(http_layer.fields['Host'], http_layer.fields['Path']),file_name)
            self.output.emit({'image': file_name})

    def random_char(self,y):
           return ''.join(random.choice(ascii_letters) for x in range(y))
