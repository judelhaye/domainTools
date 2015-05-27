#!/usr/bin/python
# coding: utf-8 

from flask import Flask, request, session, g, redirect, url_for, \
     abort, render_template, flash
from contextlib import closing


# configuration
DEBUG = True
SECRET_KEY = 'development key'

# create our little application :)
app = Flask(__name__)
app.config.from_object(__name__)

@app.route("/")
def index():
    urls = {
       'whois-dig':url_for('whois_dig'), 
       'zonecheck':url_for('zonecheck'), 
       'propadns':url_for('propadns'), 
       'getip':url_for('getip'), 
       'sortdom':url_for('sortdom'), 
    }

    return render_template('index.html', urls=urls)


@app.route("/whois-dig")
def whois_dig():
    return render_template('whois-dig.html')

@app.route('/zonecheck')
def zonecheck():
    return render_template('zonecheck.html')
    
@app.route('/propadns')
def propadns():
    return render_template('propadns.html')

@app.route('/getip')
def getip():
    return render_template('getip.html')

@app.route('/sortdom')
def sortdom():
    return render_template('sortdom.html')
    
    

if __name__=="__main__":
    app.run()

