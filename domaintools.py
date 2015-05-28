#!/usr/bin/python
# coding: utf-8 

from flask import Flask, request, session, g, redirect, url_for, \
     abort, render_template, flash
from contextlib import closing
import socket


app = Flask(__name__)
app.config.from_object(__name__)

DEBUG=True


def get_cluster_ips(cluster):
    ips = {}
    ips["directe sans cache"] = socket.gethostbyname('direct.{}.ovh.net'.format(cluster)) 
    ips["ip classique"] = socket.gethostbyname('{}.ovh.net'.format(cluster)) 
    ips["CDN 3 POP"] = socket.gethostbyname('basic-cdn-01.{}.ovh.net'.format(cluster)) 
    ips["CDN 17 POP"] = socket.gethostbyname('full-cdn-01.{}.ovh.net'.format(cluster)) 
    return ips 

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

@app.route('/getip', methods=['GET', 'POST'])
def getip():
    ips={}
    if request.method == 'POST':
        cluster = request.form['cluster']
        ips = get_cluster_ips(cluster.split("-")[0].strip())
        datas = { 
            'cluster': cluster,
            'ips': ips,
        }   

    else:
        context={}

    return render_template('getip.html', ips=ips, cluster=cluster)

@app.route('/sortdom', methods=['GET', 'POST'])
def sortdom():
    sorted_doms = {}
    if request.method == 'POST':
        doms = request.form['domains']
        domains = doms.split("\r\n")
        # get all domains and tlds in the file
        extensions =[]
        domains_list=[]
        for domain in domains:
            if "." not in domain:
                #pas de point = pas de domaine = osef
                continue
            domain = domain.strip().decode('utf8').encode('idna')
            domains_list.append(domain)
            sorted_doms['.'.join(domain.split('.')[1:]).strip()] = []
        for tld in sorted_doms.keys():
            for dom in domains_list:
                if ".".join(dom.split(".")[1:]) == tld :
                    sorted_doms[tld].append(dom)
    return render_template('sortdom.html', result=sorted_doms)

    

if __name__=="__main__":
    app.run(host='0.0.0.0')

