#!/usr/bin/python
# coding: utf-8 

from flask import Flask, request, session, g, redirect, url_for, \
     abort, render_template, flash
from contextlib import closing
import socket
import subprocess

app = Flask(__name__)
app.config.from_object(__name__)

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

@app.route('/zonecheck', methods=['GET','POST'])
def zonecheck():
    domain=""
    res=""
    if request.method == 'POST':
        domain = request.form['domain'].strip().encode('idna')
    
        p = subprocess.Popen(["zonemaster-cli", domain], stdout=subprocess.PIPE)
        result =  p.communicate()[0][:-1]
        res = result

    return render_template('zonemaster.html', domain=domain, res=res)
    
@app.route('/propadns', methods=['GET', 'POST'])
def propadns():
    context = {}
    res=[]
    domain=""
    if request.method == 'POST':
        context['res'] = []
        domain = request.form['domain'].strip().encode('idna')
        context['domain'] = domain
        servers = [ 
            {"ip":"8.8.8.8", "localisation":"google (US)"},
            {"ip":"208.67.222.222", "localisation":"openDNS (US)"},
            {"ip":"8.26.56.26", "localisation":"comodo (US)"},
            {"ip":"156.154.70.1", "localisation":"DNS advantage (US)"},
            {"ip":"198.153.192.50", "localisation":"norton DNS (US)"},
            {"ip":"109.69.8.51", "localisation":"puntCAT (espagne)"},
            {"ip":"89.233.43.71", "localisation":"censurfridns.dk (danemark) "},
            {"ip":"37.235.1.174", "localisation":"FreeDNS (autriche)"},
            {"ip":"195.46.39.39", "localisation":"SafeDNS (Russie)"},
            {"ip":"81.218.119.11", "localisation":"GreenTeamDNS (israel)"},
            {"ip":"84.200.69.80", "localisation":"DNS.WATCH (Allemagne)"},
            {"ip":"187.115.169.179","localisation":"Bresil"},
            {"ip":"211.22.80.180","localisation":"taiwan"},
        ]   
        for server in servers:
            if "ns_check" in request.form.keys():
                p = subprocess.Popen(["dig", domain, "NS", "@{}".format(server["ip"]), "+short"], stdout=subprocess.PIPE)
                result =  p.communicate()[0][:-1]
                ns = result.split("\n")
                nss = sorted(ns)
                result = " - ".join(nss)
                res.append("servers : {1} at {0} ".format(server["localisation"], result))
            else :
                p = subprocess.Popen(["dig", domain, "@{}".format(server["ip"]), "+short"], stdout=subprocess.PIPE)
                result =  p.communicate()[0][:-1]
                res.append("servers : {1} at {0} ".format(server["localisation"], result))

    return render_template('propadns.html', res=res, domain=domain)


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
            domain = domain.strip().encode('idna')
            domains_list.append(domain)
            sorted_doms['.'.join(domain.split('.')[1:]).strip()] = []
        for tld in sorted_doms.keys():
            for dom in domains_list:
                if ".".join(dom.split(".")[1:]) == tld :
                    sorted_doms[tld].append(dom)
    return render_template('sortdom.html', result=sorted_doms)

    

if __name__=="__main__":
    app.run(host='0.0.0.0')

