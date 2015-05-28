#!/usr/bin/python
# coding: utf-8 

from flask import Flask, request, session, g, redirect, url_for, \
     abort, render_template, flash
from contextlib import closing
import socket
import subprocess

app = Flask(__name__)
app.config.from_object(__name__)

def whois_gtld(domain):
    p = subprocess.Popen(["whois",domain], stdout=subprocess.PIPE)
    result = p.communicate()[0]
    lines = result.decode('utf-8').split(u"\n")
    datas = {}
    for line in lines : 
        if "Registrar:" in line and "Technical" not in line:
            datas['registrar'] = line.split(":")[1]
        if "Registrant Name:" in line : 
            datas['owner'] = line.split(":")[1]
        if "Domain Status:" in line :
            if 'status' not in datas.keys():
                datas['status'] = "".join(line.split(":")[1:])

    return datas

def whois_me(domain):
    p = subprocess.Popen(["whois",domain], stdout=subprocess.PIPE)
    result = p.communicate()[0]
    lines = result.decode('utf-8').split(u"\n")
    datas = {}
    for line in lines : 
        if "Sponsoring Registrar:" in line:
            datas['registrar'] = line.split(":")[1]
        if "Registrant Name" in line : 
            datas['owner'] = line.split(":")[1]
        if "Domain Status" in line :
            datas['status'] = line.split(":")[1]

    return datas

def whois_fr(domain):
    p = subprocess.Popen(["whois",domain], stdout=subprocess.PIPE)
    result = p.communicate()[0]
    lines = result.decode('utf-8').split(u"\n")
    datas = {}
    for line in lines : 
        if "registrar:" in line:
            datas['registrar'] = line.split(":")[1]
        if "contact" in line : 
            datas['owner'] = line.split(":")[1]
        if "status" in line :
            datas['status'] = line.split(":")[1]

    return datas

def whois_eu(domain):
    p = subprocess.Popen(["whois",domain], stdout=subprocess.PIPE)
    result = p.communicate()[0]
    lines = result.decode('utf-8').split(u"\n")
    datas = {}
    for i, line in enumerate(lines):
        # owner and status are not available on the whois, need to go to web based whois
        datas['owner'] = "NOT DISCLOSED! Visit www.eurid.eu"
        datas['status'] = "NOT DISCLOSED! Visit www.eurid.eu"
        if "Registrar:" in line :
            datas['registrar'] = lines[i+1].split(":")[1]
    return datas

def whois_uk(domain):
    p = subprocess.Popen(["whois",domain], stdout=subprocess.PIPE)
    result = p.communicate()[0]
    lines = result.decode('utf-8').split(u"\n")
    datas = {}
    for i, line in enumerate(lines):
        if "Registrant:" in line :
            datas['owner'] =lines[i+1].strip()
        if "Registrar" in line :
             datas['registrar'] =lines[i+1].strip()
        if "Data validation:" in line :
            datas['status'] = lines[i+1].strip()
    return datas

def whois_be(domain):
    p = subprocess.Popen(["whois",domain], stdout=subprocess.PIPE)
    result = p.communicate()[0]
    lines = result.decode('utf-8').split(u"\n")
    datas = {}
    for i, line in enumerate(lines):
        if "Registrant:" in line :
            datas['owner'] =lines[i+1].strip()
        if "Registrar" in line  and "Technical" not in line :
             datas['registrar'] =lines[i+1].split(":")[1].strip()
        if "Status:" in line :
            datas['status'] = line.split(":")[1].strip()
    return datas


def whois_ovh(domain):
    p = subprocess.Popen(["whois", "-h", "whois.nic.ovh", domain], stdout=subprocess.PIPE)
    result = p.communicate()[0]
    lines = result.decode('utf-8').split(u"\n")
    datas = {}
    for i, line in enumerate(lines):
        if "Registrant Name:" in line :
            datas['owner'] =line.split(":")[1]
        if "Sponsoring Registrar:" in line :
             datas['registrar'] = line.split(":")[1]
        if "Domain Status:" in line :
            datas['status'] = line.split(":")[1]
    return datas

def whois_bzh(domain):
    p = subprocess.Popen(["whois", "-h", "whois.nic.bzh", domain], stdout=subprocess.PIPE)
    result = p.communicate()[0]
    lines = result.decode('utf-8').split(u"\n")
    datas = {}
    for i, line in enumerate(lines):
        if "Registrant Name:" in line :
            datas['owner'] =line.split(":")[1]
        if "Sponsoring Registrar:" in line :
             datas['registrar'] = line.split(":")[1]
        if "Domain Status:" in line :
            datas['status'] = line.split(":")[1]
    return datas



def whois(domain):
    tld = domain.split(".")[-1]
    if tld == "com" or tld == "net" or tld == "org" or tld == "info":
        result = whois_gtld(domain)
    elif tld == "fr" or tld == "re":
        result = whois_fr(domain)
    elif tld == "eu":
        result = whois_eu(domain)
    elif tld == "uk":
        result = whois_uk(domain)
    elif tld == "me":
        result = whois_me(domain)
    elif tld == "ovh":
        result = whois_ovh(domain)
    elif tld == "bzh":
        result = whois_bzh(domain)
    elif tld == "be":
        result = whois_be(domain)
    else:
        result = {'owner':"La recherche whois n'est pas (encore) gérée pour cette extension"}

    return result
        

def digger(dom, trace=False, field='A', exchange=True):
    res = {}
    if not trace:
        if exchange:
            dig_autodiscover_process = subprocess.Popen(["dig", "_autodiscover._tcp.{}".format(dom), "SRV", "+short"], stdout=subprocess.PIPE)
            dig_autodiscover_res = dig_autodiscover_process.communicate()[0][:-1]
            res['discover'] = dig_autodiscover_res
        dig_a_process = subprocess.Popen(["dig", dom, "+short"], stdout=subprocess.PIPE)
        dig_a_res = dig_a_process.communicate()[0][:-1]
        if "\n" in dig_a_res: #multiples A fields
            dig_a_res = " - ".join(dig_a_res.split("\n"))
        if isinstance(dig_a_res, list):
            try:
                host = socket.gethostbyaddr(dig_a_res[0])[0]
            except:
                host = u"impossible de récupérer le nom d'hôte"
        else:
            try:
                host = socket.gethostbyaddr(dig_a_res)[0]
            except:
                host = u"impossible de récupérer le nom d'hôte"
        
        dig_ns_process = subprocess.Popen(["dig", dom, "NS", "+short"], stdout=subprocess.PIPE)
        dig_ns_res = dig_ns_process.communicate()[0][:-1]

        dig_mx_process = subprocess.Popen(["dig", dom, "MX", "+short"], stdout=subprocess.PIPE)
        dig_mx_res = dig_mx_process.communicate()[0][:-1]

        dig_txt_process = subprocess.Popen(["dig", dom, "TXT", "+short"], stdout=subprocess.PIPE)
        dig_txt_res = dig_txt_process.communicate()[0][:-1]

        res['A'] = dig_a_res
        res['HOST'] = host
        res['NS'] = sorted(dig_ns_res.split("\n"))
        res['MX'] = sorted(dig_mx_res.split("\n"))
        res['TXT'] = sorted(dig_txt_res.split("\n"))
    else :
        dig_trace_process = subprocess.Popen(["dig", dom, field, "+trace"], stdout=subprocess.PIPE)
        res['A'] = dig_trace_process.communicate()[0][:-1]

    return res

def dig_on_server(dom, serv):
    dig_to_process = subprocess.Popen(["dig", dom, "@{}".format(serv) , "+short"], stdout=subprocess.PIPE)
    res = dig_to_process.communicate()[0][:-1]
    if res is None:
        res = "Le domaine n'est pas déclaré sur le serveur."
    return res

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


@app.route("/whois-dig", methods=['GET','POST'])
def whois_dig():
    serveur = ""
    trace=False
    dig_result = None
    discover = True
    trace = False
    domain=""
    dig_to = ""
    serveur=""
    whois_dom=""

    if request.method == 'POST':
        discover = True
        domain = request.form['domain'].strip().encode('idna')
        if "trace" in request.form.keys():
            field =  request.form['field']
            dig_result = digger(domain, trace=True, field=field)
            dig_result = dig_result['A'].replace("/n","<br/>")
            dig_to = None
            trace = True

        else:
            dig_result = digger(domain)
            dig_to = None
        whois_dom = whois(domain)
    return render_template('whois-dig.html', domain=domain, whois=whois_dom, dig_to=dig_to, res=dig_result, trace=trace, serv=serveur)

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
    cluster=""
    if request.method == 'POST':
        cluster = request.form['cluster']
        ips = get_cluster_ips(cluster.split("-")[0].strip())
        datas = { 
            'cluster': cluster,
            'ips': ips,
        }   

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

