#!/usr/bin/python
# coding: utf-8

from flask import Flask, request, url_for, render_template
import socket
import subprocess
import whois_helper

app = Flask(__name__)
app.config.from_object(__name__)
app.debug = True

def whois(domain):
    tld = domain.split(b'.')[-1]
    if tld == "com" or tld == "net" or tld == "org" or tld == "info":
        result = whois_helper.gtld(domain)
    elif tld == "fr" or tld == "re":
        result = whois_helper.helper.fr(domain)
    elif tld == "eu":
        result = whois_helper.eu(domain)
    elif tld == "uk":
        result = whois_helper.uk(domain)
    elif tld == "me":
        result = whois_helper.me(domain)
    elif tld == "ovh":
        result = whois_helper.ovh(domain)
    elif tld == "bzh":
        result = whois_helper.bzh(domain)
    elif tld == "be":
        result = whois_helper.be(domain)
    else:
        result = {'owner':"La recherche whois n'est pas (encore) \
                    gérée pour cette extension"}
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
        if "\n" in str(dig_a_res): #multiples A fields
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
        dig_ns_res = str(dig_ns_process.communicate()[0][:-1])

        dig_mx_process = subprocess.Popen(["dig", dom, "MX", "+short"], stdout=subprocess.PIPE)
        dig_mx_res = str(dig_mx_process.communicate()[0][:-1])

        dig_txt_process = subprocess.Popen(["dig", dom, "TXT", "+short"], stdout=subprocess.PIPE)
        dig_txt_res = str(dig_txt_process.communicate()[0][:-1])

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



@app.route("/")
def index():
    return render_template('index.html')


@app.route("/whois-dig", methods=['GET','POST'])
def whois_dig():
    serveur = ""
    trace=False
    dig_result = None
    discover = ""
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

@app.route('/sortdom', methods=['GET', 'POST'])
def sortdom():
    sorted_doms = {}
    if request.method == 'POST':
        doms = request.form['domains']
        domains = sorted(doms.split("\r\n"))
        # get all domains and tlds in the file
        extensions =[]
        domains_list=[]
        for domain in domains:
            if "." not in domain:
                #pas de point = pas de domaine = osef
                continue
            domain = str(domain.strip().encode('idna'))
            domains_list.append(domain)
            sorted_doms['.'.join(domain.split('.')[1:]).strip()] = []
        for tld in sorted_doms.keys():
            for dom in domains_list:
                if ".".join(dom.split(".")[1:]) == tld :
                    sorted_doms[tld].append(dom)
    return render_template('sortdom.html', result=sorted_doms)

@app.route("/rbl", methods=['GET', 'POST'])
def rbl():
    res=[]
    fail=[]
    if request.method=='POST':
        ip = request.form['ip']
        res, fail = rbl_check(ip)
    return render_template('rbl-check.html', result=res, failed=fail)


@app.route('/mail_header', methods=['GET', 'POST'])
def mail_header():
    data = {}
    if request.method == 'POST':
        header = request.form['header']
        head = header.split('\n')
        for line in head :
            value = ""
            if ":" in line :
                keyword = line.split(':')[0]
                values_array = line.split(':')[1:]
                if len(values_array) > 1:
                    value = " ".join(values_array)
                else :
                    value = values_array[0]
                data[keyword] = value
    return render_template('mail_header.html', result=data)


if __name__=="__main__":
    app.run(host='0.0.0.0')
