# coding: utf-8

import subprocess


def gtld(domain):
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

def me(domain):
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

def fr(domain):
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

def eu(domain):
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

def uk(domain):
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

def be(domain):
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

def bzh(domain):
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
