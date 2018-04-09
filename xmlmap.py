 # -*- coding: utf-8 -*-

import subprocess
import json
import xmltodict
import os

def nmap_scan(ip, argumentos):
    

    try:
        r=subprocess.check_output("nmap "+str(argumentos)+" "+str(ip), shell=True)
        return(r)
        if(r.find("80/tcp  open  http")):
            print("Port 80 is Open!!!")
        else:
            print("Port 80 is Down!!!")
    except:
        print("Error during nmap scan [!]")

def xml_to_json(xml_filename):
    xml_file = str(xml_filename)+".xml"
    fi = open(xml_file)
    xml_content = fi.read()
    fi.close()
    json_converted = json.dumps(xmltodict.parse(xml_content))
    os.system("echo '"+str(json_converted+"' > "+str(xml_filename).replace(".xml", ".json")))
    #os.system("cat "+str(xml_filename))

def json_load(json_filename):
    opened_ports = []
    data = json.load(open((json_filename)))
    nmap_name = data['nmaprun']['@scanner']
    used_args = data['nmaprun']['@args']
    start_time = data['nmaprun']['@startstr']
    nmap_version = data['nmaprun']['@version']
    xml_outputversion = data['nmaprun']['@xmloutputversion']
    scaninfo_type = data['nmaprun']['scaninfo']['@type']
    scaninfo_protocol = data['nmaprun']['scaninfo']['@protocol']
    host_address = data['nmaprun']['host']['address'][0]['@addr']
    host_state = data['nmaprun']['host']['status']['@state']
    host_vendor = data['nmaprun']['host']['address'][1]['@vendor']
    host_ports_miss = data['nmaprun']['host']['ports']['extraports']['@count']
    host_ports_open = 1000 - int(host_ports_miss)
    ports = host_ports_miss = data['nmaprun']['host']['ports']['port']
    for i in range(0, host_ports_open):
        opened_ports.append(ports[i]['@portid'])
    
        
    print("Portas abertas do Host: "+host_address+" sao: "+str(len(opened_ports)-1))   
        
            
 
