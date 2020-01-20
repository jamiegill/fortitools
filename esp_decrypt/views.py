import os
from . import app
from flask import render_template, request, redirect, url_for, flash, send_file
import sys
import re
import csv
from shutil import copyfile

csv_contents = 0
line_extract = []

@app.route("/")
def get_root():
     return render_template("main_page.html")

@app.route("/sa_list/", methods=["GET", "POST"])
def get_sa():
    def alg_map(alg, bits):
        try:
            alg_bits = alg + ' ' + bits
            dictionary = {
            "des 8": "DES-CBC [RFC2405]",
            "3des 24": "TripleDES-CBC [RFC2451]",
            "aes 16": "AES-CBC [RFC3602]",
            "aes 24": "AES-CBC [RFC3602]",
            "aes 32": "AES-CBC [RFC3602]",
            "aes-gcm 20": "AES-GCM [RFC4106]",
            "aes-gcm 36": "AES-GCM [RFC4106]",
            "sha1 20": "HMAC-SHA-1-96 [RFC2404]",
            "sha256 32": "HMAC-SHA-256-128 [RFC4868]",
            "sha384 48": "HMAC-SHA-384-192 [RFC4868]",
            "sha512 64": "HMAC-SHA-512-256 [RFC4868]",
            "null 0": "ANY 128 bit authentication [no checking]",
            }
            wshark_val = dictionary[alg_bits]
            return wshark_val
        except:
            return "NOT SUPPORTED"
    
    if os.path.exists("esp_decrypt/wireshark_sa.csv"):
        os.remove("esp_decrypt/wireshark_sa.csv")
    if os.path.exists("esp_decrypt/diag_vpn_tunnel_list.txt"):
        os.remove("esp_decrypt/diag_vpn_tunnel_list.txt")
    
    if request.method == 'POST':
        tunnel_list_form = request.form["tunnel_list_form"]
        
        with open('esp_decrypt/diag_vpn_tunnel_list.txt', 'w') as tunnel_list:
            tunnel_list.write(tunnel_list_form)

        input_list=open("esp_decrypt/diag_vpn_tunnel_list.txt").readlines()
    
    for line in input_list:
        if 'name=' in line:
            if "dst_mtu=" in line:   #6.2.0 and above
                both_ip = line.strip().rsplit(' ', 2)[1]
            else:                    #before 6.2.0
                both_ip = line.strip().rsplit(' ', 1)[1]
            print ("both_ip: {}".format(both_ip))
            if "4500" in both_ip:
                local_pub = re.split(':4500|->', both_ip)[0]
                remote_pub = re.split(':4500|->', both_ip)[2]
            else:
                local_pub = re.split(':0|->', both_ip)[0]
                remote_pub = re.split(':0|->', both_ip)[2]
                
            print ("Local Public: {}".format(local_pub))
            print ("Remote Public: {}".format(remote_pub))
        if 'spi=' in line:
            spi = line.split()[1].split("=")[1]
            enc_key = line.split()[4]
            enc_alg = line.split()[2].split("=")[1]
            enc_bits = line.split()[3].split("=")[1]
            hash_key = line.split()[4]
            wshark_enc = alg_map(enc_alg,enc_bits)
            #print ("SPI: {}".format(spi))
            #print ("Encryption Key: {}".format(enc_key))
            #print ("Encryption Alg: {}".format(enc_alg))
            #print ("Encryption Bits: {}".format(enc_bits))
            #print ("WShark Enc: {}".format(wshark_enc))
            if 'dec:' in line:
                first_ip = remote_pub
                second_ip = local_pub
            else:
                first_ip = local_pub
                second_ip = remote_pub        
    
        if 'ah=' in line:
            global csv_contents
            try:
                hash_key = line.split()[2]
            except:       #ie. in the case of alg = aes-gcm
                hash_key = "0"    
            hash_alg = line.split()[0].split("=")[1]
            hash_bits = line.split()[1].split("=")[1]
            wshark_hash = alg_map(hash_alg,hash_bits)
            #print ("Hash Key: {}".format(hash_key))
            #print ("Hash Alg: {}".format(hash_alg))
            #print ("Hash Bits: {}".format(hash_bits))
            #print ("WShark Hash: {}".format(wshark_hash))
            wshark_sa = ['IPv4', first_ip, second_ip, "0x"+spi, wshark_enc, "0x"+enc_key, wshark_hash, "0x"+hash_key]
            #print(wshark_sa)
            with open('esp_decrypt/wireshark_sa.csv', mode='a') as csvfile:
            #with open('esp_decrypt/wireshark_sa.csv', mode='a') as csvfile:
                csv_write = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
                csv_write.writerow(wshark_sa)
            csv_contents = open('esp_decrypt/wireshark_sa.csv', 'r').read()
     
    return render_template("sa_list.html", csv_contents=csv_contents)

@app.route("/ttl_script/", methods=["GET", "POST"])
def get_teraterm():
    sleep_time = request.form["teraterm_sleep"]
    if os.path.exists("esp_decrypt/teraterm_script.txt"):
        os.remove("esp_decrypt/teraterm_script.txt")
    if request.method == 'POST':
        teraterm_contents = request.form["teraterm_form"].splitlines(0)
    with open('esp_decrypt/teraterm_script.txt', mode='a') as ttlfile:
        ttlfile.write("while 1\n")
    for line in teraterm_contents:
        ttl_command = ("    sendln '{}'\n".format(line))
        ttl_wait = ("    wait '#'\n".format(line))
        with open('esp_decrypt/teraterm_script.txt', mode='a') as ttlfile:
            ttlfile.write(ttl_command)
            ttlfile.write(ttl_wait)
    with open('esp_decrypt/teraterm_script.txt', mode='a') as ttlfile:
        ttlfile.write("    pause {}\n".format(sleep_time))
        ttlfile.write("endwhile\n")
    teraterm_contents = open('esp_decrypt/teraterm_script.txt', 'r').read()
    return render_template("teraterm_script.html", teraterm_contents=teraterm_contents)

@app.route("/address_object", methods=["GET", "POST"])
def get_addr_obj():
    with open('esp_decrypt/temp_files/addr_object.txt', 'w') as addr_obj_list:
        addr_obj_list.write(request.form["addr_obj_form"])	 
    
    config_list=open("esp_decrypt/temp_files/addr_object.txt").readlines()
    
    #this function accepts a start and end line pattern and extracts all lines in between the two patterns  
    def pattern_extract(start_del, end_del, config_in):
        inside_group = False
        line_extract = []
        for line in config_in:
            if line.startswith(start_del):
                inside_group = True
            if inside_group:
                line_extract.append(line.rstrip('\n'))
                if line.startswith(end_del):
                    inside_group = False
        return(line_extract)
 
    #this function will take the config and an address object name, and find the value associated with that name         
    def addr_value_extract(address_name, config_in):
        address_type = []
        start_ip = []
        end_ip = []
        start_mac = []
        end_mac = []
        address_value = []
        indiv_address = pattern_extract('    edit "{}"'.format(address_name), "    next", config_in)
        for line in indiv_address:
            if line.startswith('        set type'):           #covers any case other than default(set type 'ipmask')
                address_type = (line.split()[2])
            elif line.startswith('        set subnet'):       #covers default 'ipmask' type --> ie. this assumes no 'set type' command is in config
                address_value = (line.split()[2] +" "+ line.split()[3])
                address_type = "ipmask"
            
            if "iprange" in address_type:
                if line.startswith('        set start-ip'): 
                    start_ip = line.split()[2]
                if line.startswith('        set end-ip'):
                    end_ip = line.split()[2]
                address_value = ("{} - {}".format(start_ip,end_ip))
            elif "fqdn" in address_type:
                if line.startswith('        set fqdn'):
                    address_value = line.split()[2][1:-1]          #remove first and last quote
            elif "geography" in address_type:
                if line.startswith('        set country'):
                    address_value = line.split()[2][1:-1]          #remove first and last quote
            elif "mac" in address_type:
                if line.startswith('        set start-mac'): 
                    start_mac = line.split()[2]
                if line.startswith('        set end-mac'):
                    end_mac = line.split()[2]
                address_value = ("{} - {}".format(start_mac,end_mac))
        
        if not address_value:
           address_value = "0.0.0.0/0"
        
        return(address_value)
       
                
    all_addresses = pattern_extract("config firewall address", "end", config_list)
    address_name_list = []
    
    f = open("/home/fortinet/Documents/Python/esp_decrypt/esp_decrypt/temp_files/addr_search.html", "r")
    html_file = f.readlines()
    f.close()
    
    
    # Obtain address name and address value pairs, and append to html_file
    for line in all_addresses:
        if line.startswith('    edit "'):
            address_name = line.split('"')[1] #parses between the quotations
            address_name_list.append(address_name)
            addr_value = addr_value_extract(address_name,config_list)
            add_record = '<li><a href="#">{} - <font color="green">{}</font></a></li>'.format(address_name, addr_value)
            html_file.insert(74, add_record)
            #print("{}: {}".format(address_name,addr_value))
     
    # Obtain group name to find address name and address value pairs, and append to html_file        
    all_groups = pattern_extract("config firewall addrgrp", "end", config_list)
    group_name_list = []
    for line in all_groups:
       if line.startswith('    edit "'):
           group_name = line.split('"')[1] #parses between the quotations
           group_name_list.append(group_name)
    for line in group_name_list:
        indiv_group = pattern_extract('    edit "{}"'.format(line), "    next", all_groups)
        for group_line in indiv_group:
            if group_line.startswith('        set member "'):
                print(group_line.split('"'))
         
       
    try:
        os.remove("/home/fortinet/Documents/Python/esp_decrypt/esp_decrypt/temp_files/addr_search_results.html")
    except:
        pass
        
    f = open("/home/fortinet/Documents/Python/esp_decrypt/esp_decrypt/temp_files/addr_search_results.html", "w+")
    html_file = "".join(html_file)
    f.write(html_file)
    f.close()
    
    return send_file('/home/fortinet/Documents/Python/esp_decrypt/esp_decrypt/temp_files/addr_search_results.html', as_attachment=True)

