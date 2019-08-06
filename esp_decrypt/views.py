import os
from . import app
from flask import render_template, request, redirect, url_for, flash
import sys
import re
import csv
from shutil import copyfile

csv_contents = 0

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




