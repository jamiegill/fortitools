    import sys
    import re
    import csv
    
    def alg_map(alg, bits):
        try:
            alg_bits = alg + ' ' + bits
            dictionary = {
            "des 8": "DES-CBC [RFC2405]",
            "3des 24": "TripleDES-CBC [RFC2451]",
            "aes 16": "AES-CBC [RFC3602]",
            "aes 24": "AES-CBC [RFC3602]",
            "aes 32": "AES-CBC [RFC3602]",
            "md5 16": "HMAC-MD5-96 [RFC2403]",
            "sha1 20": "HMAC-SHA-1-96 [RFC2404]",
            "sha256 32": "HMAC-SHA-256-128 [RFC4868]",
            "sha384 48": "HMAC-SHA-384-192 [RFC4868]",
            "sha512 64": "HMAC-SHA-512-256 [RFC4868]",
            }
            wshark_val = dictionary[alg_bits]
            return wshark_val
        except:
            return "NOT SUPPORTED"
    
    input_list = open("diag_vpn_tunnel_list.txt", "r")
    for line in input_list:
        if 'name=' in line:
            both_ip = line.strip().split()[3]
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
            hash_key = line.split()[2]
            hash_alg = line.split()[0].split("=")[1]
            hash_bits = line.split()[1].split("=")[1]
            wshark_hash = alg_map(hash_alg,hash_bits)
            #print ("Hash Key: {}".format(hash_key))
            #print ("Hash Alg: {}".format(hash_alg))
            #print ("Hash Bits: {}".format(hash_bits))
            #print ("WShark Hash: {}".format(wshark_hash))
            wshark_sa = ['IPv4', first_ip, second_ip, "0x"+spi, wshark_enc, "0x"+enc_key, wshark_hash, "0x"+hash_key]
            print(wshark_sa)
            with open('testcsv.csv', mode='a') as csvfile:
                csv_write = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
                csv_write.writerow(wshark_sa)
    