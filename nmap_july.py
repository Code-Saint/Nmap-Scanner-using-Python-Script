#!/usr/bin/python3

import nmap

sc = nmap.PortScanner()

print("Welcome to Simple Nmap Scan Tool")
print("- - - - - - - - - - - - - - - - - - - - - - - - ")

ip_addr = input("Please enter the IP Address to Scan :")

print("The entered IP address is : ",ip_addr)

print("The type of entered data : ", type(ip_addr))

resp = input("""\n Please Enter the Type of Scan you want to perform : 
            1. SYN Scan
            2. UDP Scan
            3. Comprehensive Scan\n""")
            
print("You have Selected:", resp)

resp_dict = {'1':['-sS -vv -sV', 'tcp'],'2':['-sU -vv -sV', 'udp'],'3':['-sS -vv -O -sV -p- -sC', 'tcp']}

if resp not in resp_dict.keys():
            print("Please Enter a Valid Option.")
else:
            print("Nmap Version:", sc.nmap_version())
            sc.scan(ip_addr, "1-65535", resp_dict[resp][0])
            
            if sc[ip_addr].state() == 'up':
                    print("Host is up, scanning results:")
                    
                    for proto in sc[ip_addr].all_protocols():
                            print("\n Protocol : {}".format(proto))
                            print("\n Open Ports : {}".format(', '.join(map(str, sc[ip_addr][proto].keys()))))
                     
                            for port, info in sc[ip_addr][proto].items():
                                    print("\nPort : {}\nService : {}\nState : {}".format(port, info['name'],info['state']))


