import subprocess
import re
import sys
import argparse

activeip = []

#Search Function
def find_all(sub, string):
	start = 0
	while True:
		start = string.find(sub, start)
		if start == -1: return
		yield start
		start += len(sub)
		
#First scan (Top 1000 ports only)
def nmapscan1 (machineaddr):
	output = subprocess.run(['nmap','-T4',machineaddr,'-v'], check=True, stdout=subprocess.PIPE, universal_newlines=True)
	#print(output.stdout)
	
	startpos = (list(find_all("open port", output.stdout)))

	#Extract Active Ports
	port = ""
	for i in range(len(startpos)):
		val = startpos[i] + 9
		while output.stdout[val] != "/":
			val=val+1

		endpos = val
		adjstartpos = startpos[i] + 9
		while adjstartpos != endpos:
			port = port+output.stdout[adjstartpos]
			adjstartpos = adjstartpos + 1

	#Split ports in string into list
	activeports = []
	for line in port.split(" "):
	    if not line.strip():
		    continue
	    activeports.append(line.lstrip())
	
	activeports.insert(0,machineaddr)
	return activeports

#Second scan (All ports)
def nmapscan2 (machineaddr):
	output = subprocess.run(['nmap','-T4','-p-',machineaddr,'-v'], check=True, stdout=subprocess.PIPE, universal_newlines=True)
	print(output.stdout)
	
	startpos = (list(find_all("open port", output.stdout)))

	#Extract Active Ports
	port = ""
	for i in range(len(startpos)):
		val = startpos[i] + 9
		while output.stdout[val] != "/":
			val=val+1

		endpos = val
		adjstartpos = startpos[i] + 9
		while adjstartpos != endpos:
			port = port+output.stdout[adjstartpos]
			adjstartpos = adjstartpos + 1

	#Split ports in string into list
	activeports = []
	for line in port.split(" "):
	    if not line.strip():
		    continue
	    activeports.append(line.lstrip())
	
	activeports.insert(0,machineaddr)
	return activeports

#Third scan (Default Scripts, Version, OS Enum)
def nmapscan3 (activeports):
	for i in range(len(activeports)-1):
		output = subprocess.run(['nmap','-A','-T4','-p', activeports[i+1], activeports[0],'-v'], check=True, stdout=subprocess.PIPE, universal_newlines=True)
		print(output.stdout)
	
#Get Active Machines
def getactive(subnet):
	output = subprocess.run(['nmap','-T4','-sn',subnet,'-v'], check=True, stdout=subprocess.PIPE, universal_newlines=True)
	#Search String "Host is up"
	endpos = (list(find_all("Host is up", output.stdout)))

	#Extract Active IP Addresses
	ip = ""
	for i in range(len(endpos)):
		val = endpos[i] - 2
		while str.isspace(output.stdout[val]) is False:
			val=val-1

		startpos = val
		while startpos != endpos[i]:
			ip = ip+output.stdout[startpos]
			startpos = startpos+1

	#Split IP Addresses in string into list
	for line in ip.split("\n"):
	    if not line.strip():
		    continue
	    activeip.append(line.lstrip())


parser = argparse.ArgumentParser()
parser.add_argument("-ip", help="Specify a single host or with CIDR notation")
args = parser.parse_args()
if args.ip:
	print("Starting scan on ", args.ip)
	getactive(args.ip)

#Add null checks and validate ip address later
for i in range(len(activeip)):
	print('STARTING BASIC SCAN ON: ',activeip[i])
	portlist = nmapscan1(activeip[i])
	#print('STARTING FULL PORT SCAN ON: ',activeip[i])
	#portlist = nmapscan2(activeip[i])
	print('STARTING PORT ENUM SCAN ON: ',activeip[i])
	print(nmapscan3(portlist))
