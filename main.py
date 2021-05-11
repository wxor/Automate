import subprocess
import re
import os
import sys
import argparse
from httpenum import httpstart
from findall import startfind

from getactive import startactive



# First scan (Top 1000 ports only)
def nmapscan1(machineaddr):
    output = subprocess.run(['nmap', '-T4', machineaddr, '-v'], check=True, stdout=subprocess.PIPE,
                            universal_newlines=True)
    filename = str(machineaddr+'-Top1000'+'.txt')
    print(filename)
    with open(filename, 'w') as f:
        print(output.stdout, file=f)

    startpos = (list(startfind("open port", output.stdout)))

    # Extract Active Ports
    port = ""
    for i in range(len(startpos)):
        val = startpos[i] + 9
        while output.stdout[val] != "/":
            val = val + 1

        endpos = val
        adjstartpos = startpos[i] + 9
        while adjstartpos != endpos:
            port = port + output.stdout[adjstartpos]
            adjstartpos = adjstartpos + 1

    # Split ports in string into list
    activeports = []
    for line in port.split(" "):
        if not line.strip():
            continue
        activeports.append(line.lstrip())

    activeports.insert(0, machineaddr)
    return activeports


# Second scan (All ports)
def nmapscan2(machineaddr):
    output = subprocess.run(['nmap', '-T4', '-p-', machineaddr, '-v'], check=True, stdout=subprocess.PIPE,
                            universal_newlines=True)
    filename = str(machineaddr+'-AllPorts'+'.txt')
    print(filename)
    with open(filename, 'w') as f:
        print(output.stdout, file=f)

    startpos = (list(startfind("open port", output.stdout)))

    # Extract Active Ports
    port = ""
    for i in range(len(startpos)):
        val = startpos[i] + 9
        while output.stdout[val] != "/":
            val = val + 1

        endpos = val
        adjstartpos = startpos[i] + 9
        while adjstartpos != endpos:
            port = port + output.stdout[adjstartpos]
            adjstartpos = adjstartpos + 1

    # Split ports in string into list
    activeports = []
    for line in port.split(" "):
        if not line.strip():
            continue
        activeports.append(line.lstrip())

    activeports.insert(0, machineaddr)
    return activeports


# Third scan (Default Scripts, Version, OS Enum)
def nmapscan3(activeports):
    for i in range(len(activeports) - 1):
        cmd = 'nmap -A -T4 --script=banner -v -p'+activeports[i+1]+" "+activeports[0]
        print(cmd)
        output = subprocess.run(cmd, check=True, shell=True, stdout=subprocess.PIPE, universal_newlines=True)
        #output = subprocess.run(['nmap', '-A', '-T4', script, '-p', activeports[i+1], activeports[0], '-v'], check=True,
        #                        stdout=subprocess.PIPE, universal_newlines=True)

        filename = str(activeports[0])+'-EnumPort-'+str(activeports[i+1])+'.txt'
        print(filename)
        with open(filename, 'w') as f:
            print(output.stdout, file=f)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-ip", help="Specify a single host or with CIDR notation")
    parser.add_argument("-o", help="Specify output folder")
    args = parser.parse_args()
    if args.ip:
        activehosts = startactive(args.ip)
    if args.o:
        path = args.o
    else:
        path = os.getcwd()

    # Add null checks and validate ip address later
    for i in range(len(activehosts)):
        #create dir structure
        path = path+'/'+activehosts[i]
        try:
            os.mkdir(path)
        except OSError:
            print("Creation of the directory %s failed" % path)
        else:
            print("Successfully created the directory %s " % path)



        print('STARTING BASIC SCAN ON: ', activehosts[i])
        portlist = nmapscan1(activehosts[i])
        print('STARTING FULL PORT SCAN ON: ', activehosts[i])
        portlist = nmapscan2(activehosts[i])
        print('STARTING PORT ENUM SCAN ON: ', activehosts[i])
        print(nmapscan3(portlist))

    httpports = httpstart('192.168.29.204')
    print(httpports)
