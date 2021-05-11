import subprocess
from findall import startfind



def startactive(subnet):
    output = subprocess.run(['nmap', '-T4', '-sn', subnet, '-v'], check=True, stdout=subprocess.PIPE,
                            universal_newlines=True)
    endpos = (list(startfind("Host is up", output.stdout)))

    filename = str(subnet+'-AllActiveHosts.txt')
    with open(filename, 'w') as f:
        print(output.stdout, file=f)

    # Extract Active IP Addresses
    ip = ""
    for i in range(len(endpos)):
        val = endpos[i] - 2
        while str.isspace(output.stdout[val]) is False:
            val = val - 1

        startpos = val
        while startpos != endpos[i]:
            ip = ip + output.stdout[startpos]
            startpos = startpos + 1

    # Split IP Addresses in string into list
    for line in ip.split("\n"):
        if not line.strip():
            continue
        activeip = []
        activeip.append(line.lstrip())
    return activeip