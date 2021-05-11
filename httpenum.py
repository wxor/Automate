from findall import startfind

def httpstart(activeip):
    filename = activeip+'-AllPorts.txt'

    with open(filename, 'r') as f:
        output = f.read()
        endpos = (list(startfind("open  http", output)))

    # Extract Active IP Addresses
    httpport = ""
    for i in range(len(endpos)):
        val = endpos[i] - 2
        while output[val] != "\n":
            val = val - 1

        startpos = val
        print(output[startpos])
        while output[startpos] != '/':
            httpport = httpport + output[startpos]
            startpos = startpos + 1

    # Split IP Addresses in string into list
    activehttp = []
    for line in httpport.split("\n"):
        if not line.strip():
            continue
        activehttp.append(line.lstrip())

    # start directory enum
    # output = subprocess.run(['nmap', '-T4', '-sn', subnet, '-v'], check=True, stdout=subprocess.PIPE,
    #                        universal_newlines=True)

    return activehttp