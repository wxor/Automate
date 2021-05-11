def startfind(sub, string):
    start = 0
    while True:
        start = string.find(sub, start)
        if start == -1: return
        yield start
        start += len(sub)