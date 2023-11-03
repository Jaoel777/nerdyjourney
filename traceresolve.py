#!/usr/bin/env python
import re
import socket
import sys
def main():
    """this script is to solve resulve of traceroute which is sent from customer.
you need copy this script it self and make textfile named "resolve.txt" on your ~/ directory.
so what you do before use the is
1. >cp traceresolve.py ~/
2. >touch resolve.txt
3. copy result of customer traceroute to resolve.txt
then run the script
>python ./traceresolve.py
"""


    f = open('resolve.txt', 'r')
    for line in f:
        #remove unnecessry lines
        if re.match(' ^\s+' , line) is not None:
            continue
        part = line.split( )
        for p in part:
            if re.search('[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' , p) is not None:
                try:
                    result = socket.gethostbyaddr(p)
                    line = re.sub(p, result[0],line)
                except:
                   pass
        sys.stdout.write(line)
if __name__ == '__main__':
    main()
