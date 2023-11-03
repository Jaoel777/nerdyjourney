#!/opt/gums/bin/python2
# quick script to make reading bestpath compare a little more user friendly
# jsaine -- 05/12/2018
'''
example:
clogin -c "show bgp 180.189.20.0/22 best" r03.tokyjp05.jp.bb.gin.ntt.net | bestpath.py

or paste output to a file and send it to the script,
bestpath.py output.txt
'''

import re
import socket
import sys
import os.path

def main():
    f = open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin
    for line in f:
        # fine the (<ip address>) lines and extract the ip out to lookup hostname
        match = re.search(r'\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)', line)
        if match:
           try:
               result = socket.gethostbyaddr(match.group(1))
               line = re.sub(match.group(1), result[0].replace('.gin.ntt.net', ''), line, 1)
           except:
               pass
        # highlight relevant lines to make it easier to review
        if "Paths:" in line:
           line = "\033[36m" + line + "\033[39m"
        if "than path" in line or "best path" in line:
           line = "\033[91m" + line + "\033[39m"
        if "Path #" in line:
           line = "\033[32m" + line + "\033[39m"
        if "Overall best" in line:
           line = "\033[93m" + line + "\033[39m"

        sys.stdout.write(line)

if __name__ == '__main__':
    main()
