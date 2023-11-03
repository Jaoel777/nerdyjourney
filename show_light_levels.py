#!/opt/gums/bin/python3
# -*- encoding: utf-8 -*-
# -*- coding: utf-8 -*-
import psycopg2 as db
from psycopg2.extras import DictCursor
import subprocess
import re
import os
import sys
import collections
import atexit
import time # DEBUG rikeda

try:
    import netmiko
except:
    print('## For using this script, please install netmiko ##')
    print('## Please run the command below ##')
    print('pip3 install --user -U netmiko cryptography')
    print()
    sys.exit()

####################################################################################
# define namedtuple
router_command = collections.namedtuple(
    'router_command',
    ['key', 'command']
)
router_response = collections.namedtuple(
    'router_response',
    ['key', 'command', 'response']
)


####################################################################################
ifc_shortname_dict = {
    'bundle-ether': 'be',
    'loopback': 'lo',
    'null': 'nu',
    'tunnel': 'ti',
    'gigabitethernet': 'gi',
    'tengige': 'te',
    'hundredgige': 'hu'
}


####################################################################################
class Cloginrc:
    def __init__(self, file="~/.cloginrc"):
        self.file = os.path.expanduser(file)
        self._parse()

    def _parse(self):
        with open(self.file) as f:
            for line in f:
                if re.match(r"add user\s+", line):
                    self.username = line.split()[-1]
                elif re.match(r"add password\s+\*", line):
                    self.password = line.split()[-2][1:-1]
                    break


####################################################################################
class RouterSession(object):
    def __init__(self, router_name, router_os_name):

        self.router_name = router_name

        if router_os_name == 'cisco':
            self.platform = 'cisco_xr'
        elif router_os_name == 'juniper':
            self.platform = 'juniper_junos'
        else:
            self.platform = 'nokia_sros'

        self.session = self._make_new_session()

    def __call__(self, commands, delay_factor=2):

        for cmd in commands:
            response = self.session.send_command(
                cmd.command,
                #strip_prompt=True, strip_command=True, delay_factor=delay_factor)
                strip_prompt=False, strip_command=True, delay_factor=delay_factor)### Modified due to not Rx power displaying. Original output in router,
#                                                                                 ### RX power and prompt is existing in the same line. so removed by netmiko.
#                                                                                 ### This was requested by Denny. The cuase line is following.
#										  ### Rx power: 0.16530 mW (-7.81727 dBm)RP/0/RSP1/CPU0:r03.atlnga05.us.bb#

            response= re.sub(r"RP/\d{1}/R\w+\d{1}/CPU\d{1}:\w{1}\d{2}\.\w{6}\d{2}\.\w{2}\.\w{2}#", "", response).rstrip() ### strip_prompt of netmiko changed to False(Cisco)
            response= re.sub(r"\S+@\w{1}\d{2}\.\w{6}\d{2}\.\w{2}\.\w{2}-re\d{1}>", "", response).rstrip() ### strip_prompt (Juniper)
            response= re.sub(r"\S+@\w{1}\d{2}\.\w{6}\d{2}\.\w{2}\.\w{2}>", "", response).rstrip()

            response = re.sub('\{master\}', '', response).rstrip()
            response = re.sub('---\(more (\d+)%\)---', '', response).rstrip()

            response = re.sub(r"A:\w+@a\d{2}\.\w{6}\d{2}\.\w{2}\.\w{2}# ", "", response).rstrip() ### strip_prompt (Nokia)
            yield router_response(cmd.key, cmd.command, response)

    def _make_new_session(self):

        auth_clogin = Cloginrc()
        session = netmiko.ConnectHandler(
            device_type=self.platform,
            ip=self.router_name,
            username=auth_clogin.username,
            password=auth_clogin.password
        )

        return session

    def close_session(self):
        self.session.clear_buffer()
        self.session.disconnect()
        print("session closed")

def grab_output(query, value2):
    table = []
    try:
        conn = db.connect("dbname=cfgtools host=localhost")
        cur = conn.cursor(cursor_factory=DictCursor)
        cur.execute((query), (value2))
        table = cur.fetchall()
        cur.close()
        conn.close()
    except db.DatabaseError as ex:
        print()
        print('#' * 80)
        print('{}'.format(ex))
        print('#' * 80)
        sys.exit(1)
    dict_table = []
    for row in table:
       dict_table.append(dict(row))
    return dict_table

def isExist(target,query_result):
    if target == "router":
        if len(query_result) == 1:
            return True
        elif len(query_result) == 0:
            print("{} is not valid router name".format(args.router))
        elif len(query_result) >=2:
            print("more than 2 routers matched to {}".format(args.router))
        else:
            pass
        return False
    elif target == "interface":
        if len(query_result) >= 1:
            return True
        elif len(query_result) == 0:
            print(f"no interface name matched with '{args.interface}'")
        else:
            pass
        return False

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("-d","--debug",action="store_true")
    parser.add_argument("router",help="router name")
    parser.add_argument("interface",help="interface or slot")
    parser.add_argument("-U","--unused",action="store_true",help="skip unused interfaces")
    parser.add_argument("-I","--include",help="include lines that match",metavar="string")
    parser.add_argument("-E","--exclude",help="exclude lines that match",metavar="string")
    parser.add_argument("-n","--nologin",action="store_true",help="no login")
    args = parser.parse_args()

    ### Check router name validity
    router_info = grab_output("select * from routers where name ~ %s",(args.router,))    
    if isExist("router",router_info) is not True:
        print("aborting")
        exit()

    ### Check interface validity
    interface_info = grab_output("select * from interfaces where router ~ %s and ifc_name ~ %s",(router_info[0]["name"],args.interface,))
    if isExist("interface",interface_info) is not True:
        print("aborting")
        exit()

    ### If mfg is Juniper or Cisco, run previous version of show_light_levels 
    if router_info[0]["mfg"] == "juniper" or router_info[0]["mfg"] == "cisco":
        proc_cmd = f"~/config/tools/scripts/show_light_levels {args.router} {args.interface}"
        proc = subprocess.run(proc_cmd, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True, )
        print(f'{proc.stdout.decode("utf8")}{proc.stderr.decode("utf8")}')

    ### If mfg is Nokia run new added function on this script
    else:
        ### Make commands to run
        nokia_cmds = []
        for interface in sorted(interface_info,key=lambda x:x['ifc_name']):
            if args.unused and interface["intf_type"] == 'UU': ### skip unused interfaces with option "-d" enabled.
                if args.debug:
                    print(f"DEBUG: skipping {interface['ifc_name']} as unused interface")
                continue
            elif re.search(":",interface["ifc_name"]) is not None: ### skip logical ifcs, e.g. "eth-esat-1/1/26:250"
                if args.debug:
                    print(f"DEBUG: skipping {interface['ifc_name']} as logical interface")
                continue
            if args.include is not None:
                if re.search(args.include,interface["name"]) is not None:
                    pass
                else:
                    if args.debug:
                        print(f"DEBUG: skipping {interface['ifc_name']}, desc:{interface['name']} as not matched with search line")
                    continue
            if args.exclude is not None:
                if re.search(args.exclude,interface["name"]) is None:
                    pass
                else:
                    if args.debug:
                        print(f"DEBUG: skipping {interface['ifc_name']}, desc:{interface['name']} as matched with exception")
                    continue
            ifc_name = re.sub("eth-","",interface["ifc_name"]) ### e.g. "eth-esat-1/1/1" -> "esat-1/1/1"

            nokia_cmds.append(router_command(key='show_desc', command=f"show port {ifc_name} description"))
            if re.match(r"(.*c\d+)",ifc_name) is not None: ### for optical commands "1/1/c27/3" need to be changed to "1/1/c27"
                ifc_name = re.match(r"(.*c\d+)",ifc_name).group(1)
            nokia_cmds.append(router_command(key='show_lightlevel', command=f"show port {ifc_name} optical"))
        if args.debug:
            print(f'{"*" *5} commands {"*" *5}')
            for nokia_cmd in nokia_cmds:
                print(f"{nokia_cmd.key}:\n  {nokia_cmd.command}")
        if args.nologin:
            print("exiting")
            exit()

        ### Establish SSH session with Nokia device
        session = RouterSession(router_info[0]["name"], router_info[0]["mfg"])
        atexit.register(session.close_session) ### closing ssh session with nokia device at end

        ### retrieve responses from SSH session and print results
        for response in session(nokia_cmds):
            ### Description part
            if response.key == 'show_desc':
                for num,line in enumerate(response.response.splitlines()):
                    if re.search("^esat-",line) is not None or re.search("^\d+\/\d+\/c\d+\/\d+",line) is not None: ### retrieve description from output
                        desc = line
                        if re.search("^=",response.response.splitlines()[num+1]) is None: ### if description has 2lines, include 2nd line.
                            desc += response.response.splitlines()[num+1].strip()
                try:print(router_info[0]["name"],desc)
                except:
                    print("failed on description part",response.response)
                    import code; code.interact(local=locals())
                    exit()
            ### Light level part
            elif response.key == 'show_lightlevel':
                if re.search("esat-",response.command) is not None:
                    for line in response.response.splitlines():
                        if re.search("Rx Optical Power \(avg dBm\) +([-.0-9]+)",line) is not None:
                            rx_light = "Rx Power: {} dBm".format(re.search("Rx Optical Power \(avg dBm\) +([-.0-9]+)",line).group(1))
                        elif re.search("Tx Output Power \(dBm\) +([-.0-9]+)",line) is not None:
                            tx_light = "Tx Power: {} dBm".format(re.search("Tx Output Power \(dBm\) +([-.0-9]+)",line).group(1))
                    print(f"  {tx_light}\n  {rx_light}")
                else:
                    for num,line in enumerate(response.response.splitlines()):
                         if re.search("Lane ID",line) is not None:
                             i = 2
                             while i < 6:
                                 tx = response.response.splitlines()[num+i].split()[3]
                                 rx = response.response.splitlines()[num+i].split()[4]
                                 print(f"  Lane {i-1}\n     Tx Power: {tx} dBm\n     Rx Power: {rx} dBm")  
                                 i += 1

