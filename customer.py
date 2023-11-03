#!/opt/gums/bin/python3
# -*- encoding: utf-8 -*-
# -*- coding: utf-8 -*-

from functools import reduce
from datetime import datetime, timedelta

import argparse
import collections
import os
import psycopg2.extras
import re
import sys
import json
import time
import ipaddress

try:
    import netmiko
except:
    print('## For using this script, please install netmiko ##')
    print('## Please run the command below ##')
    print('pip3 install --user -U netmiko cryptography')
    print()
    sys.exit()

VERSION = '0.9'
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
            password=auth_clogin.password,
            global_delay_factor=2
        )

        return session

    def close_session(self):
        self.session.clear_buffer()
        self.session.disconnect()


#######################################################################################################################
class Tools(object):

    @staticmethod
    def colorstring(string, color):
        RED = '\033[31m'
        GREEN = '\033[32m'
        YELLOW = '\033[33m'
        BLUE = '\033[34m'
        PURPLE = '\033[35m'
        CYAN = '\033[36m'
        END = '\033[0m'

        color_string = string
        if color == 'red':
            color_string = RED + string + END
        elif color == 'green':
            color_string = GREEN + string + END
        elif color == 'blue':
            color_string = BLUE + string + END
        elif color == 'yellow':
            color_string = YELLOW + string + END
        elif color == 'cyan':
            color_string = CYAN + string + END
        elif color == 'purple':
            color_string = PURPLE + string + END

        return color_string

    @staticmethod
    def table_output(mydict, key_list=None, name_list=None):
        if key_list is None:
            key_list = list(mydict[0].keys() if mydict else [])

        if (key_list and name_list) and (len(key_list) == len(name_list)):
            mylist = [name_list]
        else:
            mylist = [key_list]

        for item in mydict:
            mylist.append([str(item[col] or '') for col in key_list])

        colsize = [max(map(len, col)) for col in zip(*mylist)]
        formatStr = ' | '.join(["{{:<{}}}".format(i) for i in colsize])
        mylist.insert(1, ['-' * i for i in colsize])

        output = []

        for item in mylist:
            output.append(formatStr.format(*item))

        return '\n'.join(output)

    @staticmethod
    def make_short_interface_name(ifc):
        return reduce(lambda x, y: x.replace(y, ifc_shortname_dict[y]), ifc_shortname_dict, ifc)

    @staticmethod
    def make_long_interface_name(ifc):
        new_ifc = ifc
        for key, value in ifc_shortname_dict.items():
            if ifc[:2] == value:
                new_ifc = ifc.replace(value, key)
                break
        return new_ifc

    @staticmethod
    def none2empty(string):
        return string or ''

    @staticmethod
    def stats_url(interface):
        stats_url = 'https://stats.gin.ntt.net/stats/ip-eng/graph_stats.cgi?'

        tday, yday = datetime.now(), datetime.now() - timedelta(days=1)
        router, ifc_name = interface.split(' ')

        if 'eth-esat' in ifc_name:
            ifc_name = ifc_name.replace("eth-", "", 1)
        else:
            ifc_name = ifc_name

        params = [
            'do_graph=Show+Graph',
            'dates=%s:%s' % (yday.strftime('%Y.%m.%d'), tday.strftime('%Y.%m.%d')),
            'bps=bps',
            'errors=errors',
            # 'qos_drops=qos_drops',
            'skip_unused=skip_unused',
            'ifc_partial_match=1?',
            'router=%s' % router,
            'interface_%s=on' % ifc_name,
        ]

        stats_url += '&'.join(params)

        return stats_url

    @staticmethod
    def gnome_url(cust_id):
        gnome_url = 'https://gnome.gin.ntt.net/index.pl?usid=%s' % cust_id
        return gnome_url


####################################################################################
class ConfigToolsDB(object):

    @staticmethod
    def search(query, listing=False):
        sql, item_tuple = query
        auth = Cloginrc()

        db_conn = psycopg2.connect(
            'dbname=cfgtools host=localhost user=%s password=%s' % (auth.username, auth.password))
        db_cur = db_conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        db_cur.execute(sql)

        result = []
        for row in db_cur:
            result.append(item_tuple._make(row))

        if listing and len(result) > 0:
            return result
        elif not listing and len(result) > 0:
            return result[0]
        else:
            return None

    @staticmethod
    def get_router_info(router):
        selector = 'name, mfg, os_rev'
        table = 'routers'
        filter = 'name = \'%(router)s\'' % locals()

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()
        return sql, collections.namedtuple('router_info',
                                           ['name', 'mfg', 'os_rev']
                                           )

    @staticmethod
    def get_interface_from_usid(usid):
        selector = 'interfaces.router, interfaces.ifc_name, routers.mfg, routers.os_rev, interfaces.intf_type, ' \
                   'interfaces.cust_id, interfaces.name, interfaces.telco, interfaces.cid, interfaces.state, ' \
                   'interfaces.comment'
        table = 'routers, interfaces'
        filter = 'interfaces.router = routers.name and interfaces.state != \'unused\' and ' \
                 'interfaces.state != \'shutdown\' and interfaces.cust_id = \'%(usid)s\'' % locals()

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()
        return sql, collections.namedtuple('interface_info',
                                           ['router', 'interface', 'mfg', 'os_rev', 'intf_type',
                                            'cust_id', 'name', 'telco', 'cid', 'state',
                                            'comment']
                                           )

    @staticmethod
    def get_static_route_info(router):
        selector = 'ct_devices.device_name, prefix, nexthop_ip'
        table = 'ct_statics, ct_devices'
        filter = 'ct_devices.device_id=ct_statics.device_id and ' \
                 'ct_devices.device_name=\'%(router)s\'' % locals()

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()

        return sql, collections.namedtuple('static_route',
                                           ['router', 'prefix', 'nexthop_ip']
                                           )

    @staticmethod
    def get_agg_ifc_id(router, interface):
        selector = 'ct_devices.device_name, ct_ifcs.ifc_name, ct_proto_proto_agg.ifc_id, ct_proto_proto_agg.agg_ifc_id'
        table = 'ct_proto_proto_agg, ct_ifcs, ct_devices'
        filter = 'ct_ifcs.device_id = ct_devices.device_id and ct_ifcs.ifc_id = ct_proto_proto_agg.ifc_id and '
        filter += 'device_name=\'%(router)s\' and ifc_name=\'%(interface)s\'' % locals()

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()

        return sql, collections.namedtuple('interface_agg',
                                           ['device_name', 'ifc_name', 'ifc_id', 'agg_ifc_id']
                                           )

    @staticmethod
    def get_ifc_name_from_id(ifc_id):
        selector = 'ct_devices.device_name, ct_ifcs.ifc_name'
        table = 'ct_ifcs, ct_devices'
        filter = 'ct_ifcs.device_id = ct_devices.device_id and ct_ifcs.ifc_id=\'%(ifc_id)s\'' % locals()

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()

        return sql, collections.namedtuple('interface_name',
                                           ['device_name', 'ifc_name']
                                           )

    @staticmethod
    def get_local_ipv4(router, interface):
        selector = 'ct_devices.device_name, ct_ifcs.ifc_name, ct_proto_ipv4.ipv4'
        table = 'ct_devices, ct_ifcs, ct_proto_ipv4'
        filter = 'ct_ifcs.device_id = ct_devices.device_id and ct_ifcs.ifc_id = ct_proto_ipv4.ifc_id and ' \
                 'ct_devices.device_name = \'%(router)s\' and ct_ifcs.ifc_name = \'%(interface)s\'' % locals()

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()

        return sql, collections.namedtuple(
            'peer_info',
            ['router', 'interface', 'local_ipv4']
        )

    @staticmethod
    def get_local_ipv6(router, interface):
        selector = 'ct_devices.device_name, ct_ifcs.ifc_name, ct_proto_ipv6.ipv6'
        table = 'ct_devices, ct_ifcs, ct_proto_ipv6'
        filter = 'ct_ifcs.device_id = ct_devices.device_id and ct_ifcs.ifc_id = ct_proto_ipv6.ifc_id and ' \
                 'ct_devices.device_name = \'%(router)s\' and ct_ifcs.ifc_name = \'%(interface)s\'' % locals()

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()

        return sql, collections.namedtuple(
            'peer_info',
            ['router', 'interface', 'local_ipv6']
        )

    @staticmethod
    def get_peer_info(router, interface):
        selector = 'router, multihop_src, ip_addr, asn, description, peertype, state'
        table = 'peers'
        filter = 'router = \'%(router)s\' and multihop_src = \'%(interface)s\'' % locals()

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()

        return sql, collections.namedtuple(
            'peer_info',
            ['router', 'interface', 'peer_ip', 'asn', 'p_desc', 'p_type', 'p_state']
        )

    @staticmethod
    def get_peer_info_from_ip(router, ip_addr):
        selector = 'router, multihop_src, ip_addr, asn, description, peertype, state'
        table = 'peers'
        filter = 'router = \'%(router)s\' and ip_addr = \'%(ip_addr)s\'' % locals()

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()

        return sql, collections.namedtuple(
            'peer_info',
            ['router', 'interface', 'peer_ip', 'asn', 'p_desc', 'p_type', 'p_state']
        )

############## Added from here by wataru #############
    @staticmethod
    def get_nexthop_ip(usid):
        selector= "nexthop_ip"
        table= "ct_statics"
        filter= "nexthop_ifc_id= (SELECT ifc_id FROM ct_ifcs where cust_id = \'%(usid)s\' limit 1)" % locals()

        sql= "SELECT %(selector)s FROM %(table)s where %(filter)s" % locals()

        return sql, collections.namedtuple(
            "nexthop_ip_info",
            ["nexthop_ip"]
        )
# If occure error, add namedtuple

### Added following
### For "4. If a customer has bgp can it pull the ASN and AS-macro info only? If not this isn't a big deal." @Dan

    @staticmethod
    def get_bgp_macro(router, interface):
        selector= "asn, name, as_macro, pfx_count, allow_specifics, as6_macro, pfx6_count, allow6_specifics, irr_srcs"
        table= "autnum"
        filter= "asn = (SELECT asn FROM peers WHERE router = \'%(router)s\' and multihop_src = \'%(interface)s\' LIMIT 1)" % locals()

        sql= "SELECT %(selector)s FROM %(table)s where %(filter)s" % locals()

        return sql, collections.namedtuple(
            "bgp_macro",
            ["asn", "name", "as_macro", "pfx_count", "allow_specifics", "as6_macro", "pfx6_count", "allow6_specifics", "irr_srcs"]
        )

    @staticmethod
    def get_bgp_macro_retry(router, interface):
        selector= "asn, name, as_macro, pfx_count, allow_specifics, as6_macro, pfx6_count, allow6_specifics, irr_srcs"
        table= "autnum"
        filter= "asn = (SELECT asn from peers where description ilike (select name from interfaces where router = \'%(router)s\' and ifc_name = \'%(interface)s\' LIMIT 1) LIMIT 1)" % locals()

        sql= "SELECT %(selector)s FROM %(table)s where %(filter)s" % locals()

        return sql, collections.namedtuple(
            "bgp_macro",
            ["asn", "name", "as_macro", "pfx_count", "allow_specifics", "as6_macro", "pfx6_count", "allow6_specifics", "irr_srcs"]
        )

###### End additon ###########i

#######################################################################################################################
class RouterCommand(object):

    @staticmethod
    def show_cloc(mfg):
        if mfg == "cisco":
            cmd = 'show cloc'
        elif mfg == 'juniper':
            cmd = 'show system uptime | match current'
        else:
            cmd = 'show time'

        return router_command(key='show_cloc', command=cmd)

    @staticmethod
    def show_ifc_info(mfg, interface, ce_flag, gc_flag):
        if mfg == "cisco":
            if ce_flag == False and gc_flag == False:
                cmd = 'show interfaces %(interface)s | ' \
                      'include "Description|line protocol|Internet address|MTU|flap|rate|runt|rror|clear"' % locals()
            else:
                cmd = 'show interfaces %(interface)s' % locals()
        elif mfg == 'juniper':
            if ce_flag == False and gc_flag == False:
                cmd = 'show interfaces extensive %(interface)s | ' \
                      'match "Description|Physical interface|Destination|MTU|flap|bytes|rror|leared"' % locals()
            else:
                cmd = 'show interfaces extensive %(interface)s' % locals()
        else:
            interface = re.sub("eth-","",interface)
            if ce_flag == False and gc_flag == False:
                cmd = "show port %(interface)s | match 'Admin State|Physical Link|Last State Change|Errors|Last Cleared Time'"   % locals()
            else:
                cmd = 'show port %(interface)s detail'  % locals()

        return router_command(key='show_ifc_info', command=cmd)

    @staticmethod
    def run_ping(mfg, target, count):
        if mfg == "cisco":
            if ':' in target:
                cmd = 'ping %(target)s count %(count)s' % locals()
            else:
                cmd = 'ping %(target)s count %(count)s donotfrag' % locals()
        elif mfg == 'juniper':
            if ':' in target:
                cmd = 'ping %(target)s rapid count %(count)s' % locals()
            else:
                cmd = 'ping %(target)s rapid count %(count)s do-not-fragment' % locals()
        else:
            if ':' in target:
                cmd = 'ping %(target)s count %(count)s' % locals() #no rapid option on Sros
            else:
                cmd = 'ping %(target)s count %(count)s do-not-fragment' % locals()

        return router_command(key='run_ping', command=cmd)

########## ADD
    @staticmethod
    def pre_ping(mfg, target, count=10):
        if mfg == "cisco":
            if ':' in target:
                cmd = 'ping %(target)s count %(count)s' % locals()
            else:
                cmd = 'ping %(target)s count %(count)s donotfrag' % locals()

        elif mfg == 'juniper':
            if ':' in target:
                cmd = 'ping %(target)s rapid count %(count)s' % locals()
            else:
                cmd = 'ping %(target)s rapid count %(count)s do-not-fragment' % locals()
        else:
            if ':' in target:
                cmd = 'ping %(target)s count %(count)s' % locals() #no rapid option on Sros
            else:
                cmd = 'ping %(target)s count %(count)s do-not-fragment' % locals()

        return router_command(key='run_ping', command=cmd)

############

    @staticmethod
    def show_arp(mfg, ipv4):
        if mfg == "cisco":
            cmd = 'show arp %(ipv4)s' % locals()
        elif mfg == 'juniper':
            cmd = 'show arp no-resolve hostname %(ipv4)s' % locals()
        else:
            cmd = 'show router arp %(ipv4)s' % locals()

        return router_command(key='show_arp', command=cmd)

    @staticmethod
    def show_arp6(mfg, ipv6):
        if mfg == "cisco":
            cmd = 'show ipv6 neighbors | include "IPv6 Address\|%(ipv6)s "' % locals()
        elif mfg == 'juniper':
            cmd = 'show ipv6 neighbors | match "Interface|%(ipv6)s "' % locals()
        else:
            cmd = 'show router neighbor | match %(ipv6)s' % locals() #mac address can not be shown(rikeda)
        return router_command(key='show_arp', command=cmd)

    @staticmethod
    def show_power(mfg, interface, ce_flag, gc_flag):
        interface = interface.split('.')[0]
        if mfg == "cisco":
            if 'Hu' in interface or 'hundredgige' in interface:
                if ce_flag == False and gc_flag == False:
                    #cmd = 'show controllers %(interface)s phy | include "(        \[0-3\].*mW |Lane * Temp)"' % locals()
                    #cmd = 'show controllers %(interface)s phy | include "(        \[0-3\].*mW |Lane * Temp|Transmit Power:|Receive Power:)"' % locals()
                    cmd = 'show controllers %(interface)s phy' % locals() ### Dan's request. The non --ce should have the "show controllers <interface> phy output as well.
                else:
                    if gc_flag == False:
                        cmd = 'show controllers %(interface)s phy' % locals()
                    else:
                        cmd = 'show controllers %(interface)s phy | begin Tx' % locals()

            elif 'Te' in interface or 'tengige' in interface:
                if ce_flag == False and gc_flag == False:
                    #cmd = 'show controllers %(interface)s phy | include "x P|N/A"' % locals()
                    cmd = 'show controllers %(interface)s phy | include dBm' % locals()
                else:
                    if gc_flag == False:
                        cmd = 'show controllers %(interface)s phy' % locals()
                    else:
                        cmd = 'show controllers %(interface)s phy | begin Tx' % locals()
            else:
                if ce_flag == False and gc_flag == False:
                    #cmd = 'show controllers %(interface)s phy | include "x P|N/A"' % locals()
                    cmd = 'show controllers %(interface)s phy | include "dBm|N/A"' % locals()
                else:
                    if gc_flag == False:
                        cmd = 'show controllers %(interface)s phy' % locals()
                    else:
                        cmd = 'show controllers %(interface)s phy | begin Tx' % locals()

        elif mfg == 'juniper':
            cmd = 'show interfaces diagnostics optics %(interface)s ' % locals()
            cmd += '| except "volt|alarm|temp|off|bias" '

        else:
            interface = re.sub("eth-","",interface)
            if re.match(r"(.*c\d+)",interface) is not None: ### for optical commands "1/1/c27/3" need to be changed to "1/1/c27"
                interface = re.match(r"(.*c\d+)",interface).group(1)
            cmd = 'show port %(interface)s optical' % locals()

        return router_command(key='show_power', command=cmd)

    @staticmethod
    def bgp_status(mfg, neighbor):

        addr = ipaddress.ip_address(neighbor)
        if mfg == 'cisco' and addr.version == 4:
            cmd = 'show bgp ipv4 unicast neighbors %(neighbor)s | ' \
                  'include "Remote AS|BGP state|accepted prefixes|Local host|Foreign host"' % locals()

        elif mfg == 'cisco' and addr.version == 6:
            cmd = 'show bgp ipv6 unicast neighbors %(neighbor)s | ' \
                  'include "Remote AS|BGP state|accepted prefixes|Local host|Foreign host"' % locals()

        elif mfg == 'juniper' and addr.version == 4:
            cmd = 'show bgp neighbor %(neighbor)s | ' \
                  'match "Peer:|Type|Active prefixes|Accepted prefixes" | except "NLRI|Restart"' % locals()

        elif mfg == 'juniper' and addr.version == 6:
            cmd = 'show bgp neighbor %(neighbor)s | ' \
                  'match "Peer:|Type|Active prefixes|Accepted prefixes" | except "NLRI|Restart"' % locals()
        elif mfg == 'nokia' and addr.version == 4:
            cmd = "show router bgp neighbor %(neighbor)s | " \
                  "match 'Peer AS|State|IPv6 active|Local Address|Peer Address'" % locals()
        elif mfg == 'nokia' and addr.version == 6:
            cmd = "show router bgp neighbor %(neighbor)s | " \
                  "match 'Peer AS|State|IPv6 active|Local Address|Peer Address'" % locals()

        return router_command(key='show_bgp_status', command=cmd)

##### Added here for 'show bgp summary'. 
##### I have a request from JonA which seems reasonable.
##### could you add the output of show bgp summary or something similar showing for the affected BGP session uptime in each platform?
##### by Casey.

    @staticmethod
    def bgp_summary(mfg, neighbor):

        addr= ipaddress.ip_address(neighbor)
        if mfg == 'cisco' and addr.version == 4:
            cmd= "show bgp summary | include %(neighbor)s" % locals()
        elif mfg == 'cisco' and addr.version == 6:
            cmd= "show bgp ipv6 unicast summary | utility egrep %(neighbor)s -A 1" % locals()
        elif mfg == 'juniper' and addr.version == 4:
            cmd= "show bgp summary | match %(neighbor)s" % locals()
        elif mfg == 'juniper' and addr.version == 6:
            cmd= "show bgp summary | match %(neighbor)s" % locals()
        elif mfg == 'nokia' and addr.version == 4:
            cmd= "show router bgp summary family ipv4" % locals() # does not show info in a line
        elif mfg == 'nokia' and addr.version == 6:
            cmd = "show router bgp summary family ipv6"  % locals() # does not show info in a line

        return router_command(key='show_bgp_summary', command=cmd)

### Verification
#
# J-v4: 287907-Okay
# J-v6: 287907-Okay
# C-v4: 269539-Okay
# C-v6: 269539-Okay
#
##### End of addition

    @staticmethod
    def static_route_status(mfg, prefix):

        if ':' in prefix:
            if mfg == 'cisco':
                cmd = 'show route ipv6 unicast %(prefix)s detail' % locals()
            elif mfg == 'juniper':
                cmd = 'show route %(prefix)s detail' % locals()
            else:
                cmd = 'show router route-table %(prefix)s extensive' % locals()
        else:
            if mfg == 'cisco':
                cmd = 'show route ipv4 unicast %(prefix)s detail' % locals()
            elif mfg == 'juniper':
                cmd = 'show route %(prefix)s detail' % locals()
            else:
                cmd = 'show router route-table %(prefix)s extensive' % locals()
        return router_command(key='show_bgp_status', command=cmd)

    @staticmethod
    def show_log_ifc(mfg, os_rev, interface, count=20):
        if mfg == "cisco":
            if os_rev == '5.3.4':
                cmd = 'show log | utility fgrep -i %(interface)s | utility tail count %(count)s' % locals()
            else:
                cmd = 'show log | utility fgrep %(interface)s -i | utility tail count %(count)s' % locals()
        elif mfg == 'juniper':
            cmd = 'show log messages | match %(interface)s | last %(count)s | match LINK | no-more' % locals()
        else:
            interface = re.sub("eth-","",interface)
            cmd = 'show log log-id 101 message %(interface)s count %(count)s ' % locals()

        return router_command(key='show_log_ifc', command=cmd)

    @staticmethod
    def show_log_peer(mfg, os_rev, peer, count=20):
        if mfg == "cisco":
            if os_rev == '5.3.4':
                cmd = 'show log | utility fgrep -i %(peer)s | utility tail count %(count)s' % locals()
            else:
                cmd = 'show log | utility fgrep %(peer)s -i | utility tail count %(count)s' % locals()
        elif mfg == 'juniper':
            cmd = 'show log messages | match %(peer)s | last %(count)s | no-more' % locals()
        else:
            cmd = 'show log log-id 101 message %(peer)s count %(count)s' % locals()

        return router_command(key='show_log_peer', command=cmd)

    @staticmethod
    def show_l2vpn(mfg, interface, vcid):

        if mfg == "cisco":
            ciscoVC = 'l2vpn-{}'.format(vcid)
            cmd = 'show l2vpn xconnect group %(ciscoVC)s detail | ' \
                  'include "Group l2vpn|AC: |PW: |MTU |Source address"' % locals()

        elif mfg == 'juniper':
            if '.' not in interface:
                interface += '.0'
            cmd = 'show l2circuit connections interface %(interface)s extensive | match "Neighbor|vc "' % locals()
        else:
            cmd = 'show service sdp-using | match ":%(vcid)s"' % locals()

        return router_command(key='show_l2vpn', command=cmd)

    @staticmethod
    def l2vpn_log(mfg, os_rev, vcid):

        if mfg == "cisco":
            if os_rev == '5.3.4':
                cmd = 'show log | utility fgrep -i "id  {}," | utility tail count 4'.format(vcid)
            else:
                cmd = 'show log | utility fgrep "id  {}," -i | utility tail count 4'.format(vcid)
        elif mfg == 'juniper':
            cmd = 'show log messages | match RPD_LAYER2 | match ": {}"'.format(vcid)
        else:
            cmd = 'show log log-id 101 message SVCMGR-MINOR-sdpBindStatusChanged | match ":{}"'.format(vcid)

        return router_command(key='l2vpn_log', command=cmd)

    @staticmethod
    def show_ifc_error(mfg, ifc):
        interface = ifc.split('.')[0]
        if mfg == "cisco":
            cmd = 'show interfaces %(interface)s | include error' % locals()
        elif mfg == 'juniper':
            cmd = 'show interfaces %(interface)s extensive | match rror' % locals()
        else:
            interface = re.sub("eth-","",interface)
            cmd = 'show port %(interface)s detail | match Error' % locals()
        return router_command(key='show_ifc_error', command=cmd)

    @staticmethod
    def clear_ifc_counter(mfg, ifc):
        interface = ifc.split('.')[0]
        if mfg == "cisco":
            cmd = 'clear counters %(interface)s' % locals()
        elif mfg == 'juniper':
            cmd = 'clear interfaces statistics %(interface)s' % locals()
        else:
            interface = re.sub("eth-","",interface)
            cmd = 'clear port %(interface)s statistics'  % locals()

        return router_command(key='clear_counter', command=cmd)


#######################################################################################################################
class Check(object):
    def __init__(self, args, psr, sub_cmd_name):
        self.psr = psr

    def get_help(self):
        return self.psr.format_help()

    def get_usage(self):
        return self.psr.format_usage()


class CustomerCheck(Check):

    def __init__(self, args, psr):
        super().__init__(args, psr, sub_cmd_name='customercheck')

        self.usid = args.usid
        self.clear = args.clear
        self.ce_flag= args.ce ### Added by wataru
        self.gc_flag= args.gc ### Added by wataru

        self.interface_info_list = self.get_interface_from_usids()
        self.usid_summary_dict = collections.OrderedDict()

    def get_interface_from_usids(self):

        filtered_interface_info_list = []

        for usid in self.usid.split('|'):
            query = ConfigToolsDB.get_interface_from_usid(usid)
            interface_info = ConfigToolsDB.search(query, listing=False)

            if interface_info:
                filtered_interface_info_list.append(interface_info)
            else:
                msg = 'could not find {}... skip this usid'.format(usid)
                print(Tools.colorstring(msg, 'red'))

        return filtered_interface_info_list

    def get_interface_current_info(self):
        for router, usid_dict in self.usid_summary_dict.items():

            mfg_list = []
            interface_info_list = []

            for usid, summary_dict in usid_dict.items():
                mfg = self.usid_summary_dict[router][usid]['mfg']
                mfg_list.append(mfg)

                interface_info_list.append(self.usid_summary_dict[router][usid])

            self.check_ifc_list_current_status(router, mfg_list[0], interface_info_list)

    @staticmethod
    def get_peer_list(router, interface):
        query = ConfigToolsDB.get_peer_info(router, interface)
        peerinfo_list = ConfigToolsDB.search(query, listing=True)

        peer_list = []
        if peerinfo_list:
            for peerinfo in peerinfo_list:
                peer_list.append(peerinfo.peer_ip)
        if len(peer_list) == 0:
            peer_list = None
        return peer_list

    def init_target_info(self):
        for interface_info in self.interface_info_list:
            if interface_info.cust_id:

                router = interface_info.router
                usid = interface_info.cust_id
                interface = interface_info.interface

                if router not in self.usid_summary_dict:
                    self.usid_summary_dict[router] = collections.OrderedDict()
                    query = ConfigToolsDB.get_static_route_info(router)
                    static_route_info_list = ConfigToolsDB.search(query, listing=True)

                self.usid_summary_dict[router][usid] = collections.OrderedDict()
                self.usid_summary_dict[router][usid]['cust_id'] = usid
                self.usid_summary_dict[router][usid]['router'] = interface_info.router
                self.usid_summary_dict[router][usid]['interface'] = interface
                self.usid_summary_dict[router][usid]['mfg'] = interface_info.mfg
                self.usid_summary_dict[router][usid]['os_rev'] = interface_info.os_rev
                self.usid_summary_dict[router][usid]['intf_type'] = interface_info.intf_type
                self.usid_summary_dict[router][usid]['name'] = interface_info.name
                self.usid_summary_dict[router][usid]['cid'] = interface_info.cid
                self.usid_summary_dict[router][usid]['state'] = interface_info.state
                self.usid_summary_dict[router][usid]['comment'] = interface_info.comment

                query = ConfigToolsDB.get_agg_ifc_id(router, interface)
                interface_agg_info = ConfigToolsDB.search(query, listing=False)

                if interface_agg_info:
                    if interface_agg_info.ifc_id == interface_agg_info.agg_ifc_id:
                        self.usid_summary_dict[router][usid]['agg_member'] = None
                    else:
                        self.usid_summary_dict[router][usid]['agg_member'] = interface_agg_info.agg_ifc_id
                else:
                    self.usid_summary_dict[router][usid]['agg_member'] = None

                if self.usid_summary_dict[router][usid]['agg_member']:
                    query = ConfigToolsDB.get_ifc_name_from_id(interface_agg_info.agg_ifc_id)
                    bundle_info = ConfigToolsDB.search(query, listing=False)

                    if bundle_info:
                        self.usid_summary_dict[router][usid]['bundle_ifc_name'] = bundle_info.ifc_name
                    else:
                        msg = '{} {} : agg ifc was no found.. DB is something wrong?'.format(router, interface)
                        print(Tools.colorstring(msg, 'red'))
                        self.usid_summary_dict[router][usid]['bundle_ifc_name'] = None
                else:
                    self.usid_summary_dict[router][usid]['bundle_ifc_name'] = None

                if self.usid_summary_dict[router][usid]['bundle_ifc_name']:
                    bundle_ifc_name = self.usid_summary_dict[router][usid]['bundle_ifc_name']
                    self.usid_summary_dict[router][usid]['peer_list'] = self.get_peer_list(router, bundle_ifc_name)

                    query = ConfigToolsDB.get_local_ipv4(router, bundle_ifc_name)
                    ipv4_info = ConfigToolsDB.search(query, listing=False)
                    if ipv4_info:
                        self.usid_summary_dict[router][usid]['local_ipv4'] = ipv4_info.local_ipv4
                    else:
                        self.usid_summary_dict[router][usid]['local_ipv4'] = None

                    query = ConfigToolsDB.get_local_ipv6(router, bundle_ifc_name)
                    ipv6_info = ConfigToolsDB.search(query, listing=False)
                    if ipv6_info:
                        self.usid_summary_dict[router][usid]['local_ipv6'] = ipv6_info.local_ipv6
                    else:
                        self.usid_summary_dict[router][usid]['local_ipv6'] = None

                else:
                    self.usid_summary_dict[router][usid]['peer_list'] = self.get_peer_list(router, interface)

                    query = ConfigToolsDB.get_local_ipv4(router, interface)
                    ipv4_info = ConfigToolsDB.search(query, listing=False)
                    if ipv4_info:
                        self.usid_summary_dict[router][usid]['local_ipv4'] = ipv4_info.local_ipv4
                    else:
                        self.usid_summary_dict[router][usid]['local_ipv4'] = None

                    query = ConfigToolsDB.get_local_ipv6(router, interface)
                    ipv6_info = ConfigToolsDB.search(query, listing=False)
                    if ipv6_info:
                        self.usid_summary_dict[router][usid]['local_ipv6'] = ipv6_info.local_ipv6
                    else:
                        self.usid_summary_dict[router][usid]['local_ipv6'] = None

                static_list = []
                if self.usid_summary_dict[router][usid]['local_ipv4'] and static_route_info_list:
                    local_ip = ipaddress.ip_interface(self.usid_summary_dict[router][usid]['local_ipv4'])

                    for static_route_info in static_route_info_list:

                        if static_route_info.nexthop_ip is None:
                            continue

                        next_hop = ipaddress.ip_address(static_route_info.nexthop_ip)
                        if next_hop in local_ip.network:
                            static_list.append('_'.join([static_route_info.prefix, static_route_info.nexthop_ip]))
                            if '/32' in static_route_info.prefix:
                                peer_ip = static_route_info.prefix.split('/')[0]
                                query = ConfigToolsDB.get_peer_info_from_ip(router, peer_ip)
                                peer_ip_info = ConfigToolsDB.search(query, listing=True)

                                if peer_ip_info:
                                    if self.usid_summary_dict[router][usid]['peer_list']:
                                        self.usid_summary_dict[router][usid]['peer_list'].append(peer_ip)
                                    else:
                                        self.usid_summary_dict[router][usid]['peer_list'] = [peer_ip]

                if self.usid_summary_dict[router][usid]['local_ipv6'] and static_route_info_list:
                    local_ip = ipaddress.ip_interface(self.usid_summary_dict[router][usid]['local_ipv6'])

                    for static_route_info in static_route_info_list:

                        if static_route_info.nexthop_ip is None:
                            continue

                        next_hop = ipaddress.ip_address(static_route_info.nexthop_ip)
                        if next_hop in local_ip.network:
                            static_list.append('_'.join([static_route_info.prefix, static_route_info.nexthop_ip]))
                            if '/128' in static_route_info.prefix:
                                peer_ip = static_route_info.prefix.split('/')[0]
                                query = ConfigToolsDB.get_peer_info_from_ip(router, peer_ip)
                                peer_ip_info = ConfigToolsDB.search(query, listing=True)

                                if peer_ip_info:
                                    if self.usid_summary_dict[router][usid]['peer_list']:
                                        self.usid_summary_dict[router][usid]['peer_list'].append(peer_ip)
                                    else:
                                        self.usid_summary_dict[router][usid]['peer_list'] = [peer_ip]

                if self.usid_summary_dict[router][usid]['peer_list']:
                    self.usid_summary_dict[router][usid]['peer_list'] = \
                        sorted(self.usid_summary_dict[router][usid]['peer_list'])

                if len(static_list) > 0:
                    self.usid_summary_dict[router][usid]['static_route'] = static_list
                else:
                    self.usid_summary_dict[router][usid]['static_route'] = None

                if self.usid_summary_dict[router][usid]['intf_type'] == 'BD':
                    self.usid_summary_dict[router][usid]['isVLINK'] = True
                else:
                    self.usid_summary_dict[router][usid]['isVLINK'] = False

                    if self.usid_summary_dict[router][usid]['comment']:
                        if 'VC-' in self.usid_summary_dict[router][usid]['comment']:
                            self.usid_summary_dict[router][usid]['isVLINK'] = True
                # print('#####')
                # print(json.dumps(self.usid_summary_dict[router][usid], indent=4))
                # print('#####')
                # print()

    @staticmethod
    def send_command(session, router, cmds,mfg):
        try:
######### Added code for color if error count is not 0 or oustside of light power threshold #############
            light_color_flg= 0
            color_flg= 0
            juniper_count= 0
            skip_flg= 0
            light_color_point_tx= []
            light_color_point_rx= []
            command_response= []
            light_value_list=[]
            light_thresh_dict= {}
            light_txcur_dict= {} # {num : value}
            light_rxcur_dict= {}
            juniper_light_search_tx_high= re.compile(r"output power high warning threshold")
            juniper_light_search_tx_low= re.compile(r"output power low warning threshold")
            juniper_light_search_rx_high= re.compile(r"rx power high warning threshold")
            juniper_light_search_rx_low= re.compile(r"rx power low warning threshold")
            juniper_light_search_tx_cur= re.compile(r"Laser output power")
            juniper_light_search_rx_cur= re.compile(r"Laser receiver power|Receiver signal average|Laser rx power")
            juniper_light_search_thresh= re.compile(r"threshold")

            juniper_error_search= re.compile(r"errors|errored")
            juniper_other_error_search= re.compile(r"Bit errors|Errored blocks|CRC/Align errors|FIFO errors\s+|Output packet error count")
            cisco_error_search= re.compile(r"input errors|giants,|carrier transitions|output errors|output buffer failures")

            cisco_skip_search= re.compile(r"CPAK \d{1} EEPROM|Threshold Data \(CPAK NVR")
            cisco_resume_search= re.compile(r"Transmit")

            nokia_light_search_tx = re.compile(r"Tx Output Power \(dBm\)")
            nokia_light_search_rx = re.compile(r"Rx Optical Power \(avg dBm\)")


            dbm_search= re.compile(r"dBm")
            light_error_search= re.compile(r"<-40.00|N/A")

            ### Not depends on vendor.
            bgp_error_search= re.compile(r"Idle|Active|Connect")
            bgp_error_avoid_search= re.compile(r"Active prefixes|down|Down|is Active|Active alarms|Active defects|_recv|Active Rts|Connector Code")

# -------------

            ### Just checking error line and light level line, also stored output to command_response
            for response in session(cmds):
                command_response.append("-" * 15)
                command_response.append("%s : %s" % (router, re.sub(' {2,}', ' ', response.command)))
                val_lines = response.response.splitlines()
                ### Nokia command cannot grep specific lines in output for bgp summary command. let python do it.  
                if mfg == "nokia" and re.search("show router bgp summary",response.command) != None:
                    val_lines = []
                    for cmd in cmds:
                        ### Find ipv6 peer adder
                        if re.search("show router bgp neighbor",cmd.command) != None and re.search(":",cmd.command) != None:
                            ip_addr = re.search("\d+\:+[0-9a-z:]+",cmd.command).group(0)
                        ### Find ipv4 peer adder
                        elif re.search("show router bgp neighbor",cmd.command) != None and re.search("\d+\.\d+\.\d+\.\d+",cmd.command) != None:
                            ip_addr = re.search("\d+\.\d+\.\d+\.\d+",cmd.command).group(0)
                    for num,val_line in enumerate(response.response.splitlines()):
                        if re.search(ip_addr,val_line) != None:
                            val_lines.append(response.response.splitlines()[num])
                            val_lines.append(response.response.splitlines()[num+1])

                for val_num,val_line in enumerate(val_lines):
                    ### Skip check (limit for 100G of Cisco)
                    if cisco_resume_search.search(val_line) != None: skip_flg= 0
                    if skip_flg == 1: continue
                    if cisco_skip_search.search(val_line) != None:
                        skip_flg= 1
                        continue

                    ### Add resulut line to list
                    command_response.append(val_line)

                    ### Error search of Juniper
                    if mfg == "juniper":
                        if color_flg == 0 and juniper_error_search.search(val_line) != None and re.search(r":\s{1}[1-9]", val_line) != None:
                            color_flg= 1
                        if color_flg == 0 and juniper_other_error_search.search(val_line) != None and re.search(r"[1-9]", val_line) != None:
                            color_flg= 1

                    ### Error search of Cisco
                    if mfg == "cisco":
                        if color_flg == 0 and cisco_error_search.search(val_line) != None and re.search(r"[1-9]", val_line) != None:
                            color_flg= 1

                    ### BGP establish search
                    if color_flg == 0 and bgp_error_search.search(val_line) != None:
                        color_flg= 1

                    ### Light search of Nokia start
                    if mfg == "nokia":
                            if nokia_light_search_tx.search(val_line) != None:
                                val_line = re.sub("!","",val_line)
                                light_thresh_dict["tx_high"] = float(val_line.split()[-3])
                                light_thresh_dict["tx_low"] = float(val_line.split()[-2])
                                if re.search("show port .*c\d+",response.command) is None:  #for 1G interfaces
                                    light_txcur_dict["0"] = float(val_line.split()[-5])
                                else:  #for 1G interfaces
                                    i = 0
                                    while i < 4:
                                        light_txcur_dict[str(i)] = float(re.sub("\/[A-Z-]+","",val_lines[val_num+6+i].split()[-2])) # '-40.00/L-WA'=>'-40.00'
                                        i += 1
                                continue

                            elif nokia_light_search_rx.search(val_line) != None:
                                val_line = re.sub("!","",val_line)
                                light_thresh_dict["rx_high"] = float(val_line.split()[-3])
                                light_thresh_dict["rx_low"] = float(val_line.split()[-2])
                                if re.search("show port .*c\d+",response.command) is None: #for 1G interfaces
                                    light_rxcur_dict["0"] = float(val_line.split()[-5])
                                else: # for 10G interfaces
                                    while i < 4:
                                        light_rxcur_dict[str(i)] = float(re.sub("\/[A-Z-]+","",val_lines[val_num+5+i].split()[-1])) # '-40.00/L-WA'=>'-40.00'
                                        i += 1
                                continue

                    ### Light search of Juniper start
                    if juniper_light_search_tx_high.search(val_line) != None:
                        light_thresh_dict["tx_high"]= float(val_line.split(" ")[-2])
                        continue
                    elif juniper_light_search_tx_low.search(val_line) != None:
                        light_thresh_dict["tx_low"]= float(val_line.split(" ")[-2])
                        continue
                    elif juniper_light_search_rx_high.search(val_line) != None:
                        light_thresh_dict["rx_high"]= float(val_line.split(" ")[-2])
                        continue
                    elif juniper_light_search_rx_low.search(val_line) != None:
                        light_thresh_dict["rx_low"]= float(val_line.split(" ")[-2])
                        continue
                    elif juniper_light_search_thresh.search(val_line) == None and juniper_light_search_tx_cur.search(val_line) != None and dbm_search.search(val_line) != None:
                        tmp_list= []
                        for i in val_line.split(): tmp_list.append(i) ### To get value as a float type
                        light_txcur_dict[str(juniper_count)]= float(tmp_list[-2])
                        continue
                    elif juniper_light_search_thresh.search(val_line) == None and juniper_light_search_rx_cur.search(val_line) != None and dbm_search.search(val_line) != None:
                        tmp_list= []
                        for i in val_line.split(): tmp_list.append(i) ### To get value as a float type
                        light_rxcur_dict[str(juniper_count)]= float(tmp_list[-2])
                        juniper_count+= 1
                        continue

                    if juniper_count != 0: continue # For skip below if os is junos.

                    ### Light search of Cisco start
                    if mfg == "cisco":
                      if dbm_search.search(val_line) != None:
                        tmp_list= []
                        for i in val_line.split(): tmp_list.append(i)
                        light_value_list.append(tmp_list)

                        for val_light in light_value_list:
                            ### Get threshold
                            if val_light[0] == "Transmit": ### TX
                                if re.search(r"<-40.00|N/A", val_light[8].strip("\(")) == None: light_thresh_dict["tx_high"]= float(val_light[8].strip("\("))
                                else: light_thresh_dict["tx_high"]= float("-40.00") ### If -40.00 or N/A detected, it stored -40.00 forcely.

                                if re.search(r"<-40.00|N/A", val_light[12].strip("\(")) == None: light_thresh_dict["tx_low"]= float(val_light[12].strip("\("))
                                else: light_thresh_dict["tx_low"]= float("-40.00") 

                            elif val_light[0] == "Receive": ### RX
                                if re.search(r"<-40.00|N/A", val_light[8].strip("\(")) == None: light_thresh_dict["rx_high"]= float(val_light[8].strip("\("))
                                else: light_thresh_dict["rx_high"]= float("-40.00")

                                if re.search(r"<-40.00|N/A", val_light[12].strip("\(")) == None: light_thresh_dict["rx_low"]= float(val_light[12].strip("\("))
                                else: light_thresh_dict["rx_low"]= float("-40.00")

                            else:
                                ### If Gigabit-ether
                                if re.search(r"gigabitethernet", response.command) != None:
                                    ### Check TX and avoid error
                                    if re.search(r"Tx", val_light[0]) != None:
                                        if re.search(r"<-40.00|N/A", val_light[-2].strip("\(")) != None:
                                            light_txcur_dict[val_light[0]]= float("-40.00")
                                        else:
                                            light_txcur_dict[val_light[0]]= float(val_light[-2].strip("\("))
                                    else:
                                    ### Check RX and avoid error
                                        if re.search(r"<-40.00|N/A", val_light[-2].strip("\(")) != None:
                                            light_rxcur_dict[val_light[0]]= float("-40.00")
                                        else:
                                            light_rxcur_dict[val_light[0]]= float(val_light[-2].strip("\("))

                                else:
                                ### If NOT gigabit-ether
                                    ### Check TX error
                                    if re.search(r"<-40.00|N/A", val_light[-6].strip("\(")) != None: 
                                        light_txcur_dict[val_light[0]]= float("-40.00")
                                    else:
                                        light_txcur_dict[val_light[0]]= float(val_light[-6].strip("\("))

                                    ### Check RX error
                                    if re.search(r"<-40.00|N/A", val_light[-2].strip("\(")) != None:
                                        light_rxcur_dict[val_light[0]]= float("-40.00")
                                    else:
                                        light_rxcur_dict[val_light[0]]= float(val_light[-2].strip("\("))

                     ### End of cisco ###
                command_response.append(" ")
            #print("Tx dict: {}".format(light_txcur_dict))
            #print("Rx dict: {}".format(light_rxcur_dict))
            #print("Thresh old: {}".format(light_thresh_dict))

            ### Just Compare with rx/tx and threshold. Not depends on cisco/juniper
            if light_thresh_dict:
                ### TX
                for num, val_light in light_txcur_dict.items():
                    if val_light >= light_thresh_dict["tx_high"] or val_light <= light_thresh_dict["tx_low"]:
                        light_color_flg= 1
                        light_color_point_tx.append(num)
                ### RX
                for num, val_light in light_rxcur_dict.items():
                    if val_light >= light_thresh_dict["rx_high"] or val_light <= light_thresh_dict["rx_low"]:
                        light_color_flg= 1
                        light_color_point_rx.append(num)

            ### Displaying from here
            if color_flg == 1 or light_color_flg == 1:
                ### Part of error check
                for val_line in command_response:
                    if juniper_error_search.search(val_line) != None and re.search(r":\s{1}[1-9]", val_line) != None:
                        print(Tools.colorstring(val_line, "red"))
                    elif juniper_other_error_search.search(val_line) != None and re.search(r"[1-9]", val_line) != None:
                        print(Tools.colorstring(val_line, "red"))
                    elif cisco_error_search.search(val_line) != None and re.search(r"[1-9]", val_line) != None:
                        print(Tools.colorstring(val_line, "red"))

                    ### Part of BGP error check
                    elif bgp_error_search.search(val_line) != None and bgp_error_avoid_search.search(val_line) == None:
                        print(Tools.colorstring(val_line, "red"))

                    ### Part of light power check
                    elif light_color_flg == 1:
                        coloring_flag= 0
                        ### For Tx using dict's key word
                        for point in light_color_point_tx:
                            if re.search(str(light_txcur_dict[str(point)]), val_line) != None:
                                coloring_flag= 1
                        ### For Rx using dict's key word
                        for point in light_color_point_rx:
                            if re.search(str(light_rxcur_dict[str(point)]), val_line) != None:
                                coloring_flag= 1

                        ### Branch for light power output wether add color or not
                        if coloring_flag == 0: print(val_line)
                        else: print(Tools.colorstring(val_line, "red"))
                    else:
                        print(val_line)
            else:
                ### This is not neseccery case for add color
                for val_line in command_response:
                    print(val_line)

### Debug status #####
#cisco----
#10G:  good:OK(287840) bad: OK(293798)
#1G:   good:OK(215300) bad: OK(GIN-EU-SID2005294)
#100G: good:OK(255121) bad: OK(293874)
#Juniper---
#10G:  good:OK(219457) bad: OK(294197)
######################

##### Original code #######
#            for response in session(cmds):
#                msg = '-' * 15 + '\n'
#                msg += '%s : %s ' % (router, re.sub(' {2,}', ' ', response.command)) + '\n'
#                msg += response.response + '\n'##### MEMO: "response.response" is command response.
#                print(msg)

        except KeyboardInterrupt:
            print("pressed control-c by user")
            sys.exit()

########## Added for pre-ping #####
    @staticmethod
    def send_command_pre(session, router, cmds):
        try:
            ping_fail_flag= 0
            for response in session(cmds):
                msg = response.response
                if re.search(r"\!", msg) == None:
                    ping_fail_flag= 1
                    #msg = '-' * 15 + "\n"
                    #msg += '%s : %s ' % (router, re.sub(' {2,}', ' ', response.command)) + '\n'
                    #msg += "*** ping failed ***\n"
                    #msg += response.response + '\n'
                    #print(msg)
            return(ping_fail_flag)

        except KeyboardInterrupt:
            print("pressed control-c by user")
            sys.exit()
### End of addition ###

    def check_ifc_list_current_status(self, router, mfg, interface_info_list):

        session = RouterSession(router, mfg)

        for interface_info in interface_info_list:
            usid = interface_info['cust_id']
            interface = interface_info['interface']
            if mfg == 'nokia' and re.search("(.*):",interface) is not None: # for nokia case,  convert eth-esat-1/1/8:3903 into eth-esat-1/1/8
                interface = re.search("(.*):",interface).group(1)
            name = interface_info['name']
            os_rev = interface_info['os_rev']

            ipv4_peer_list = []
            ipv6_peer_list = []

            if interface_info['peer_list']:
                for neighbor in interface_info['peer_list']:
                    if ':' in neighbor:
                        ipv6_peer_list.append(neighbor)
                    else:
                        ipv4_peer_list.append(neighbor)

            """ * Snap of interface:
                * Logs:
                * Light levels:
                * sh arp entries:
                * sh bgp summ of BOTH v4 and v6:
                * Ping bgp session:
                * Clear counters:
            """
            msg = 'Start Checking USID: {}, {} {} ({})'.format(usid, router, interface, name)
            print(Tools.colorstring(msg, 'green'))
            print('Stats URL: {} {}'.format(router, interface))
            print(Tools.colorstring(Tools.stats_url(' '.join([router, interface])), 'blue'))
            print('Gnome URL: USID {}'.format(usid))
            print(Tools.colorstring(Tools.gnome_url(usid), 'blue'))
            print('-' * 15 + '\n')
            print('=' * 15)
            print('You may copy and paste the below output to customer')
            print('=' * 15 + '\n')
            print('USID: {}'.format(usid))
            cmds = []
            cmds.append(RouterCommand.show_cloc(mfg))
            self.send_command(session, router, cmds,mfg)

            # check if start
            if self.gc_flag == False:
                msg = 'Checking interface status and logs: {} {}'.format(router, interface)
                if interface_info['bundle_ifc_name']:
                    msg += ' (also {})'.format(interface_info['bundle_ifc_name'])
            else:
                msg = 'Checking interface status: {} {} (GC-mode)'.format(router, interface)
            print(Tools.colorstring(msg, 'green'))
            cmds = []

            ### Interface
            cmds.append(RouterCommand.show_ifc_info(mfg, interface, self.ce_flag, self.gc_flag))

            ### Log
            if self.ce_flag == False and self.gc_flag == False:
                cmds.append(RouterCommand.show_log_ifc(mfg, os_rev, interface))

            if 'bundle-ether' not in interface:
                cmds.append(RouterCommand.show_power(mfg, interface, self.ce_flag, self.gc_flag))

            # check bundle start
            if interface_info['bundle_ifc_name']:
                cmds.append(RouterCommand.show_ifc_info(mfg, interface_info['bundle_ifc_name'], self.ce_flag, self.gc_flag))

            self.send_command(session, router, cmds,mfg)

            # check arp, ping, bgp
            if interface_info['peer_list']:
                if self.gc_flag == False:
                    msg = 'Checking Arp, Ping and BGP\n'
                else:
                    msg = 'Checking Ping (GC-mode)'
                print(Tools.colorstring(msg, 'green'))

                if len(ipv4_peer_list) > 0:
                    for ipv4_peer in ipv4_peer_list:
                        msg = 'Checking {}'.format(ipv4_peer)
                        print(Tools.colorstring(msg, 'cyan'))

                        ### If ce_flag is TRUE, run pre_ping
                        if self.ce_flag == True:
                            cmds= []
                            cmds.append(RouterCommand.pre_ping(mfg, ipv4_peer))
                            ping_fail_flag= self.send_command_pre(session, router, cmds)

                        cmds = []
                        if self.gc_flag == False:
                            cmds.append(RouterCommand.show_arp(mfg, ipv4_peer))

                        if self.ce_flag == True and ping_fail_flag == 0:
                            cmds.append(RouterCommand.run_ping(mfg, ipv4_peer, 1000))
                        else:
                            cmds.append(RouterCommand.run_ping(mfg, ipv4_peer, 10))
                            if self.ce_flag == True: print("ping count is set 10 due to ping fail")

                        if self.gc_flag == False:
                            cmds.append(RouterCommand.bgp_status(mfg, ipv4_peer))
                            cmds.append(RouterCommand.bgp_summary(mfg, ipv4_peer))
                        
                        if self.ce_flag == False and self.gc_flag == False:
                            cmds.append(RouterCommand.show_log_peer(mfg, os_rev, ipv4_peer))

                        # Run here using cmds-list concurrently with display output
                        self.send_command(session, router, cmds,mfg)


                ### IPv6 phase
                if len(ipv6_peer_list) > 0:
                    for ipv6_peer in ipv6_peer_list:
                        msg = 'Checking {}'.format(ipv6_peer)
                        print(Tools.colorstring(msg, 'cyan'))

                        ### If ce_flag is TRUE, run pre_ping
                        if self.ce_flag == True:
                            cmds = []
                            cmds.append(RouterCommand.pre_ping(mfg, ipv6_peer))
                            ping_fail_flag= self.send_command_pre(session, router, cmds)

                        cmds = []
                        if self.gc_flag == False:
                            cmds.append(RouterCommand.show_arp6(mfg, ipv6_peer))

                        if self.ce_flag == True and ping_fail_flag == 0:
                            cmds.append(RouterCommand.run_ping(mfg, ipv6_peer, 1000))
                        else:
                            cmds.append(RouterCommand.run_ping(mfg, ipv6_peer, 10))
                            if self.ce_flag == True: print("ping count is set 10 due to ping fail")

                        if self.gc_flag == False:
                            cmds.append(RouterCommand.bgp_status(mfg, ipv6_peer))
                            cmds.append(RouterCommand.bgp_summary(mfg, ipv6_peer))

                        if self.ce_flag == False and self.gc_flag == False:
                            cmds.append(RouterCommand.show_log_peer(mfg, os_rev, ipv6_peer))

                        # Run here using cmds-list
                        self.send_command(session, router, cmds,mfg)


######### start of Addition for show bgp_macro info ######
#### This is based on Dan request: If a customer has bgp can it pull the ASN and AS-macro info only?
        #
#            if self.ce_flag == True or self.gc_flag == True:
#                sys.exit()

            # For show bgp_macro info
#            query = ConfigToolsDB.get_bgp_macro(router, interface)
#            bgp_macro_list = ConfigToolsDB.search(query, listing=True)

#            if interface_info['bundle_ifc_name']:
#                query = ConfigToolsDB.get_bgp_macro(router, interface_info['bundle_ifc_name'])
#                bgp_macro_list = ConfigToolsDB.search(query, listing=True)

#            if bgp_macro_list == None or len(bgp_macro_list) == 0:
#                print("No match data found")
#                session.close_session()
#                sys.exit()

#            msg= "Checking about AS information"
#            print(Tools.colorstring(msg, 'cyan'))
#            print("---------------\n")

#            for tap in bgp_macro_list:
#                if tap[0] != None and len(str(tap[0])) > 3: len_asn= len(str(tap[0])) ### ASN
#                else: len_asn= 3
#                if tap[1] != None and len(tap[1]) > 4: len_name= len(tap[1]) ### AS-NAME
#                else: len_name= 4
#                if tap[2] != None and len(tap[2]) > 8: len_macro= len(tap[2]) ### AS_MACRO
#                else: len_macro= 8
#                if tap[3] != None and len(str(tap[3])) > 9: len_count= len(str(tap[3])) ### Prefix-count
#                else: len_count= 9
#                if tap[4] != None and len(tap[4]) > 15: len_spec= len(tap[4]) ### Allow_spcifics
#                else: len_spec= 15
#                if tap[5] != None and len(tap[5]) > 9: len_v6macro= len(tap[5]) ### AS IPv6_macro
#                else: len_v6macro= 9
#                if tap[6] != None and len(str(tap[6])) > 10: len_v6count= len(str(tap[6])) ### AS IPv6 Prefix-count
#                else: len_v6count= 10
#                if tap[7] != None and len(tap[7]) > 16: len_c6spec= len(tap[7]) ### IPv6 Allow_specifics
#                else: len_v6spec= 16
#                if tap[8] != None and tap[8] != "none" and len(tap[8]) > 8: len_irr= len(tap[8]) ### IRR_source
#                else: len_irr= 8

#                r_tap= []

#                for x in tap:
#                    if x != None: r_tap.append(str(x))
#                    else: r_tap.append("None")

#                len_total= len_asn + len_name + len_macro + len_count + len_spec + len_v6macro + len_v6count + len_v6spec + len_irr

#                print("ASN " + " " *(len_asn - 3) + "|" +\
#                      " Name " + " " *(len_name - 4) + "|" +\
#                      " AS_macro " + " " *(len_macro - 8) + "|" +\
#                      " pfx_count " + " " *(len_count - 9) + "|" +\
#                      " allow_specifics " + " " *(len_spec - 15) + "|" +\
#                      " AS6_macro " + " " *(len_v6macro - 9) + "|" +\
#                      " pfx6_count " + " " *(len_v6count - 10) + "|" +\
#                      " allow6_specifics " + " " *(len_v6spec - 16) + "|" +\
#                      " IRR_srcs " + " " *(len_irr - 8))
#                print("-" * (len_total + 24))
#                print(str(r_tap[0]) + " " + " " *(len_asn - len(r_tap[0])) + "|" +\
#                      " " + r_tap[1] + " " + " " *(len_name - len(r_tap[1])) + "|" +\
#                      " " + r_tap[2] + " " + " " *(len_macro - len(r_tap[2])) + "|" +\
#                      " " + str(r_tap[3]) + " " + " " *(len_count - len(r_tap[3])) + "|" +\
#                      " " + r_tap[4] + " " + " " *(len_spec - len(r_tap[4])) + "|" +\
#                      " " + r_tap[5] + " " + " " *(len_v6macro - len(r_tap[5])) + "|" +\
#                      " " + str(r_tap[6]) + " " + " " *(len_v6count - len(r_tap[6])) + "|" +\
#                      " " + r_tap[7] + " " + " " *(len_v6spec - len(r_tap[7])) + "|" +\
#                      " " + r_tap[8] + " " + " " *(len_irr - len(r_tap[8])))
#                print(" ")

################ end of addition ######


############ Added about only WAN service customer #################
#### This is based on CEs request.

            else: 
                nexthop_ip_list= []
                query= ConfigToolsDB.get_nexthop_ip(usid)
                nexthop_ip_list= ConfigToolsDB.search(query, listing=True) #Get and restore to list

                if nexthop_ip_list != None and len(nexthop_ip_list) != 0:
                    msg= 'Checking Arp, Ping and BGP\n'
                    print(Tools.colorstring(msg, 'green'))

                    for nexthop_ip_info in nexthop_ip_list:
                        if self.ce_flag == True:
                            cmds= []
                            cmds.append(RouterCommand.pre_ping(mfg, nexthop_ip_info.nexthop_ip))
                            ping_fail_flag= self.send_command_pre(session, router, cmds)

                        cmds= []

                        if self.gc_flag == False:
                            if ":" not in nexthop_ip_info.nexthop_ip:
                                cmds.append(RouterCommand.show_arp(mfg, nexthop_ip_info.nexthop_ip))
                            else:
                                cmds.append(RouterCommand.show_arp6(mfg, nexthop_ip_info.nexthop_ip))

                        if self.ce_flag == True and ping_fail_flag == 0:
                            cmds.append(RouterCommand.run_ping(mfg, nexthop_ip_info.nexthop_ip, 1000))
                        else:
                            cmds.append(RouterCommand.run_ping(mfg, nexthop_ip_info.nexthop_ip, 10))
                            if self.ce_flag == True: print("ping count is set 10 due to ping fail")

                        self.send_command(session, router, cmds,mfg)
#                else:
#                    msg= "Not found nexthop IPaddress\n"
#                    print(Tools.colorstring(msg, 'green'))

            # check static start
            if self.gc_flag == False:
                if interface_info['static_route']:
                    msg = 'Checking Static Route'
                    print(Tools.colorstring(msg, 'green'))
                    cmds = []
                    for static_route in interface_info['static_route']:
                        cmds.append(RouterCommand.static_route_status(mfg, static_route.split('_')[0]))
                    self.send_command(session, router, cmds,mfg)

            # check vc start
            if interface_info['isVLINK']:
                pattern = r'VC-(\d+)-[A|Z]'
                match = re.search(pattern, interface_info['comment'])
                if match:

                    msg = 'Checking VLINK'
                    print(Tools.colorstring(msg, 'green'))
                    cmds = []

                    vcid = str(match.group(1))
                    cmds.append(RouterCommand.show_l2vpn(mfg, interface, vcid))

                    if self.ce_flag == False and self.gc_flag == False:
                        cmds.append(RouterCommand.l2vpn_log(mfg, os_rev, vcid))

                    if self.gc_flag == False:
                        self.send_command(session, router, cmds,mfg)

            if self.clear:
                msg = 'Check & Clear Couters, Sleep 5[sec] and Check Couters again.'
                print(Tools.colorstring(msg, 'green'))
                cmds = []
                cmds.append(RouterCommand.show_ifc_error(mfg, interface))
                self.send_command(session, router, cmds,mfg)

                if mfg == "cisco":
                    if os_rev == "5.3.4": ### For difference command depends in OS-revision.
                        clear_cisco = 'clear counters ' + interface
                    else:
                        clear_cisco = 'clear counters interface ' + interface

                    msg = Tools.colorstring('trying to clear counters ({} {}).... '.format(router, interface), 'cyan')
                    print(msg)

                    tmp_output = session.session.send_command_timing(clear_cisco)
                    if '[confirm]' in tmp_output:
                        tmp_output += '\n'
                        tmp_output += session.session.send_command_timing("y")
                        msg = Tools.colorstring('clear counters may be successful', 'cyan')
                        msg += '\n'
                    else:
                        msg = Tools.colorstring('clear counters may NOT be successful', 'red')
                        msg += '\n'
                    ###print(msg)
                else:
                    msg = Tools.colorstring('trying to clear counters ({} {}).... \n'.format(router, interface), 'cyan')
                    print(msg)
                    cmds = []
                    cmds.append(RouterCommand.clear_ifc_counter(mfg, interface))
                    self.send_command(session, router, cmds,mfg)

                msg = Tools.colorstring('sleeping 5[sec]........', 'purple')
                print(msg)
                time.sleep(5)
                msg = Tools.colorstring('done', 'purple')
                print(msg)

                cmds = []
                cmds.append(RouterCommand.show_ifc_error(mfg, interface))
                self.send_command(session, router, cmds,mfg)


            ######### start of Addition for show bgp_macro info ######
            #### This is based on Dan request: If a customer has bgp can it pull the ASN and AS-macro info only?
            if self.ce_flag == True or self.gc_flag == True:
                sys.exit()

            # For show bgp_macro info
            query = ConfigToolsDB.get_bgp_macro(router, interface)
            bgp_macro_list = ConfigToolsDB.search(query, listing=True)

            if interface_info['bundle_ifc_name']:
                query = ConfigToolsDB.get_bgp_macro(router, interface_info['bundle_ifc_name'])
                bgp_macro_list = ConfigToolsDB.search(query, listing=True)

            if bgp_macro_list == None or len(bgp_macro_list) == 0:
                #print("\nNot found BGP information. Re-searching in other table.\n")
                query = ConfigToolsDB.get_bgp_macro_retry(router, interface)
                bgp_macro_list = ConfigToolsDB.search(query, listing=True)

                if bgp_macro_list == None or len(bgp_macro_list) == 0:
                    print("No BGP information found")
                    session.close_session()
                    sys.exit()

                #print("No BGP information found")
                #session.close_session()
                #sys.exit()

            msg= "Checking about AS information"
            print(Tools.colorstring(msg, 'cyan'))
            print("---------------\n")

            for tap in bgp_macro_list:
                if tap[0] != None and len(str(tap[0])) > 3: len_asn= len(str(tap[0])) ### ASN
                else: len_asn= 3
                if tap[1] != None and len(tap[1]) > 4: len_name= len(tap[1]) ### AS-NAME
                else: len_name= 4
                if tap[2] != None and len(tap[2]) > 8: len_macro= len(tap[2]) ### AS_MACRO
                else: len_macro= 8
                if tap[3] != None and len(str(tap[3])) > 9: len_count= len(str(tap[3])) ### Prefix-count
                else: len_count= 9
                if tap[4] != None and len(tap[4]) > 15: len_spec= len(tap[4]) ### Allow_spcifics
                else: len_spec= 15
                if tap[5] != None and len(tap[5]) > 9: len_v6macro= len(tap[5]) ### AS IPv6_macro
                else: len_v6macro= 9
                if tap[6] != None and len(str(tap[6])) > 10: len_v6count= len(str(tap[6])) ### AS IPv6 Prefix-count
                else: len_v6count= 10
                if tap[7] != None and len(tap[7]) > 16: len_c6spec= len(tap[7]) ### IPv6 Allow_specifics
                else: len_v6spec= 16
                if tap[8] != None and tap[8] != "none" and len(tap[8]) > 8: len_irr= len(tap[8]) ### IRR_source
                else: len_irr= 8

                r_tap= []

                for x in tap:
                    if x != None: r_tap.append(str(x))
                    else: r_tap.append("None")

                len_total= len_asn + len_name + len_macro + len_count + len_spec + len_v6macro + len_v6count + len_v6spec + len_irr

                print("ASN " + " " *(len_asn - 3) + "|" +\
                      " Name " + " " *(len_name - 4) + "|" +\
                      " AS_macro " + " " *(len_macro - 8) + "|" +\
                      " pfx_count " + " " *(len_count - 9) + "|" +\
                      " allow_specifics " + " " *(len_spec - 15) + "|" +\
                      " AS6_macro " + " " *(len_v6macro - 9) + "|" +\
                      " pfx6_count " + " " *(len_v6count - 10) + "|" +\
                      " allow6_specifics " + " " *(len_v6spec - 16) + "|" +\
                      " IRR_srcs " + " " *(len_irr - 8))
                print("-" * (len_total + 24))
                print(str(r_tap[0]) + " " + " " *(len_asn - len(r_tap[0])) + "|" +\
                      " " + r_tap[1] + " " + " " *(len_name - len(r_tap[1])) + "|" +\
                      " " + r_tap[2] + " " + " " *(len_macro - len(r_tap[2])) + "|" +\
                      " " + str(r_tap[3]) + " " + " " *(len_count - len(r_tap[3])) + "|" +\
                      " " + r_tap[4] + " " + " " *(len_spec - len(r_tap[4])) + "|" +\
                      " " + r_tap[5] + " " + " " *(len_v6macro - len(r_tap[5])) + "|" +\
                      " " + str(r_tap[6]) + " " + " " *(len_v6count - len(r_tap[6])) + "|" +\
                      " " + r_tap[7] + " " + " " *(len_v6spec - len(r_tap[7])) + "|" +\
                      " " + r_tap[8] + " " + " " *(len_irr - len(r_tap[8])))
                print(" ")

            ### End of addition for 

        session.close_session()

def main():
    start_time= time.time()

    psr = argparse.ArgumentParser()
    psr.add_argument('usid', help='eg) 260302')
    psr.add_argument('--clear', action='store_true', help='clear interfaces couter')
    psr.add_argument("--ce", action= "store_true", help= "Option for CEs. Several command result is full, log output is removed, and ping count is 1000.")
    psr.add_argument("--gc", action= "store_true", help= "Show the shorter result than as usual for GC case")
    args = psr.parse_args()

    if args.ce == True and args.gc == True:
        print("Please use only one either --ce or --gc")
        sys.exit()

    check = CustomerCheck(args, psr)
    check.init_target_info()
    check.get_interface_current_info()

    t= time.time() - start_time
    #print(t)

if __name__ == '__main__':
    main()
