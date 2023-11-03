#!/opt/gums/bin/python3
# -*- encoding: utf-8 -*-
# -*- coding: utf-8 -*-

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from operator import attrgetter
from functools import reduce

import argparse
import collections
import codecs
import difflib
import os
import io
import psycopg2.extras
import re
import stat
import yaml
import sys
import gzip
import logging
import logging.handlers
import socket

file_dir = os.path.dirname(os.path.abspath(__file__))
modules_dir = os.path.join(file_dir,"modules")
sys.path.append(modules_dir)
import retrieve_logs


try:
    import netmiko
except:
    print('## For using this script, please install netmiko ##')
    print('## Please run the command below ##')
    print('pip3 install --user -U netmiko cryptography')
    print()
    sys.exit()

sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8')
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Load setting file
file_dir = os.path.dirname(os.path.abspath(__file__))
setting_file = os.path.join(file_dir,"modules","settings.yml")
if os.path.exists(setting_file):
     with open(setting_file) as f:
         settings = yaml.safe_load(f)
else:
     print("ERROR: Failed to find settings.yml.")
     exit()



VERSION = '1.13'
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

ifc_log_tuple = collections.namedtuple(
    'interface',
    ['lastdown', 'lastdown_sort', 'interface', 'interface_short', 'type', 'interface_name', 'telco',
     'cid', 'state', 'cust_id', 'count', 'nocfield', 'description', 'abbr', 'lastup', 'current']
)


bgp_log_tuple = collections.namedtuple(
    'bgp',
    ['lastdown', 'lastdown_sort', 'lastup', 'current', 'interface', 'interface_short',
     'peer_address', 'asn', 'type', 'description', 'telco', 'state', 'cust_id', 'count',
     'p_type', 'p_desc', 'p_state', 'i_p_desc']

)

vc_log_tuple = collections.namedtuple(
    'vc',
    ['lastdown', 'lastdown_sort', 'vcid', 'interface', 'interface_short',
     'another_side', 'another_side_short', 'description', 'usid', 'state',
     'count', 'vcid_int', 'lastup', 'current', 'neighbor']
)


regex_filter_tuple = collections.namedtuple(
    'regex_filter_tuple',
    ['filename', 'regex', 'filter']
)

ifcs_descr_type = collections.namedtuple(
    'ifcs_descr_type',
    ['dict_list', 'description', 'key_list', 'name_list']
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


# Log outout
LOG_DIR = '/tftpboot/kikeda/log/'
DOWNSORT_LOGFILE = 'downsort.log'
NOCCHECK_LOGFILE = 'noc_check.log'
NOCCHECK_DOWN_LOGFILE = 'noc_check_down.log'


# log output
loggers = {}


####################################################################################
class Logger:
    def __init__(self, file_name, level=0):
        self.file_name = file_name
        self.level = level

        global loggers
        if loggers.get(file_name):
            self.system_logger = loggers.get(file_name)
        else:
            self.system_logger = logging.getLogger(file_name)
            self.set_logger()

    def set_logger(self):
        if self.level == 5:
            log_level = logging.DEBUG
        elif self.level == 4:
            log_level = logging.INFO
        elif self.level == 3:
            log_level = logging.WARNING
        elif self.level == 2:
            log_level = logging.ERROR
        elif self.level == 1:
            log_level = logging.CRITICAL
        else:
            log_level = logging.DEBUG

        self.system_logger.setLevel(log_level)
        formatter = logging.Formatter('[%(asctime)s] %(levelname)s %(message)s')
        handler = logging.handlers.RotatingFileHandler(
            self.file_name,
            maxBytes=1024000,  # 1MB
            backupCount=10  # 10 files
        )
        handler.setLevel(log_level)
        handler.setFormatter(formatter)
        self.system_logger.addHandler(handler)

        loggers[self.file_name] = self.system_logger

    def debug(self, message, data=None):
        if data:
            self.system_logger.debug(message+'\n'+data)
        else:
            self.system_logger.debug(message)

    def info(self, message, data=None):
        if data:
            self.system_logger.info(message+'\n'+data)
        else:
            self.system_logger.info(message)

    def warning(self, message, data=None):
        if data:
            self.system_logger.warning(message+'\n'+data)
        else:
            self.system_logger.warning(message)

    def error(self, message, data=None):
        if data:
            self.system_logger.error(message+'\n'+data)
        else:
            self.system_logger.error(message)

    def critical(self, message, data=None):
        if data:
            self.system_logger.critical(message+'\n'+data)
        else:
            self.system_logger.critical(message)



####################################################################################
class Cloginrc:
    def __init__(self, file="~/.cloginrc"):
        self.file = os.path.expanduser(file)
        self._parse()

    def _parse(self):
        with open(self.file) as f:
            for line in f:
                # line = line.expandtabs()
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
                strip_prompt=True, strip_command=True, delay_factor=delay_factor)

            response = re.sub('\{master\}', '', response).strip()
            response = re.sub('---\(more (\d+)%\)---', '', response).strip()
            response = re.sub('\[\]','',response).rstrip() 
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


#######################################################################################################################
class Tools(object):

    @staticmethod
    def logging(status, message, data='', logfile='test.log'):

        try:
            user = ''
            for name in ('LOGNAME', 'USER', 'LNAME', 'USERNAME'):
                user = os.environ.get(name)
                if user:
                    break
            if user is None:
                user = 'someone'

            logger = Logger(LOG_DIR + logfile)

            if status is True:
                logger.info('{} : {}'.format(user, message), data)
            elif status is False:
                logger.error('{} : {}'.format(user, message), data)

            os.chmod(LOG_DIR + logfile, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
        except:
            # import traceback
            # err_msg = traceback.format_exc()
            # print(err_msg)
            pass

    @staticmethod
    def colorstring(string, color):
        RED = '\033[31m'
        GREEN = '\033[32m'
        YELLOW = '\033[33m'
        BLUE = '\033[34m'
        PURPLE = '\033[35m'
        CYAN = '\033[36m'
        END = '\033[0m'

        # BLACK = '\033[30m'
        # WHITE = '\033[37m'
        # BOLD = '\038[1m'
        # UNDERLINE = '\033[4m'
        # INVISIBLE = '\033[08m'
        # REVERCE = '\033[07m'

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
    def stats_url(interface):
        stats_url = 'https://stats.gin.ntt.net/stats/ip-eng/graph_stats.cgi?'

        tday, yday = datetime.now(), datetime.now() - timedelta(days=1)
        router, ifc_name = interface.split(' ')

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
    def multi_stats_url(routers_dict):

        multi_url_dict = collections.OrderedDict()

        tday, yday = datetime.now(), datetime.now() - timedelta(days=1)

        for router in routers_dict:
            stats_url = 'https://stats.gin.ntt.net/stats/ip-eng/graph_stats.cgi?'
            params = [
                'do_graph=Show+Graph',
                'dates=%s:%s' % (yday.strftime('%Y.%m.%d'), tday.strftime('%Y.%m.%d')),
                'bps=bps',
                'errors=errors',
                # 'qos_drops=qos_drops',
                'skip_unused=skip_unused',
                'ifc_partial_match=1?',
                'router=%s' % router,
            ]
            for ifc_name in routers_dict[router]:
                params.append('interface_%s=on' % ifc_name)

            stats_url += '&'.join(params)
            multi_url_dict[router] = stats_url

        return multi_url_dict

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
    def yes_no_input():
        while True:
            choice = input("Please respond with 'yes' or 'no' [y/N]: ").lower()
            if choice in ['y', 'ye', 'yes']:
                return True
            elif choice in ['n', 'no']:
                return False

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
    def gnome_url(cust_id):
        gnome_url = 'https://gnome.gin.ntt.net/index.pl?usid=%s' % cust_id
        return gnome_url

    @staticmethod
    def get_anoc_coutry_fiter():
        query = ConfigToolsDB.get_asia_county_info()
        asia_county_infos = ConfigToolsDB.search(query, listing=True)

        anoc_countrycode_list = []
        for asia_county in asia_county_infos:
            anoc_countrycode_list.append(asia_county.code)

        return '|'.join(anoc_countrycode_list)


#######################################################################################################################
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
    def get_nocfield(router, interface):
        selector = 'ct_devices.device_name, ct_ifcs.ifc_name, ct_ifcs.noc_field'
        table = 'ct_ifcs, ct_devices'
        filter = 'ct_devices.device_id = ct_ifcs.device_id and ' \
                 'ct_devices.device_name = \'%(router)s\' and ct_ifcs.ifc_name ilike \'%(interface)s\'' % locals()

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()
        return sql, collections.namedtuple('nocfield',
                                           ['router', 'interface', 'nocfield']
                                           )

    @staticmethod
    def get_interface_info(router, interface):
        selector = 'interfaces.router, interfaces.ifc_name, routers.mfg, routers.os_rev, interfaces.intf_type, ' \
                   'interfaces.cust_id, interfaces.name, interfaces.telco, interfaces.cid, interfaces.state, ' \
                   'interfaces.comment'
        table = 'routers, interfaces'
        filter = '(interfaces.router = routers.name) and ' \
                 'interfaces.router = \'%(router)s\' and interfaces.ifc_name ilike \'%(interface)s\'' % locals()

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()
        return sql, collections.namedtuple('interface_info',
                                           ['router', 'interface', 'mfg', 'os_rev', 'intf_type',
                                            'cust_id', 'name', 'telco', 'cid', 'state',
                                            'comment']
                                           )

    @staticmethod
    def get_abbr_info(telco_name):
        selector = 'ct_vendor.name, ct_vendor.abbr'
        table = 'ct_vendor'
        filter = 'ct_vendor.name = \'%(telco_name)s\'' % locals()

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()
        return sql, collections.namedtuple('abbr_info', ['name', 'abbr'])

    @staticmethod
    def get_another_ifc_info(cid):
        selector = 'router, ifc_name'
        table = 'interfaces'
        filter = 'cid ~* \'%(cid)s\'' % locals()

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()
        return sql, collections.namedtuple(
            'bb_interface', ['router', 'interface']
        )

    @staticmethod
    def get_vc_info(vcid):
        selector = 'l2.id, ifc.name as name, l2.router, l2.ifc_name, ifc.cust_id as usid, ifc.state'
        table = 'l2vpnu l2'
        join = 'interfaces ifc ON l2.router = ifc.router and l2.ifc_name = ifc.ifc_name'
        filter = 'l2.id = \'%(vcid)s\'' % locals()

        sql = 'select %(selector)s from %(table)s left join %(join)s where %(filter)s order by id' % locals()
        return sql, collections.namedtuple(
            'vc_info',
            ['id', 'name', 'router', 'ifc_name', 'usid', 'state']
        )

    @staticmethod
    def get_peer_info(router, ipaddr):
        selector = 'peers.router, peers.multihop_src, peers.ip_addr, peers.asn, peers.description, peers.peertype, ' \
                   'peers.state, routers.mfg, routers.os_rev, ' \
                   'interfaces.intf_type, interfaces.cust_id, interfaces.name, interfaces.telco, interfaces.state'
        table = 'peers, routers, interfaces'
        filter = 'peers.router = routers.name and peers.router = \'%(router)s\' and peers.ip_addr = \'%(ipaddr)s\' ' \
                 'and peers.router = interfaces.router and peers.multihop_src = interfaces.ifc_name' % locals()

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()

        return sql, collections.namedtuple(
            'peer_info',
            ['router', 'interface', 'ip_addr', 'asn', 'p_desc', 'p_type',
             'p_state', 'mfg', 'os_rev',
             'intf_type', 'cust_id', 'name', 'telco', 'state'])

    @staticmethod
    def get_peer_usid_info(router, customer_name):
        selector = 'routers.name, interfaces.ifc_name, interfaces.cust_id, interfaces.name'
        table = 'routers, interfaces'
        filter = 'routers.name = interfaces.router and routers.name = \'%(router)s\' and ' % locals()
        filter += 'interfaces.name like \'%{}%\''.format(customer_name)

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()

        return sql, collections.namedtuple(
            'peer_usid_info',
            ['router', 'interface', 'cust_id', 'name']
        )

    @staticmethod
    def get_asia_county_info():
        selector = 'comm_country_descr, comm_country_proper_name'
        table = 'ct_comm_country'
        filter = 'comm_region_id = 3'

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()

        return sql, collections.namedtuple(
            'asia_county_info',
            ['code', 'name']
        )

    @staticmethod
    def get_router_info(router):
        selector = 'name, mfg, os_rev'
        table = 'routers'
        filter = 'name = \'%(router)s\'' % locals()

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()
        return sql, collections.namedtuple('router_info',
                                           ['name', 'mfg', 'os_rev']
                                           )
    #### This is added to improve investigate-mode to look bgp-summary with ifc-investigate-result
    @staticmethod
    def check_peer_from_circuit(router, interface):
        sql= "SELECT ip_addr FROM peers WHERE router = '{}' and multihop_src = '{}'".format(router, interface)
        return sql, collections.namedtuple('peer_ip_info', ['peering_ip'])


#######################################################################################################################
class RouterCommand(object):

    @staticmethod
    def show_cloc(peer):
        if peer.mfg == "cisco":
            cmd = 'show cloc'
        elif peer.mfg == "juniper":
            cmd = 'show system uptime | match current'
        else:
            cmd = 'show time'

        return router_command(key='show_cloc', command=cmd)

    @staticmethod
    def ifc_desc(peer):
        interface = peer.interface
        if peer.mfg == "cisco":
            cmd = 'show interfaces %(interface)s description' % locals()
        elif peer.mfg == "juniper":
            cmd = 'show interfaces %(interface)s descriptions' % locals()
        else:
            interface = re.sub("eth-","",interface)
            interface = re.sub(":\d+","",interface)
            cmd = "show port %(interface)s | match 'Description|Admin State|Oper State'" % locals()
        return router_command(key='ifc_desc', command=cmd)

    @staticmethod
    def show_flap(peer):
        interface = peer.interface
        if peer.mfg == "cisco":
            cmd = 'show interfaces %(interface)s | include "flap|rate"' % locals()
        elif peer.mfg == "juniper":
            cmd = 'show interfaces %(interface)s | match "flap|rate"' % locals()
        else:
            interface = re.sub("eth-","",interface)
            interface = re.sub(":\d+","",interface)
            cmd = 'show port %(interface)s | match "Last State Change"' % locals()

        return router_command(key='show_flap', command=cmd)

    @staticmethod
    def show_power(peer):

        interface = peer.interface.split('.')[0]
        if peer.mfg == "cisco":
            cmd = 'show controllers %(interface)s phy | include \"x P | dBm\"' % locals()
        elif peer.mfg == "juniper":
            cmd = 'show interfaces diagnostics optics %(interface)s' % locals()
            cmd += '| except "volt|alarm|temp|off|bias" '
#            cmd += '| match "output|receive|rx" | except alarm | except warning'
        else:
            interface = re.sub("eth-","",interface)
            interface = re.sub(":\d+","",interface)
            cmd = "show port %(interface)s optical | match 'Tx Output|Rx Optical|Value'" % locals()

        return router_command(key='show_power', command=cmd)

    @staticmethod
    def show_error(peer):
        interface = peer.interface.split('.')[0]
        if peer.mfg == "cisco":
            cmd = 'show interfaces %(interface)s | include error' % locals()
        elif peer.mfg == "juniper":
            cmd = 'show interfaces %(interface)s extensive | match "cleared|rror|FIFO|Code" | except PDU' % locals()
        else:
            interface = re.sub("eth-","",interface)
            interface = re.sub(":\d+","",interface)
            cmd = 'show port %(interface)s | match Errors' % locals()
        return router_command(key='show_error', command=cmd)

    @staticmethod
    def ifc_log(peer):
        interface = peer.interface
        if peer.mfg == "cisco":
            if peer.os_rev == '5.3.4':
                cmd = 'show log | utility fgrep -i %(interface)s | utility tail count 4' % locals()
            else:
                cmd = 'show log | utility fgrep %(interface)s -i | utility tail count 4' % locals()
        elif peer.mfg == "juniper":
            cmd = 'show log messages | match %(interface)s | last 15 | no-more | except cast | match "SNMP_TRAP"' % locals()
        else:
            interface = re.sub("eth-","",interface)
            interface = re.sub(":\d+","",interface)
            cmd = 'show log log-id 101 message %(interface)s count 4' % locals()

        return router_command(key='ifc_log', command=cmd)

    @staticmethod
    def bgp_summary_asn4(peer):
        asn = peer.asn
        if peer.mfg == "cisco":
            cmd = 'show bgp ipv4 unicast summary | include \" %(asn)s \"' % locals()
        elif peer.mfg == "juniper":
            cmd = 'show bgp summary | match \" %(asn)s \"' % locals()
        else:
            cmd= "show router bgp summary family ipv4" % locals() 
        return router_command(key='bgp_summary_asn4', command=cmd)


    @staticmethod
    def bgp_summary_asn6(peer):
        asn = peer.asn
        if peer.mfg == "cisco":
            cmd = 'show bgp ipv6 unicast summary | utility fgrep \" %(asn)s \" -B 1' % locals()
        elif peer.mfg == "juniper":
            cmd = 'show bgp summary | match \" %(asn)s \"' % locals()
        else:
            cmd = "show router bgp summary family ipv6"  % locals()
        return router_command(key='bgp_summary_asn6', command=cmd)

    ### This is added for improve in feb. about get info with ifc investigation. wataru
    @staticmethod
    def bgp_summary_ipv4(interface_info, peering_ip):
        if interface_info.mfg == "cisco":
            cmd = 'show bgp ipv4 unicast summary | include \"%(peering_ip)s\"' % locals()
        elif interface_info.mfg == "juniper":
            cmd = 'show bgp summary | match \"%(peering_ip)s\"' % locals()
        else:
            cmd = "show router bgp summary family ipv4" % locals()
        return router_command(key='bgp_summary_ipv4', command=cmd)

    ### This is added for improve in feb. about get info with ifc investigation. wataru
    @staticmethod
    def bgp_summary_ipv6(interface_info, peering_ip):
        if interface_info.mfg == "cisco":
            cmd = 'show bgp ipv6 unicast summary | utility fgrep \"%(peering_ip)s\" -A 1' % locals()
        elif interface_info.mfg == "juniper":
            cmd = 'show bgp summary | match \"%(peering_ip)s\"' % locals()
        else:
            cmd = "show router bgp summary family ipv6"  % locals()
        return router_command(key='bgp_summary_ipv6', command=cmd)


    @staticmethod
    def bgp_asn_log(peer, last=10):
        asn = peer.asn
        if peer.mfg == "cisco":
            cmd = 'show logging | include \" %(asn)s)\" | utility tail -n %(last)s' % locals()
        elif peer.mfg == "juniper":
            cmd = 'show log messages | match \" %(asn)s)\" | last %(last)s' % locals()
        else:
            cmd = 'show log log-id 101 message \"(ASN %(asn)s)\" count 4' % locals()
        return router_command(key='bgp_asn_log', command=cmd)

    @staticmethod
    def show_l2vpn(peer, vcid):

        if peer.mfg == "cisco":
            ciscoVC = 'l2vpn-{}'.format(vcid)
            cmd = 'show l2vpn xconnect group %(ciscoVC)s' % locals()
        
        elif peer.mfg == "juniper":
            interface = peer.interface
            if '.' not in interface:
                interface += '.0'
            cmd = 'show l2circuit connections interface %(interface)s extensive' % locals()
        else:
            cmd = 'show service sdp-using | match ":%(vcid)s"' % locals()
        
        return router_command(key='show_l2vpn', command=cmd)

    @staticmethod
    def show_l2vpn_mtu(peer, vcid):

        if peer.mfg == "cisco":
            ciscoVC = 'l2vpn-{}'.format(vcid)
            cmd = 'show l2vpn xconnect group %(ciscoVC)s detail | include MTU' % locals()
        
            return router_command(key='show_l2vpn_mtu', command=cmd)

    @staticmethod
    def show_l2vpn_flap(peer, vcid):

        if peer.mfg == "cisco":
            ciscoVC = 'l2vpn-{}'.format(vcid)
            cmd = 'show l2vpn xconnect group %(ciscoVC)s detail | include Last time' % locals()
        
            return router_command(key='show_l2vpn_flap', command=cmd)

    @staticmethod
    def l2vpn_log(peer, vcid):

        if peer.mfg == "cisco":
        
            if peer.os_rev == '5.3.4':
                cmd = 'show log | utility fgrep -i "id  {}," | utility tail count 4'.format(vcid)
            else:
                cmd = 'show log | utility fgrep "id  {}," -i | utility tail count 4'.format(vcid)
        elif peer.mfg == "juniper":
            cmd = 'show log messages | match RPD_LAYER2 | match ": {}"'.format(vcid)
        else:
            cmd = 'show log log-id 101 message SVCMGR-MINOR-sdpBindStatusChanged | match ":{}"'.format(vcid)
        
        return router_command(key='l2vpn_log', command=cmd)

    @staticmethod
    def l2vpn_ping(peer, vcid, neighbor):

        if peer.mfg == "cisco":
            cmd = 'ping mpls pseudowire {} {} size 4000 verbose'.format(neighbor, vcid)
        elif peer.mfg == "juniper":
            interface = peer.interface
            if '.' not in interface:
                interface += '.0'
            cmd = 'ping mpls l2circuit interface %(interface)s reply-mode application-level-control-channel ' % locals()
            cmd += 'detail size 4000'
        
        return router_command(key='l2vpn_log', command=cmd)

    @staticmethod
    def show_ifc_lastflap(ifc, mfg):
        # interface = ifc.split('.')[0]
        interface = ifc
        if mfg == "cisco":
            cmd = 'show interfaces %(interface)s | include "Desc|line protocol|flap|rate"' % locals()
        elif mfg == "juniper":
            cmd = 'show interfaces %(interface)s | match "Desc|Physical interface|flap|rate"' % locals()
        else:
            "show port %(interface)s | match 'Description|Interface|Last State Change'" % locals()
        return router_command(key='show_lastflap', command=cmd)


#######################################################################################################################
class Downsort(object):

    def __init__(self, args, psr, sub_cmd_name=''):
        self.psr = psr
        self.sub_cmd_name = sub_cmd_name

        self.minute = args.minute
        self.hour = args.hour
        self.history = args.history
        self.timerange = args.timerange

        self.stats = args.stats

        self.investigate = args.investigate
        self.parallel = args.parallel
        self.detail = args.detail

        self.filter = args.filter
        self.country = args.country
        self.desc = args.desc
        self.anoc = args.anoc

        if self.anoc:
            self.country = Tools.get_anoc_coutry_fiter()

        self.interface_dict = {}
        self.log_tuple_list = []
        self.ifcs_list = []
        self.key = ''

        self.reverse = args.reverse
        self.ignore = args.ignore
        self.current = args.current
        self.terse = args.terse

    def get_help(self):
        return self.psr.format_help()

    def get_usage(self):
        return self.psr.format_usage()

    def gather_timerange_logs(self):

        match_time = re.match(r'(\d{2,12}):(\d{2,12})', self.timerange)
        try:
            if match_time:
                start_time_str = match_time.group(1)
                end_time_str   = match_time.group(2)
                self.start_time = datetime.strptime(start_time_str, '%Y%m%d%H%M')
                self.end_time   = datetime.strptime(end_time_str, '%Y%m%d%H%M')
               
            else:
                raise ValueError
    
        except ValueError:
            print('Please use --timerange yyyymmddHHMM:yyyymmddHHMM \n')
            print(self.get_help())
            sys.exit()

        msg = '\n** checking {} to {} {} flap **'.format(self.start_time.strftime("%Y/%m/%d %H:%M"),
                                                                  self.end_time.strftime("%Y/%m/%d %H:%M"),self.sub_cmd_name)
        return(self.start_time,self.end_time,self.sub_cmd_name,msg)

    def gather_history_logs(self):
        start_time = datetime.strptime(self.history+' 00:00:00', '%Y%m%d %H:%M:%S')
        end_time = datetime.strptime(self.history+' 23:59:59', '%Y%m%d %H:%M:%S')
        msg = '\n** checking {} {} flap **'.format(datetime.strptime(self.history,'%Y%m%d').strftime("%Y/%m/%d"),self.sub_cmd_name)
        return(start_time,end_time,self.sub_cmd_name,msg)


    def gather_latest_logs(self):
        if self.hour:
            if self.hour > 24:
                print('--hour must be 24 or less :)  Please use --history\n')
                print(self.get_help())
                sys.exit()
            self.minute = self.hour * 60
        elif self.minute > 1440:
            print('--minute must be 1440 or less :)  Please use --history\n')
            print(self.get_help())
            sys.exit()

        latest = datetime.now() - timedelta(minutes=self.minute)
        yyyymmddhhmm = latest.strftime("%Y/%m/%d %H:%M")
        minute = str(self.minute)

        if self.hour:
            hour = str(self.hour)
            if self.hour < 2:
                msg = '\n** checking last %(hour)s hour ( %(yyyymmddhhmm)s ~ ) ' % locals()
            else:
                msg = '\n** checking last %(hour)s hours ( %(yyyymmddhhmm)s ~ ) ' % locals()
        else:
            msg = '\n** checking last %(minute)s minutes ( %(yyyymmddhhmm)s ~ ) ' % locals()
        start_time=latest
        end_time=datetime.now()
        msg = msg + f'{self.sub_cmd_name} flap **'
        return(start_time,end_time,self.sub_cmd_name,msg)

    def match_filter(self, router=None, desc=None):
        isMatch = True

        if router:
            if self.country:
                router_coutry = router.split('.')[2]
                if not re.search(self.country, router_coutry):
                    isMatch = False
            if self.filter:
                if not re.search(self.filter, router):
                    isMatch = False
        elif desc:
            if self.desc:
                if not re.search(self.desc.lower(), desc.lower()):
                    isMatch = False
        return isMatch

    def sort(self):
        self.log_tuple_list = sorted(self.log_tuple_list, key=self.key, reverse=self.reverse)

    def add_stats(self):
        for ifcs in self.ifcs_list:
            for ifc_dict in ifcs.dict_list:
                ifc_dict['stats_url'] = Tools.colorstring(Tools.stats_url(ifc_dict['interface']), 'blue')

    def add_investigate_line(self):
        num = 1
        for ifcs in self.ifcs_list:
            for ifc_dict in ifcs.dict_list:
                ifc_dict['line'] = num
                num += 1

    def print_devided_table(self):
        for ifcs in self.ifcs_list:
            if len(ifcs.dict_list) > 0:
                print(ifcs.description)
                print(Tools.table_output(ifcs.dict_list, ifcs.key_list, ifcs.name_list))
                print()

    def start_investigation(self):
        if len(self.log_tuple_list) == 0:
            sys.exit()

        print("*" * 100)
        print("Which line's current status do you want to investigate?")
        print("ex) 1    ex) 4 5 6   ex) 7 13-16 20-23 25    ex) all")

        while True:
            try:
                input_line = input('>>>  ')
                input_line_str_list = re.split('[ |\||,]+', input_line)

                target_num_list = []

                for input_line_str in input_line_str_list:
                    if re.match(r'(\d+)-(\d+)', input_line_str):
                        a_num, z_num = input_line_str.split('-')

                        for num in range(int(a_num), int(z_num)+1):
                            target_num_list.append(num)
                    elif input_line_str == 'all':

                        line_count = 0
                        for ifcs in self.ifcs_list:
                            line_count += len(ifcs.dict_list)

                        for num in range(1, line_count + 1):
                            target_num_list.append(num)

                    else:
                        target_num_list.append(int(input_line_str))

                target_num_list_uniq = sorted(list(set(target_num_list)))

                if self.terse:
                    if len(target_num_list_uniq) > 80:
                        print('Must be 80 or less interfaces on terse mode :)')
                        continue
                else:
                    if len(target_num_list_uniq) > 20:
                        print('Must be 20 or less interfaces :) or you can use --terse to get just terse info')
                        continue

                if len(target_num_list_uniq) == 0:
                    continue

            except KeyboardInterrupt:
                print("pressed control-c by user")
                sys.exit()

            except:
                continue

            target_interface_list = []
            target_vc_interface_list = []

            for line in target_num_list_uniq:
                for ifcs in self.ifcs_list:
                    for ifc_dict in ifcs.dict_list:
                        if ifc_dict['line'] == line:
                            if self.sub_cmd_name == 'ifc':
                                target_interface_list.append(ifc_dict['interface'])
                            elif self.sub_cmd_name == 'bgp':
                                target_interface_list.append(
                                    ifc_dict['interface'] + ' ' + ifc_dict['peer_address']
                                )
                            elif self.sub_cmd_name == 'vc':
                                target_interface_list.append(ifc_dict['interface'])
                                target_vc_interface_list.append('{} {} {}'.format(ifc_dict['interface'],
                                                                                  ifc_dict['vcid_int'],
                                                                                  ifc_dict['neighbor']))
                            break

            if len(target_interface_list) == 0:
                print('no interfaces found...')
                continue

            if self.terse:

                target_interface_dict = collections.OrderedDict()

                for target_interface in target_interface_list:
                    router = target_interface.split()[0]
                    interface = target_interface.split()[1]

                    if router not in target_interface_dict:
                        target_interface_dict[router] = [interface]
                    else:
                        target_interface_dict[router].append(interface)

                for k, v in target_interface_dict.items():
                    target_interface_dict[k] = sorted(list(set(v)))

                for k, v in target_interface_dict.items():
                    print(k, end=' : ')
                    print(', '.join([Tools.make_short_interface_name(x) for x in v]))
                print("*" * 100)

                if self.parallel and len(target_interface_dict) > 1:
                    with ThreadPoolExecutor(max_workers=20) as executor:

                        alart = 'start terse mode by parallel login mode. Bug sometimes happen.\n' \
                                'updating related packages may help this. If bug happpens, ' \
                                'please try the commnad below\n'
                        alart += Tools.colorstring('pip3 install --user -U netmiko cryptography', 'yellow')
                        print(Tools.colorstring(alart, 'red'))

                        multi_router = []
                        multi_interface_list = []
                        for key, value in target_interface_dict.items():
                            multi_router.append(key)
                            multi_interface_list.append(value)

                            if len(multi_router) > 20:
                                print('Must be 20 or less routers on terse mode :)')
                                sys.exit()

                        res = executor.map(Downsort.investigate_interface_terse, multi_router, multi_interface_list)

                    for output in list(res):
                        print(output)
                else:
                    print(Tools.colorstring('start terse mode by login router one by one.....', 'red'))

                    for key, value in target_interface_dict.items():
                        output = Downsort.investigate_interface_terse(key, value)
                        print(output)

                break

            else:
                print(target_interface_list)
                print("*" * 100)

                if self.parallel and len(target_interface_list) > 1:
                    with ThreadPoolExecutor(max_workers=20) as executor:

                        alart = 'start investigation by parallel login mode. Bug sometimes happen.\n' \
                                'updating related packages may help this. If bug happpens, ' \
                                'please try the commnad below\n'
                        alart += Tools.colorstring('pip3 install --user -U netmiko cryptography', 'yellow')

                        print(Tools.colorstring(alart, 'red'))
                        detail_list = [self.detail for _ in range(len(target_interface_list))]

                        if self.sub_cmd_name == 'ifc':
                            res = executor.map(IfcDownsort.investigate_interface, target_interface_list, detail_list)
                        elif self.sub_cmd_name == 'bgp':
                            res = executor.map(BgpDownsort.investigate_peer, target_interface_list, detail_list)
                        elif self.sub_cmd_name == 'vc':
                            res = executor.map(VcDownsort.investigate_interface, target_vc_interface_list, detail_list)

                    for output in list(res):
                        print(output)
                else:
                    print(Tools.colorstring('start investigation by login router one by one.....', 'red'))

                    if self.sub_cmd_name == 'ifc':
                        for target_interface in target_interface_list:
                            output = IfcDownsort.investigate_interface(target_interface, self.detail)
                            print(output)
                    elif self.sub_cmd_name == 'bgp':
                        for target_interface in target_interface_list:
                            output = BgpDownsort.investigate_peer(target_interface, self.detail)
                            print(output)

                    elif self.sub_cmd_name == 'vc':
                        for target_vc_interface in target_vc_interface_list:
                            output = VcDownsort.investigate_interface(target_vc_interface, self.detail)
                            print(output)
                break

    @staticmethod
    def investigate_interface_terse(router, interface_list):
        query = ConfigToolsDB.get_router_info(router)
        router_info = ConfigToolsDB.search(query, listing=False)

        try:
            result = Downsort.check_ifc_list_lastflap(router, interface_list, router_info.mfg)
        except KeyboardInterrupt:
            print("pressed control-c by user")
            sys.exit()
        except:
            print('could not get interfaces information from {}'.format(router))
            result = None

        return result

    @staticmethod
    def check_ifc_list_lastflap(router, interface_list, mfg, detail=True):

        session = RouterSession(router, mfg)

        cmds = []
        for interface in interface_list:
            cmds.append(RouterCommand.show_ifc_lastflap(interface, mfg))

        msg = '*' * 100
        msg += Tools.colorstring('\nChecking {} : {}\n'.format(
            router,
            ', '.join([Tools.make_short_interface_name(interface) for interface in interface_list])), 'green')

        for response in session(cmds):
            if detail:
                msg += '> %s : %s ' % (router, re.sub(' {2,}', ' ', response.command)) + '\n'
            msg += response.response + '\n\n'

        session.close_session()

        return_output = ''
        for output in msg.split('\n'):
            if 'down' in output.lower():
                return_output += Tools.colorstring(output, 'red') + '\n'
            elif 'rate 0 bits/sec' in output:
                return_output += Tools.colorstring(output, 'red') + '\n'
            elif ' 0 bps ' in output:
                return_output += Tools.colorstring(output, 'red') + '\n'
            else:
                return_output += output + '\n'

        return return_output

    def log_parse(self, time=None, history_datetime=None, start_time=None, end_time=None):
        for mfg in settings["mfgs"]:
            lines = retrieve_logs.run(mfg,start_time,end_time,True)
            for line in lines:
                self.update_interface_dict(mfg,line)



class IfcDownsort(Downsort):

    def __init__(self, args, psr):
        super().__init__(args, psr, sub_cmd_name='ifc')

        if self.current and not self.history:
            self.key_list = ['lastdown', 'interface_short', 'description', 'current', 'state', 'count']
            self.name_list = ['lastdown', 'interface', 'description', 'cur', 'db', 'ct']

            self.bb_key_list = ['lastdown', 'interface_short', 'description', 'current', 'state', 'count', 'nocfield']
            self.bb_name_list = ['lastdown', 'interface', 'description', 'cur', 'db', 'ct', 'noc']
        else:
            self.key_list = ['lastdown', 'interface_short', 'description', 'state', 'count']
            self.name_list = ['lastdown', 'interface', 'description', 'db', 'ct']

            self.bb_key_list = ['lastdown', 'interface_short', 'description', 'state', 'count', 'nocfield']
            self.bb_name_list = ['lastdown', 'interface', 'description', 'db', 'ct', 'noc']

        if self.stats:
            self.bb_key_list.append('stats_url')
            self.bb_name_list.append('stats_url')
            self.key_list.append('stats_url')
            self.name_list.append('stats_url')

        if self.investigate:
            self.bb_key_list.insert(0, 'line')
            self.bb_name_list.insert(0, 'line')
            self.key_list.insert(0, 'line')
            self.name_list.insert(0, 'line')

        self.ifcs_bb = ifcs_descr_type(
            dict_list=[],
            description='[BackBone Circuits]',
            key_list=self.bb_key_list,
            name_list=self.bb_name_list
        )
        self.ifcs_bp = ifcs_descr_type(
            dict_list=[],
            description='[Peer Circuits]',
            key_list=self.key_list,
            name_list=self.name_list
        )
        self.ifcs_bc = ifcs_descr_type(
            dict_list=[],
            description='[Customer Circuits]',
            key_list=self.key_list,
            name_list=self.name_list
        )
        self.ifcs_other = ifcs_descr_type(
            dict_list=[],
            description='[Other Circuits]',
            key_list=self.key_list,
            name_list=self.name_list
        )

        self.ifcs_list = [self.ifcs_bb, self.ifcs_bp, self.ifcs_bc, self.ifcs_other]
        self.key = attrgetter('lastdown_sort', 'interface')

    def devide_type(self):
        for item in self.log_tuple_list:
            if item.type == 'BB':
                self.ifcs_bb.dict_list.append(item._asdict())
            elif (item.type == 'BL') and (('bb be-' in item.interface_name) or ('bb ae-' in item.interface_name)):
                self.ifcs_bb.dict_list.append(item._asdict())
            elif item.type == 'BP':
                self.ifcs_bp.dict_list.append(item._asdict())
            elif item.type == 'BC' or item.type == 'BL' or item.type == 'BT' or item.type == 'SC' or item.type == 'BD':
                self.ifcs_bc.dict_list.append(item._asdict())
            else:
                self. ifcs_other.dict_list.append(item._asdict())

    def make_log_tuple_list(self):
        for key, value in self.interface_dict.items():
            router = key.split('_')[0]
            ifc_name = key.split('_')[1]
            lastdown = value[0]
            count = value[1]
            lastup = value[2]
            current = value[3]

            # for ignore only up log
            if count == 0:
                continue

            # for filter
            if not self.match_filter(router=router):
                continue

            query = ConfigToolsDB.get_interface_info(router, ifc_name)
            interface_info = ConfigToolsDB.search(query, listing=False)

            query = ConfigToolsDB.get_nocfield(router, ifc_name)
            nocfield = ConfigToolsDB.search(query, listing=False)
            if (interface_info is not None) and (nocfield is not None):
                if interface_info.state == 'shutdown':
                    continue
                elif interface_info.state == 'turn-up' and self.ignore:
                    continue

                if interface_info.telco:
                    query = ConfigToolsDB.get_abbr_info(interface_info.telco)
                    abbr_info = ConfigToolsDB.search(query, listing=False)
                    abbr = abbr_info.abbr if abbr_info else interface_info.telco
                else:
                    abbr = None

                interface = ' '.join([interface_info.router, interface_info.interface])
                interface_short = Tools.make_short_interface_name(interface)
                description = '{}: {}'.format(interface_info.intf_type, interface_info.name)

                if abbr or interface_info.cid or interface_info.comment:
                    description += ' - {} {} {}'.format(Tools.none2empty(abbr),
                                                        Tools.none2empty(interface_info.cid),
                                                        Tools.none2empty(interface_info.comment))
                if interface_info.cust_id:
                    description += ' - USID {}'.format(Tools.none2empty(interface_info.cust_id))

                # for filter
                if not self.match_filter(desc=description):
                    continue

                self.log_tuple_list.append(
                    ifc_log_tuple(
                        lastdown=lastdown,
                        lastdown_sort=lastdown.rsplit(":", 1)[0],
                        interface=interface,
                        interface_short=interface_short,
                        type=interface_info.intf_type,
                        interface_name=interface_info.name,
                        telco=interface_info.telco,
                        cid=interface_info.cid,
                        state=interface_info.state,
                        cust_id=interface_info.cust_id,
                        count=count,
                        nocfield=nocfield.nocfield,
                        description=description,
                        abbr=abbr,
                        lastup=lastup,
                        current=current
                    )
                )

    def update_interface_dict(self, mfg,line):
        if settings["mfg_filters"][mfg][self.sub_cmd_name][0] in line:
            m = re.match(settings["mfg_filters"][mfg][self.sub_cmd_name][1],line)
            if m:
                log_time = m.group(1)
                log_router = m.group(2)
                if mfg == 'juniper' or mfg == 'cisco':
                    log_router = m.group(2)
                    log_interface = m.group(3).split(".")[0]
                else: #mfg == 'nokia'
                    log_router_ip = m.group(2)
                    log_router = socket.getfqdn(log_router_ip).replace(".gin.ntt.net","")
                    log_interface = "eth-" + m.group(4)
                router_interface = '_'.join([log_router, log_interface])
                if mfg == 'juniper':
                    isDownLog = True
                elif mfg == 'cisco' and m.group(4) == 'Down':
                    isDownLog = True
                elif mfg == 'nokia' and m.group(3) == 'Down':
                    isDownLog = True
                else:
                    isDownLog = False
                if isDownLog:
                    if router_interface in self.interface_dict:
                        self.interface_dict[router_interface][0] = log_time
                        self.interface_dict[router_interface][1] += 1
                        self.interface_dict[router_interface][3] = 'unk' if mfg == 'juniper' else 'down'
                    else:
                        if mfg == 'juniper':
                            self.interface_dict[router_interface] = [log_time, 1, '-', 'unk']
                        else:
                            self.interface_dict[router_interface] = [log_time, 1, '-', 'down']

                else:
                    if router_interface in self.interface_dict:
                        self.interface_dict[router_interface][2] = log_time
                        self.interface_dict[router_interface][3] = 'up'
                    else:
                        self.interface_dict[router_interface] = ['-', 0, log_time, 'up']
            else:
                pass
        else:
            pass
    @staticmethod
    def check_ifc(router, interface, detail=True):

        query = ConfigToolsDB.get_interface_info(router, interface)
        interface_info = ConfigToolsDB.search(query, listing=False)

        Aend = interface_info.router + " " + interface_info.interface

        if interface_info.intf_type == 'BB':
            if interface_info.telco:
                cids = interface_info.cid.split('/')

                ntt_pattern = r'(u\d\d\d\d)'
                matchOB = re.search(ntt_pattern, interface_info.cid)

                if len(cids) == 1:
                    telco = interface_info.telco
                    cid = cids[0]
                elif matchOB:
                    telco = 'NTT'
                    cid = matchOB.group(1)
                elif ' ' in cids[1]:
                    telco = cids[1].split()[0]
                    cid = cids[1].split()[1]
                else:
                    telco = interface_info.telco
                    cid = interface_info.cid

                if (telco == interface_info.telco) and interface_info.telco:
                    query = ConfigToolsDB.get_abbr_info(telco)
                    abbr_info = ConfigToolsDB.search(query, listing=False)
                    abbr = abbr_info.abbr if abbr_info else interface_info.telco
                else:
                    abbr = None

                bb_query = ConfigToolsDB.get_another_ifc_info(cid)
                bb_info = ConfigToolsDB.search(bb_query, listing=True)

                if len(bb_info) == 2:
                    if bb_info[0].router != interface_info.router:
                        Zend = bb_info[0].router + " " + bb_info[0].interface
                    else:
                        Zend = bb_info[1].router + " " + bb_info[1].interface
                else:
                    Zend = interface_info.name
            else:
                Zend = interface_info.name
                telco = interface_info.telco
                cid = 'local wire'

            if telco is None:
                bb_subject = '1 x %(cid)s - %(Aend)s to %(Zend)s - ' % locals()
            elif abbr:
                bb_subject = '1 x %(abbr)s (%(cid)s) - %(Aend)s to %(Zend)s - ' % locals()
            else:
                bb_subject = '1 x %(telco)s (%(cid)s) - %(Aend)s to %(Zend)s - ' % locals()

            customer_name = interface_info.name.split()[0]
        elif ' ' in interface_info.name:
            customer_name = interface_info.name.split()[1]
        else:
            customer_name = interface_info.name

        ###### Added here that when user run script with ifc -i switch, if circuit has bgp session, display the bgp sum command. ###

        query = ConfigToolsDB.check_peer_from_circuit(router, interface)
        peer_ip_info = ConfigToolsDB.search(query, listing=True)

        #print(peer_ip_info)
        ###### END HERE ########

        session = RouterSession(interface_info.router, interface_info.mfg)
        cmds = []
        cmds.append(RouterCommand.show_cloc(interface_info))
        cmds.append(RouterCommand.ifc_desc(interface_info))
        cmds.append(RouterCommand.show_flap(interface_info))
        if re.search(r"bundle|ae", interface_info.interface) == None:
            cmds.append(RouterCommand.show_power(interface_info))
        cmds.append(RouterCommand.show_error(interface_info))
        cmds.append(RouterCommand.ifc_log(interface_info))

        ####### Also add with above ##########
        if peer_ip_info != None and len(peer_ip_info) > 0:
            for nmdtpl in peer_ip_info:
                # print(nmdtpl)
                if re.search(r":", str(nmdtpl.peering_ip)) != None:
                    cmds.append(RouterCommand.bgp_summary_ipv6(interface_info, nmdtpl.peering_ip))
                    peer_addr_v6 = nmdtpl.peering_ip
                else:
                    cmds.append(RouterCommand.bgp_summary_ipv4(interface_info, nmdtpl.peering_ip))
                    peer_addr_v4 = nmdtpl.peering_ip

        ####### END HERE #########

        if interface_info.intf_type == 'BB':
            subject = bb_subject
        else:
            subject = customer_name + " - " + interface_info.router
            subject += " " + interface_info.interface
            subject += " - "

        msg = ''
        for response in session(cmds):
            lines = response.response
            val_lines = ""
            if response.command == "show router bgp summary family ipv4" or response.command == "show router bgp summary family ipv6":
                if response.command == "show router bgp summary family ipv4":
                    ip_addr = peer_addr_v4
                else:
                    ip_addr = peer_addr_v6
                print("ip_addr",ip_addr)
                for num,val_line in enumerate(response.response.splitlines()):
                    if re.search(ip_addr,val_line) != None:
                        val_lines += response.response.splitlines()[num] 
                        val_lines += response.response.splitlines()[num+1] 
                lines = val_lines

            if detail:
                msg += '------------------------------------------------------------\n'
                msg += '%s : %s' % (interface_info.router, re.sub(' {2,}', ' ', response.command)) + '\n'
                msg += '------------------------------------------------------------\n'
            msg += lines + '\n\n'

        session.close_session()

        return msg, subject

    @staticmethod
    def investigate_interface(target_interface, detail=True):

        return_output = '\n'
        return_output += Tools.colorstring(target_interface, 'green')
        return_output += '\n'

        try:
            router, interface = target_interface.split(' ')
            output_line, subject = IfcDownsort.check_ifc(router, interface, detail)

            flap = True

            for output in output_line.split('\n'):
                if ('down' in output.lower()) and ('link' not in output.lower()) and ('line' not in output.lower()): 
                    return_output += Tools.colorstring(output, 'red') + '\n'
                    flap = False
                elif 'rate 0 bits/sec' in output:
                    return_output += Tools.colorstring(output, 'red') + '\n'
                elif (' 0 bps ' in output) and ('Ingress' not in output):
                    return_output += Tools.colorstring(output, 'red') + '\n'
                else:
                    return_output += output + '\n'

            if flap:
                subject += 'flap'
            else:
                subject += 'down'

            subject = 'Subject : ' + subject + '\n'

            return_output += Tools.colorstring(Tools.stats_url(target_interface), 'blue') + '\n'
            return_output += Tools.colorstring(subject, 'yellow')

        except KeyboardInterrupt:
            print("pressed control-c by user")
            sys.exit()

        except:
            return_output = '\n'
            return_output += Tools.colorstring(target_interface, 'green')
            return_output += '\n'
            return_output += ' ** sorry I conuld not invesitigate this interface **\n'
            return_output += ' ** continue to investigate next interface **'
            return_output = Tools.colorstring(return_output, 'red')

        return return_output


class BgpDownsort(Downsort):
    def __init__(self, args, psr):
        super().__init__(args, psr, sub_cmd_name='bgp')

        if self.current and not self.history:
            self.key_list = ['lastdown', 'interface_short', 'peer_address', 'asn', 'i_p_desc', 'current', 'state', 'count']
            self.name_list = ['lastdown', 'interface', 'peer_address', 'asn', 'description', 'cur', 'db', 'ct']
        else:
            self.key_list = ['lastdown', 'interface_short', 'peer_address', 'asn', 'i_p_desc', 'state', 'count']
            self.name_list = ['lastdown', 'interface', 'peer_address', 'asn', 'description', 'db', 'ct']

        if self.stats:
            self.key_list.append('stats_url')
            self.name_list.append('stats_url')

        if self.investigate:
            self.key_list.insert(0, 'line')
            self.name_list.insert(0, 'line')

        self.ifcs_bp = ifcs_descr_type(
            dict_list=[],
            description='[Peer BGP sessions]',
            key_list=self.key_list,
            name_list=self.name_list
        )
        self.ifcs_bc = ifcs_descr_type(
            dict_list=[],
            description='[Customer BGP sessions]',
            key_list=self.key_list,
            name_list=self.name_list
        )
        self.ifcs_bo = ifcs_descr_type(
            dict_list=[],
            description='[OOB BGP sessions]',
            key_list=self.key_list,
            name_list=self.name_list
        )

        self.ifcs_de = ifcs_descr_type(
            dict_list=[],
            description='[Dedicated AS BGP sessions]',
            key_list=self.key_list,
            name_list=self.name_list
        )

        self.ifcs_sub = ifcs_descr_type(
            dict_list=[],
            description='[Sub AS BGP sessions]',
            key_list=self.key_list,
            name_list=self.name_list
        )

        self.ifcs_bm = ifcs_descr_type(
            dict_list=[],
            description='[BM BGP sessions]',
            key_list=self.key_list,
            name_list=self.name_list
        )

        self.ifcs_other = ifcs_descr_type(
            dict_list=[],
            description='[Other BGP sessions]',
            key_list=self.key_list,
            name_list=self.name_list
        )

        self.ifcs_list = [self.ifcs_bp, self.ifcs_bc, self.ifcs_bo, self.ifcs_de,
                          self.ifcs_sub, self.ifcs_bm, self.ifcs_other]

        self.key = attrgetter('lastdown_sort', 'asn', 'interface', 'peer_address')

    def devide_type(self):
        for item in self.log_tuple_list:
            if item.type == 'BO':
                self.ifcs_bo.dict_list.append(item._asdict())
            elif item.type == 'BP' or item.p_type == 'peer':
                self.ifcs_bp.dict_list.append(item._asdict())
            elif item.p_type == 'customer':
                self.ifcs_bc.dict_list.append(item._asdict())
            elif item.p_type == 'dedicated_asn':
                self.ifcs_de.dict_list.append(item._asdict())
            elif item.p_type == 'subAS':
                self.ifcs_sub.dict_list.append(item._asdict())
            elif item.type == 'BM':
                self.ifcs_bm.dict_list.append(item._asdict())
            else:
                self.ifcs_other.dict_list.append(item._asdict())

    @staticmethod
    def combine_descriptions(p_desc, i_desc):
        i_p_desc = p_desc
        if p_desc is None:
            i_p_desc = i_desc
        elif i_desc is None:
            i_p_desc = p_desc
        elif 'loopback for ibgp peerage' in (i_desc).lower():
            i_p_desc = p_desc
        elif difflib.SequenceMatcher(None, i_desc, p_desc).ratio() < 0.4:
            i_p_desc += ' - ' + i_desc

        return i_p_desc

    def make_log_tuple_list(self):

        for key, value in self.interface_dict.items():
            router = key.split('_')[0]
            peer_address = key.split('_')[1]
            lastdown = value[0]
            count = value[1]
            lastup = value[2]
            current = value[3]

            # for ignore only up log
            if count == 0:
                continue

            # for filter
            if not self.match_filter(router=router):
                continue

            query = ConfigToolsDB.get_peer_info(router, peer_address)
            peerinfo = ConfigToolsDB.search(query, listing=False)

            if peerinfo is not None:
                if peerinfo.state == 'shutdown':
                    continue
                elif peerinfo.state == 'turn-up' and self.ignore:
                    continue

                interface = ' '.join([peerinfo.router, peerinfo.interface])
                interface_short = Tools.make_short_interface_name(interface)
                i_p_desc = BgpDownsort.combine_descriptions(peerinfo.p_desc, peerinfo.name)

                # for filter
                if not self.match_filter(desc=i_p_desc):
                    continue

                self.log_tuple_list.append(
                    bgp_log_tuple(
                        lastdown=lastdown,
                        lastdown_sort=lastdown.rsplit(":", 1)[0],
                        lastup=lastup,
                        current=current,
                        interface=interface,
                        interface_short=interface_short,
                        peer_address=peerinfo.ip_addr,
                        asn=peerinfo.asn,
                        type=peerinfo.intf_type,
                        description=peerinfo.name,
                        telco=peerinfo.telco,
                        state=peerinfo.state,
                        cust_id=peerinfo.cust_id,
                        count=count,
                        p_type=peerinfo.p_type,
                        p_desc=peerinfo.p_desc,
                        p_state=peerinfo.p_state,
                        i_p_desc=i_p_desc
                    )
                )

    def update_interface_dict(self, mfg, line):
        if settings["mfg_filters"][mfg][self.sub_cmd_name][0] in line:
            m = re.match(settings["mfg_filters"][mfg][self.sub_cmd_name][1],line)
            if m:
                log_time = m.group(1)
                if mfg == 'cisco' or mfg == 'juniper':
                    log_router = m.group(2)
                    peer_address = m.group(3)
                else: #mfg == 'nokia'
                    log_router_ip = m.group(2)
                    log_router = socket.getfqdn(log_router_ip).replace(".gin.ntt.net","")
                    peer_address = m.group(3)
                router_peer = '_'.join([log_router, peer_address])

                
                if mfg == 'juniper':
                    if m.group(5) == 'Established':
                        isDownLog = True
                    elif m.group(6) == 'Established':
                        isDownLog = False
                    else:
                        return
                elif mfg == 'cisco':
                    if m.group(4) == 'Down':
                        isDownLog = True
                    else:
                        isDownLog = False
                else: #mfg == 'nokia'
                    if re.search("BGP-MINOR-bgpEstablishedNotification",line) is not None or re.search("BGP-MINOR-tBgpNgEstablished",line):
                        isDownLog = False
                    elif re.search("ESTABLISHED to",line) is not None: #matches like "moved from higher state ESTABLISHED to lower state IDLE"
                        isDownLog = True
                    else: #skip other status change e.g. IDLE -> CONNECT
                        return

                if isDownLog:
                    if router_peer in self.interface_dict:
                        self.interface_dict[router_peer][0] = log_time
                        self.interface_dict[router_peer][1] += 1
                        self.interface_dict[router_peer][3] = 'down'
                    else:
                        self.interface_dict[router_peer] = [log_time, 1, '-', 'down']
                else:
                    if router_peer in self.interface_dict:
                        self.interface_dict[router_peer][2] = log_time
                        self.interface_dict[router_peer][3] = 'up'
                    else:
                        self.interface_dict[router_peer] = ['-', 0, log_time, 'up']

    @staticmethod
    def check_peer(peerinfo, detail):
        
        msg = ''
        if peerinfo is None:
            msg += Tools.colorstring('sorry. could not find on DB......', 'red')
            sys.exit()

        my_key_list = ['asn', 'ip_addr', 'router', 'interface', 'p_desc', 'p_type', 'cust_id', 'state']
        my_name_list = ['asn', 'peer_ip', 'router', 'interface', 'description', 'peertype', 'usid', 'ifc_db_state']

        msg += '\n'
        msg += Tools.table_output([peerinfo._asdict()], my_key_list, my_name_list)
        msg += '\n\n'

        if ('lo' in peerinfo.interface) or ('loopback' in peerinfo.interface):
            msg += Tools.colorstring(
                'sorry. This script does not support loopback....output may not be good...\n',
                'red')

        ifc_cmds = []
        ifc_cmds.append(RouterCommand.show_cloc(peerinfo))
        ifc_cmds.append(RouterCommand.ifc_desc(peerinfo))
        ifc_cmds.append(RouterCommand.show_flap(peerinfo))
        ifc_cmds.append(RouterCommand.ifc_log(peerinfo))

        bgp_cmds = []
        if peerinfo.mfg == 'cisco' or peerinfo.mfg == 'nokia':
            bgp_cmds.append(RouterCommand.bgp_summary_asn4(peerinfo))
            bgp_cmds.append(RouterCommand.bgp_summary_asn6(peerinfo))
        else:
            bgp_cmds.append(RouterCommand.bgp_summary_asn4(peerinfo))
        bgp_cmds.append(RouterCommand.bgp_asn_log(peerinfo))

        session = RouterSession(peerinfo.router, peerinfo.mfg)
        msg += Tools.colorstring('## {} {} : interface check'.format(peerinfo.router, peerinfo.interface), 'green')
        msg += '\n'
        for response in session(ifc_cmds):
            if detail:
                msg += '------------------------------------------------------------\n'
                msg += '%s : %s' % (peerinfo.router, re.sub(' {2,}', ' ', response.command)) + '\n'
                msg += '------------------------------------------------------------\n'
            msg += response.response + '\n\n'

        msg += Tools.colorstring('## {} AS{} : BGP check'.format(peerinfo.router, peerinfo.asn), 'green') + '\n'
        for response in session(bgp_cmds):

            lines = response.response
            val_lines = ""
            if response.command == "show router bgp summary family ipv4" or response.command == "show router bgp summary family ipv6":
                if response.command == "show router bgp summary family ipv4":
                    ip_addr = peerinfo.ip_addr
                else:
                    ip_addr = peerinfo.ip_addr
                for num,val_line in enumerate(response.response.splitlines()):
                    if re.search(ip_addr,val_line) != None:
                        val_lines += response.response.splitlines()[num]
                        val_lines += response.response.splitlines()[num+1]
                lines = val_lines

            if detail:
                msg += '------------------------------------------------------------\n'
                msg += '%s : %s' % (peerinfo.router, re.sub(' {2,}', ' ', response.command)) + '\n'
                msg += '------------------------------------------------------------\n'
            msg += lines + '\n\n'

        session.close_session()

        if 'loopback' in peerinfo.name:
            customer_name = peerinfo.name
        elif ' ' in peerinfo.name:
            customer_name = peerinfo.name.split()[1]
        else:
            customer_name = peerinfo.name

        customer_name_bgp = BgpDownsort.combine_descriptions(peerinfo.p_desc, peerinfo.name)

        subject_ifc = customer_name + " - " + peerinfo.router + " " + peerinfo.interface + " - "

        subject_bgp = customer_name_bgp + " - " + peerinfo.router + " " + peerinfo.interface + " - " + \
                      peerinfo.ip_addr + " - bgp down"

        return msg, subject_ifc, subject_bgp

    @staticmethod
    def investigate_peer(target_interface, detail=True):

        router, interface, peer = target_interface.split(' ')
        query = ConfigToolsDB.get_peer_info(router, peer)
        peerinfo = ConfigToolsDB.search(query, listing=False)

        return_output = "*" * 100 + '\n'
        return_output += Tools.colorstring(target_interface, 'green')
        return_output += '\n'

        try:
            output_line, subject_ifc, subject_bgp = BgpDownsort.check_peer(peerinfo, detail)

            target_interface = ' '.join([router, interface])
            flap = True
            ignore = False
            for output in output_line.split('\n'):
                if '-- IGNORE --' in output:
                    red_ignore = Tools.colorstring("-- IGNORE --", 'red')
                    return_output += output.replace("-- IGNORE --", red_ignore) + '\n'
                    ignore = True
                elif ('down' in output.lower()) and ('link' not in output.lower()) and \
                        ('line' not in output.lower()) and ('neighbor' not in output.lower()) and\
                        ('Hold time down' not in output):
                    return_output += Tools.colorstring(output, 'red') + '\n'
                    flap = False
                elif 'rate 0 bits/sec' in output:
                    return_output += Tools.colorstring(output, 'red') + '\n'
                elif (' 0 bps ' in output) and ('Ingress' not in output):
                    return_output += Tools.colorstring(output, 'red') + '\n'
                elif (peer in output) and ('|' not in output):
                    return_output += Tools.colorstring(output, 'purple') + '\n'
                else:
                    return_output += output + '\n'

            return_output += Tools.colorstring('## Useful info', 'green') + '\n'
            if ignore:
                return_output += Tools.colorstring('No ticket may be needed !! '
                                                  '(Because this circuit is turn-up)', 'red') + '\n\n'
            return_output += Tools.colorstring('Stats : ' + Tools.stats_url(target_interface), 'blue') + '\n'

            subject_ifc = 'Subject (ifc): ' + subject_ifc
            subject_bgp = 'Subject (bgp): ' + subject_bgp
            if flap:
                # subject_ifc += 'flap'
                return_output += Tools.colorstring(subject_bgp, 'yellow') + '\n'
            else:
                subject_ifc += 'down'
                return_output += Tools.colorstring(subject_ifc, 'yellow') + '\n'
                return_output += subject_bgp + '\n'

            usid = peerinfo.cust_id
            if usid is None:
                try:
                    if 'loopback' in peerinfo.name:
                        customer_name = peerinfo.name
                    elif ' ' in peerinfo.name:
                        customer_name = peerinfo.name.split()[1]
                    else:
                        customer_name = peerinfo.name

                    query = ConfigToolsDB.get_peer_usid_info(peerinfo.router, customer_name)
                    peer_usid_list = ConfigToolsDB.search(query, listing=True)

                    for peer_usid in peer_usid_list:
                        if peer_usid.cust_id is not None:
                            usid = peer_usid.cust_id
                            return_output += 'USID is None\n'
                            return_output += 'related USID : {} ({} {} / {}) \n'.format(usid, peer_usid.router,
                                                                                       peer_usid.interface,
                                                                                       peer_usid.name)
                            return_output += 'related Gnome : ' + Tools.gnome_url(usid) + '\n'
                            break
                except:
                    pass
            else:
                return_output += 'USID : {}\n'.format(usid)
                return_output += 'Gnome : ' + Tools.gnome_url(usid) + '\n'

        except KeyboardInterrupt:
            print("pressed control-c by user")
            sys.exit()

        except:
            return_output = '\n'
            return_output += Tools.colorstring(target_interface, 'green')
            return_output += '\n'
            return_output += ' ** sorry I conuld not invesitigate this interface **\n'
            return_output += ' ** continue to investigate next interface **'
            return_output = Tools.colorstring(return_output, 'red')

        return return_output


class VcDownsort(Downsort):
    def __init__(self, args, psr):
        super().__init__(args, psr, sub_cmd_name='vc')

        if self.current and not self.history:
            self.key_list = ['lastdown', 'vcid', 'interface_short', 'another_side_short', 'description', 'usid',
                             'current', 'state', 'count']
            self.name_list = ['lastdown', 'vcid', 'interface', 'another_side', 'description', 'usid',
                              'cur', 'db', 'ct']
        else:
            self.key_list = ['lastdown', 'vcid', 'interface_short', 'another_side_short', 'description', 'usid',
                             'state', 'count']
            self.name_list = ['lastdown', 'vcid', 'interface', 'another_side', 'description', 'usid',
                              'db', 'ct']

        if self.stats:
            self.key_list.append('stats_url')
            self.name_list.append('stats_url')

        if self.investigate:
            self.key_list.insert(0, 'line')
            self.name_list.insert(0, 'line')

        self.ifcs_vc = ifcs_descr_type(
            dict_list=[],
            description='[VC Circuits]',
            key_list=self.key_list,
            name_list=self.name_list
        )

        self.ifcs_list = [self.ifcs_vc]
        self.key = attrgetter('lastdown_sort', 'vcid_int')

    def devide_type(self):
        for item in self.log_tuple_list:
            self.ifcs_vc.dict_list.append(item._asdict())

    def make_log_tuple_list(self):
        for key, value in self.interface_dict.items():
            router = key.split('_')[0]
            vcid = key.split('_')[1]

            lastdown = value[0]
            count = value[1]
            neighbor = value[2]
            lastup = value[3]
            current = value[4]

            # for ignore only up log
            if count == 0:
                continue

            # for filter
            if not self.match_filter(router=router):
                continue

            query = ConfigToolsDB.get_vc_info(vcid)
            vlink = ConfigToolsDB.search(query, listing=True)

            if vlink:
                if len(vlink) == 2:
                    if vlink[0].router == router:
                        another_side = vlink[1].router + ' ' + vlink[1].ifc_name
                        peerinfo = vlink[0]
                    elif vlink[1].router == router:
                        another_side = vlink[0].router + ' ' + vlink[0].ifc_name
                        peerinfo = vlink[1]
                    else:
                        continue

                    if peerinfo.state == 'shutdown':
                        continue
                    elif peerinfo.state == 'turn-up' and self.ignore:
                        continue

                    interface = ' '.join([peerinfo.router, peerinfo.ifc_name])
                    interface_short = Tools.make_short_interface_name(interface)
                    another_side_short = Tools.make_short_interface_name(another_side)

                    # for filter
                    if not self.match_filter(desc=peerinfo.name):
                        continue

                    self.log_tuple_list.append(
                        vc_log_tuple(
                            lastdown=lastdown,
                            lastdown_sort=lastdown.rsplit(":", 1)[0],
                            vcid='VC-' + str(peerinfo.id),
                            interface=interface,
                            interface_short=interface_short,
                            another_side=another_side,
                            another_side_short=another_side_short,
                            description=peerinfo.name,
                            usid=peerinfo.usid,
                            state=peerinfo.state,
                            count=count,
                            vcid_int=peerinfo.id,
                            lastup=lastup,
                            current=current,
                            neighbor=neighbor

                        )
                    )
                else:
                    continue
            else:
                continue

    def update_interface_dict(self, mfg, line):
        if settings["mfg_filters"][mfg][self.sub_cmd_name][0] in line:
            m = re.match(settings["mfg_filters"][mfg][self.sub_cmd_name][1],line)

            if m:
                log_time = m.group(1)
                if mfg == 'juniper' or mfg == 'cisco':
                    log_router = m.group(2)
                    log_neighbor = m.group(3)
                    log_vcid = m.group(4)
                else: #mfg == 'nokia'
                    log_router_ip = m.group(2)
                    log_router = socket.getfqdn(log_router_ip).replace(".gin.ntt.net","")
                    log_neighbor = "-"
                    log_vcid = m.group(3)
                router_vcid = '_'.join([log_router, log_vcid])

                if mfg == 'juniper':
                    isDownLog = True
                elif mfg == 'cisco' and m.group(5) == 'Down':
                    isDownLog = True
                elif mfg == 'nokia' and m.group(4) == 'down':
                    isDownLog = True
                else:
                    isDownLog = False

                if isDownLog:
                    if router_vcid in self.interface_dict:
                        self.interface_dict[router_vcid][0] = log_time
                        self.interface_dict[router_vcid][1] += 1
                        self.interface_dict[router_vcid][4] = 'unk' if mfg == 'juniper' else 'down'
                    else:
                        if mfg == 'juniper':
                            self.interface_dict[router_vcid] = [log_time, 1, log_neighbor, '-', 'unk']
                        else:
                            self.interface_dict[router_vcid] = [log_time, 1, log_neighbor, '-', 'down']
                else:
                    if router_vcid in self.interface_dict:
                        self.interface_dict[router_vcid][3] = log_time
                        self.interface_dict[router_vcid][4] = 'up'
                    else:
                        self.interface_dict[router_vcid] = ['-', 0, log_neighbor, log_time, 'up']
            else:
                pass
        else:
            pass

    @staticmethod
    def check_ifc(router, interface, vcid_int, neighbor, detail=True):

        query = ConfigToolsDB.get_interface_info(router, interface)
        peerinfo = ConfigToolsDB.search(query, listing=False)

        vcid = str(vcid_int)
        query = ConfigToolsDB.get_vc_info(vcid)
        vlink = ConfigToolsDB.search(query, listing=True)

        if len(vlink) == 2:
            if vlink[0].router == router:
                another_side = vlink[1].router + ' ' + vlink[1].ifc_name
            else:
                another_side = vlink[0].router + ' ' + vlink[0].ifc_name
        else:
            sys.exit()

        session = RouterSession(peerinfo.router, peerinfo.mfg)

        cmds = []
        cmds.append(RouterCommand.show_cloc(peerinfo))
        cmds.append(RouterCommand.ifc_desc(peerinfo))
        cmds.append(RouterCommand.show_flap(peerinfo))
        cmds.append(RouterCommand.show_power(peerinfo))
        cmds.append(RouterCommand.show_error(peerinfo))
        cmds.append(RouterCommand.ifc_log(peerinfo))
        cmds.append(RouterCommand.show_l2vpn(peerinfo, vcid))

        if peerinfo.mfg == 'cisco':
            cmds.append(RouterCommand.show_l2vpn_mtu(peerinfo, vcid))
            cmds.append(RouterCommand.show_l2vpn_flap(peerinfo, vcid))

        cmds.append(RouterCommand.l2vpn_log(peerinfo, vcid))
        if peerinfo.mfg == 'cisco' or peerinfo.mfg == 'juniper':
            cmds.append(RouterCommand.l2vpn_ping(peerinfo, vcid, neighbor))

        Aend = router + " " + interface
        subject = " - ".join([peerinfo.name, 'VC-{}'.format(vcid), Aend + ' to ' + another_side, 'VLINK '])

        msg = ''
        for response in session(cmds):
            if "High Alarm" in response.response: #To column fix for nokia
                #res = re.sub("Value","                            Value",response.response)
                res = " " * 31 + response.response
            else: 
                res = response.response
            if detail:
                msg += '------------------------------------------------------------\n'
                msg += '%s : %s' % (peerinfo.router, re.sub(' {2,}', ' ', response.command)) + '\n'
                msg += '------------------------------------------------------------\n'
            msg += res + '\n\n'
     
        session.close_session()

        return msg, subject

    @staticmethod
    def investigate_interface(target_vc_interface, detail=True):

        router, interface, vcid_int, neighbor = target_vc_interface.split(' ')
        target_interface = ' '.join([router, interface])

        return_output = '\n'
        return_output += Tools.colorstring(target_interface, 'green')
        return_output += '\n'
        try:
            output_line, subject = VcDownsort.check_ifc(router, interface, vcid_int, neighbor, detail)

            flap = True

            for output in output_line.split('\n'):
                if (('down' in output.lower()) or ('DN' in output)) \
                        and (('link' not in output.lower())
                             and ('line' not in output.lower())
                             and ('Legend' not in output)
                             and ('L2-L2VPN_PW-3-UPDOWN' not in output)
                             and ('Last time' not in output)
                             and ('RPD_LAYER2_VC_DOWN' not in output)
                             and (' -- ' not in output)
                             and ('Hold time down' not in output)
                             ):
                    return_output += Tools.colorstring(output, 'red') + '\n'
                    flap = False
                elif 'rate 0 bits/sec' in output:
                    return_output += Tools.colorstring(output, 'red') + '\n'
                elif (' 0 bps ' in output) and ('Ingress' not in output):
                    return_output += Tools.colorstring(output, 'red') + '\n'
                else:
                    return_output += output + '\n'

            if flap:
                subject += 'flap'
            else:
                subject += 'down'

            subject = 'Subject : ' + subject + '\n'

            return_output += Tools.colorstring(Tools.stats_url(target_interface), 'blue') + '\n'
            return_output += Tools.colorstring(subject, 'yellow')

        except KeyboardInterrupt:
            print("pressed control-c by user")
            sys.exit()

        except:
            return_output = '\n'
            return_output += Tools.colorstring(target_interface, 'green')
            return_output += '\n'
            return_output += ' ** sorry I conuld not invesitigate this interface **\n'
            return_output += ' ** continue to investigate next interface **'
            return_output = Tools.colorstring(return_output, 'red')

        return return_output


#################################################################################################################
def command_downsort(downsort):
    if downsort.history:
        start_time,end_time,sub_cmd_name,msg = downsort.gather_history_logs()
    elif downsort.timerange:
        start_time,end_time,sub_cmd_name,msg = downsort.gather_timerange_logs()
    else:
        start_time,end_time,sub_cmd_name,msg = downsort.gather_latest_logs()
    column_explation = settings["column_explations"][sub_cmd_name]
    print(Tools.colorstring(msg, 'green'))
    print(Tools.colorstring(column_explation, 'yellow'))
    downsort.log_parse(start_time=start_time,end_time=end_time)

    downsort.make_log_tuple_list()
    downsort.sort()
    downsort.devide_type()
    if downsort.stats:
        downsort.add_stats()
    if downsort.investigate:
        downsort.add_investigate_line()
    downsort.print_devided_table()

    if downsort.investigate:
        downsort.start_investigation()


def command_ifc(args, psr):
    command_downsort(IfcDownsort(args, psr))


def command_bgp(args, psr):
    command_downsort(BgpDownsort(args, psr))


def command_vc(args, psr):
    command_downsort(VcDownsort(args, psr))


def main():
    def make_sub_command(psr, sub_cmd_name):

        psr.add_argument('-m', '--minute', default=15, type=int, help='must be 1440 or less')
        psr.add_argument('--hour', type=int, help='must be 24 or less')
        psr.add_argument('--history', type=str, help='ex) --history 20180202')
        psr.add_argument('--timerange', type=str, help='ex) --timerange 201802022100:201802022300 '
                                                       '(yyyymmddHHMM:yyyymmddHHMM)'
                                                       'must be in 24 hours or less')

        psr.add_argument('-s', '--stats', action='store_true', help='display stats info')

        psr.add_argument('-i', '--investigate', action='store_true',
                         help='display result of show commands, max interfaces counts are 20 or less)')
        psr.add_argument('-d', '--detail', action='store_true', help='display commands info. use with -i')

        psr.add_argument('-p', '--parallel', action='store_true',
                                help='parallel ssh function. use with -i. There may be some bugs..\n'
                                     'updating related packages may help this........\n'
                                     + Tools.colorstring('pip3 install --user -U netmiko cryptography', 'red'))

        psr.add_argument('-f', '--filter', type=str, help='filter devices by router name or pop '
                                                          '(ex: londen01 or \'londen01|londen12\')')
        psr.add_argument('-c', '--country', type=str, help='filter devices by country (ex: us or \'us|jp\')')
        psr.add_argument('--desc', type=str, help='filter devices by description '
                                                  '(ex: akamai or \'akamai|facebook\')')

        psr.add_argument('--current', action='store_true', default=False, help='display cunnret status, '
                                                                               'just for your reference')

        psr.add_argument('--terse', action='store_true', default=False,
                         help='you can get just terse info and choose more interfaces')

        psr.add_argument('-a', '--anoc', action='store_true',
                         help='for anoc. same as -c \'{}\''.format(Tools.get_anoc_coutry_fiter()))

        psr.add_argument('-r', '--reverse', action='store_true', default=False, help='for reverse sort')
        psr.add_argument('--ignore', action='store_true', default=False, help='ignore turn-up circuits')

        psr.add_argument('-v', '--verbose', action='store_true',default=False, help='show detailed information')

    Tools.logging(status=True, message=' '.join(sys.argv) + ' / start', logfile=DOWNSORT_LOGFILE)

    # main command
    parser = argparse.ArgumentParser(description='downsort script for analyzing ifc, bgp and vc logs on eng0')
    subparsers = parser.add_subparsers()

    # ifc_downsort command
    parser_ifc = subparsers.add_parser('ifc', help='see `ifc -h`')
    make_sub_command(parser_ifc, 'ifc')
    parser_ifc.set_defaults(fn=command_ifc)

    # bgp_downsort command
    parser_bgp = subparsers.add_parser('bgp', help='see `bgp -h`')
    make_sub_command(parser_bgp, 'bgp')
    parser_bgp.set_defaults(fn=command_bgp)

    # vc_downsort command
    parser_vc = subparsers.add_parser('vc', help='see `vc -h`')
    make_sub_command(parser_vc, 'vc')
    parser_vc.set_defaults(fn=command_vc)

    args = parser.parse_args()


    if hasattr(args, 'fn'):
        if args.fn == command_ifc:
            args.fn(args, parser_ifc)
        elif args.fn == command_bgp:
            args.fn(args, parser_bgp)
        elif args.fn == command_vc:
            args.fn(args, parser_vc)
    else:
        print(parser.format_help())

    Tools.logging(status=True, message=' '.join(sys.argv) + ' / end', logfile=DOWNSORT_LOGFILE)

if __name__ == '__main__':
    main()
