#!/opt/gums/bin/python3
# -*- encoding: utf-8 -*-
# -*- coding: utf-8 -*-

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, date
from functools import reduce
from netaddr.ip import IPAddress

import argparse
import collections
import difflib
import os
import psycopg2.extras
import re
import sys
import io
import stat
import gzip
import time
import socket
import math

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

import json
import logging
import logging.handlers

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

# Log outout
LOG_DIR = '/tftpboot/kikeda/log/'
DOWNSORT_LOGFILE = 'downsort.log'
NOCCHECK_LOGFILE = 'noc_check.log'
NOCCHECK_DOWN_LOGFILE = 'noc_check_down.log'

# RouterLOGFILE
LOGFILE_JUNIPER_TODAY = '/var/log/local5/debug'
LOGFILE_CISCO_TODAY = '/var/log/local7/debug'
LOGFILE_NOKIA_TODAY = '/var/log/local6/debug'

# IFC
FILTER_JUNIPER_IFC = 'SNMP_TRAP_LINK_DOWN'
FILTER_CISCO_IFC = 'PKT_INFRA-LINK-3-UPDOWN'
FILTER_NOKIA_IFC = 'SNMP-WARNING-link'

# BGP
FILTER_JUNIPER_BGP = 'RPD_BGP_NEIGHBOR_STATE_CHANGED'
FILTER_CISCO_BGP = 'ROUTING-BGP-5-ADJCHANGE'
FILTER_NOKIA_BGP = 'Base BGP'

# VC
FILTER_JUNIPER_VC = 'RPD_LAYER2_VC_DOWN'
FILTER_CISCO_VC = 'L2-L2VPN_PW-3-UPDOWN'
FILTER_NOKIA_VC = 'SVCMGR-MINOR-sdpBindStatusChanged'

# slack
SLACK_END_POINT_DEV = 'https://hooks.slack.com/services/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'
SLACK_END_POINT = SLACK_END_POINT_DEV

# SLACK_END_POINT_NOC = 'https://hooks.slack.com/services/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'
# SLACK_END_POINT = SLACK_END_POINT_NOC

# ignore list for noc_check.py down
donw_ignore_list = [
    'IGNORE',
    'OUTAGE',
    'MAINT',
    'FAILURE',
    # # 201804272330 HACK for [VNOC-1-1697258725] r06.asbnva02.us.bb LC0/11 failure
    # 'r06.asbnva02.us.bb ce-0-11'
]

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

    def call_rstrip(self, commands, delay_factor=2):
        for cmd in commands:
            response = self.session.send_command(
                cmd.command,
                strip_prompt=True, strip_command=True, delay_factor=delay_factor)

            response = re.sub('\{master\}', '', response).rstrip()
            response = re.sub('---\(more (\d+)%\)---', '', response).rstrip()
            response = re.sub('\[\]','',response).rstrip()

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
    def graph_search_stats_url(interface_list):
        stats_url = 'https://stats.gin.ntt.net/stats/ip-eng/graph_search_stats.cgi?'

        tday, yday = datetime.now(), datetime.now() - timedelta(days=1)

        peer = ''
        for i, interface in enumerate(interface_list):
            if i == 0:
                peer = interface.replace(' ', '+') + '+'
            else:
                peer += '|' + interface.replace(' ', '+') + '+'

        params = [
            'dates=%s:%s' % (yday.strftime('%Y.%m.%d'), tday.strftime('%Y.%m.%d')),
            'peer=%s' % peer,
            'bps=bps',
            'do_graph=Filter%2FGraph',
            'do_all_separate=1',
        ]

        stats_url += '&'.join(params)

        return stats_url

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

    @staticmethod
    def send_slack_notification(url, username, attachments):
        requests.post(url, data=json.dumps({
            "username": username,
            "attachments": attachments
        }))

    @staticmethod
    def get_z_interface(router, interface):
        query = ConfigToolsDB.get_z_ifc_id(router, interface)
        a_info = ConfigToolsDB.search(query, listing=False)

        z_info = None
        if a_info:
            if a_info.z_ifc_id:
                query = ConfigToolsDB.get_interface_from_z_ifc_id(a_info.z_ifc_id)
                z_info = ConfigToolsDB.search(query, listing=False)
        return z_info


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
    def get_marked_interfaces_from_ticket(ticket):

        selector = 'd.device_name, i.ifc_name, i.noc_field, i.cid, cis.ifc_state'
        table = 'ct_ifcs i'

        join1 = 'JOIN ct_devices d ON d.device_id = i.device_id'
        join2 = 'JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id '
        join3 = 'LEFT JOIN ct_vendor v ON v.vendor_id = i.telco_id'
        join = '%(join1)s %(join2)s %(join3)s' % locals()

        filter = 'i.noc_field ~* \'%(ticket)s\'' % locals()

        sql = 'select %(selector)s from %(table)s %(join)s where %(filter)s order by d.device_name,i.ifc_name' % locals()

        return sql, collections.namedtuple('ticket',
                                           ['router', 'ifc_name', 'noc_field', 'cid', 'state']
                                           )

    @staticmethod
    def get_outage_interfaces_from_ticket():

        selector = 'd.device_name, i.ifc_name, i.noc_field, i.cid, cis.ifc_state'
        table = 'ct_ifcs i'

        join1 = 'JOIN ct_devices d ON d.device_id = i.device_id'
        join2 = 'JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id '
        join3 = 'LEFT JOIN ct_vendor v ON v.vendor_id = i.telco_id'
        join = '%(join1)s %(join2)s %(join3)s' % locals()

        filter = 'cis.ifc_state = \'outage\' or cis.ifc_state = \'failure\' ' % locals()

        sql = 'select %(selector)s from %(table)s %(join)s where %(filter)s ' \
              'order by d.device_name,i.ifc_name' % locals()

        return sql, collections.namedtuple('ticket',
                                           ['router', 'ifc_name', 'noc_field', 'cid', 'state']
                                           )

    @staticmethod
    def get_maint_interfaces_from_ticket():

        selector = 'd.device_name, i.ifc_name, i.noc_field, i.cid, cis.ifc_state'
        table = 'ct_ifcs i'

        join1 = 'JOIN ct_devices d ON d.device_id = i.device_id'
        join2 = 'JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id '
        join3 = 'LEFT JOIN ct_vendor v ON v.vendor_id = i.telco_id'
        join = '%(join1)s %(join2)s %(join3)s' % locals()

        filter = 'cis.ifc_state = \'maint\'' % locals()

        sql = 'select %(selector)s from %(table)s %(join)s where %(filter)s ' \
              'order by d.device_name,i.ifc_name' % locals()

        return sql, collections.namedtuple('ticket',
                                           ['router', 'ifc_name', 'noc_field', 'cid', 'state']
                                           )

    @staticmethod
    def get_maint_routers():
        sql = 'select routers.name, routers.mfg, routers.platform, routers.os_name, routers.os_rev, ' \
              'routers.state, ct_devices.noc_field ' \
              'from routers, ct_devices ' \
              'where routers.name = ct_devices.device_name ' \
              'and state != \'up\' and state != \'down\' and state != \'shutdown\''

        return sql, collections.namedtuple('ticket',
                                           ['router', 'mfg', 'platform', 'os_name', 'os_rev', 'state', 'noc_field']
                                           )

    @staticmethod
    def get_ifc_info_from_cids(cid):
        selector = 'router, ifc_name, name, cid, state'
        table = 'interfaces'
        # filter = 'cid ~* \'%(cid)s\'' % locals()
        filter = 'cid ~* \'%(cid)s\' or ' \
                 'name ~* \'%(cid)s\' or ' \
                 'telco ~* \'%(cid)s\' or ' \
		 'cust_id ~* \'%(cid)s\' or ' \
                 'comment ~*\'%(cid)s\'' %locals()
#                 'comment ~* \'%(cid)s\' or ' \
#                 'cust_id ~* \'%(cid)s\'' % locals()

        sql = 'select %(selector)s from %(table)s where %(filter)s order by router,ifc_name' % locals()

        return sql, collections.namedtuple('circuit',
                                           ['router', 'ifc_name', 'name', 'cid', 'state']
                                           )

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

    ### This is added based on improvement to check lacp by wataru
    @staticmethod
    def get_associated_interface_info(router, interface):
        selector= "device_name, ctif.ifc_name, ifc_descr_type, ifc_descr, abbr, cid, ifc_comment, cust_id, cie_field, ctif.noc_field, z_ifc_id"
        table= "ct_ifcs ctif"
        join1= "JOIN ct_devices ON ct_devices.device_id = ctif.device_id"
        join2= "JOIN ct_ifcs_descr_type descr ON descr.ifc_descr_type_id = ctif.ifc_descr_type_id"
        join3= "LEFT JOIN ct_vendor ven ON ven.vendor_id = ctif.telco_id"
        join= "{} {} {}".format(join1, join2, join3)
        filter= "ifc_id IN (SELECT ifc_id FROM ct_proto_proto_agg WHERE agg_ifc_id = " \
                "(SELECT ifc_id FROM ct_ifcs WHERE ifc_name = \'%(interface)s\' AND device_id = " \
                "(SELECT device_id FROM ct_devices WHERE device_name = \'%(router)s\')))" % locals()

        sql= "SELECT %(selector)s FROM %(table)s %(join)s WHERE %(filter)s ORDER BY device_name, ctif.ifc_name" % locals()

        return sql, collections.namedtuple("associated_interface_info",
                                           ["router", "interface", "intf_type", "name", "telco", "cid", "comment", "cust_id", "cie_field", "noc_field", "z_ifc_id" ])

    ### This is added based on improvement to check lacp by wataru
    @staticmethod
    def get_associated_interface_info_zend(router, interface, zend):
        selector= "device_name, ctif.ifc_name, ifc_descr_type, ifc_descr, abbr, cid, ifc_comment, cust_id, cie_field, ctif.noc_field, z_ifc_id"
        table= "ct_ifcs ctif"
        join1= "JOIN ct_devices ON ct_devices.device_id = ctif.device_id"
        join2= "JOIN ct_ifcs_descr_type descr ON descr.ifc_descr_type_id = ctif.ifc_descr_type_id"
        join3= "LEFT JOIN ct_vendor ven ON ven.vendor_id = ctif.telco_id"
        join= "{} {} {}".format(join1, join2, join3)
        filter= "ifc_id IN ({})".format(zend)

        sql= "SELECT %(selector)s FROM %(table)s %(join)s WHERE %(filter)s ORDER BY device_name, ctif.ifc_name" % locals()

        return sql, collections.namedtuple("associated_interface_info_zend",
                                           ["router", "interface", "intf_type", "name", "telco", "cid", "comment", "cust_id", "cie_field", "noc_field", "z_ifc_id" ])
 
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
    def get_loopback_addr(router):
        selector = 'name, loopback'
        table = 'routers'
        filter = 'name = \'%(router)s\'' % locals()

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()
        return sql, collections.namedtuple(
            'router',
            ['name', 'loopback']
        )


    @staticmethod
    def get_peer_info(router=None, ipaddr=None):
        selector = 'peers.router, peers.multihop_src, peers.ip_addr, peers.asn, peers.description, peers.peertype, ' \
                   'peers.state, routers.mfg, routers.os_rev, ' \
                   'interfaces.intf_type, interfaces.cust_id, interfaces.name, interfaces.telco, interfaces.state'
        table = 'peers, routers, interfaces'

        if router:
            filter = 'peers.router = routers.name and peers.router = \'%(router)s\' and peers.ip_addr = \'%(ipaddr)s\' ' \
                     'and peers.router = interfaces.router and peers.multihop_src = interfaces.ifc_name' % locals()
        else:
            filter = 'peers.router = routers.name and peers.ip_addr = \'%(ipaddr)s\' ' \
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
    def get_slot_interfaces(router, slot):
        selector = 'interfaces.router, interfaces.ifc_name, routers.mfg, routers.os_rev, interfaces.intf_type, ' \
                   'interfaces.name, interfaces.telco, interfaces.cid, interfaces.comment, interfaces.cust_id, ' \
                   'interfaces.state'
        table = 'routers, interfaces'

        filter = 'interfaces.router = routers.name and interfaces.intf_type != \'UU\' and ' \
                 'interfaces.state != \'turn-up\' and interfaces.router = \'{}\' and ' \
                 'interfaces.ifc_name ilike \'%-{}/%\''.format(router, slot)

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()

        return sql, collections.namedtuple(
            'peer',
            ['router', 'interface', 'mfg', 'os_rev', 'type', 'name', 'telco', 'cid', 'comment', 'usid', 'state']
        )

    @staticmethod
    def get_all_routers():
        selector = 'name, state, mfg, platform, os_name, os_rev'
        table = 'routers'
        filter = 'name ~* \'^(a|r).*bb$\''

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()

        return sql, collections.namedtuple(
            'router',
            ['name', 'state', 'mfg', 'platform', 'os_name', 'os_rev']
        )

    @staticmethod
    def get_z_ifc_id(router, interface):
        selector = 'ct_devices.device_name, ct_ifcs.ifc_name, ct_ifcs.ifc_id, ct_ifcs.z_ifc_id'
        table = 'ct_ifcs, ct_devices'
        filter = 'ct_ifcs.device_id = ct_devices.device_id and ct_devices.device_name = \'{}\' and ' \
                 'ct_ifcs.ifc_name = \'{}\''.format(router, interface)

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()

        return sql, collections.namedtuple(
            'interface',
            ['router', 'interface', 'ifc_id', 'z_ifc_id']
        )

    @staticmethod
    def get_interface_from_z_ifc_id(z_ifc_id):
        selector = 'ct_devices.device_name, ct_ifcs.ifc_name, ct_ifcs.ifc_id, ct_ifcs.z_ifc_id'
        table = 'ct_ifcs, ct_devices'
        filter = 'ct_ifcs.device_id = ct_devices.device_id and ct_ifcs.ifc_id = \'{}\''.format(z_ifc_id)

        sql = 'select %(selector)s from %(table)s where %(filter)s' % locals()

        return sql, collections.namedtuple(
            'interface',
            ['router', 'interface', 'ifc_id', 'z_ifc_id']
        )


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

    ########### Added this for improvement to check logical-physical interface check. 8/Feb/2020 by wataru
    @staticmethod
    def show_lacp(peer):
        interface= peer.interface
        if peer.mfg == "cisco":
            cmd= "show lacp %(interface)s" % locals()
        elif peer.mfg == "juniper":
            cmd= "show lacp interfaces  %(interface)s" % locals()
        else:
            interface = re.sub("lag","",interface) # "lag2" -> "2"
            cmd= "show lag %(interface)s" % locals() 

        return router_command(key="show_lacp", command= cmd)


    @staticmethod
    def clear_counter(peer):
        interface = peer.interface
        if peer.mfg == "cisco":
            cmd = 'clear counters %(interface)s' % locals()
        elif peer.mfg == "juniper":
            cmd = 'clear interfaces statistics %(interface)s' % locals()
        else:
            interface = re.sub("eth-","",interface)
            interface = re.sub(":\d+","",interface)
            if re.match(r"(.*c\d+)",interface) is not None: ### for optical commands "1/1/c27/3" need to be changed to "1/1/c27"
                interface = re.match(r"(.*c\d+)",interface).group(1)
            cmd = 'clear port %(interface)s statistics'  % locals()
            

        return router_command(key='clear_counter', command=cmd)

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
            cmd = 'show port %(interface)s description' % locals()

        return router_command(key='ifc_desc', command=cmd)
    def ifc_status(peer):
        interface = peer.interface
        interface = re.sub("eth-","",interface)
        interface = re.sub(":\d+","",interface)
        if re.match(r"(.*c\d+)",interface) is not None: ### for optical commands "1/1/c27/3" need to be changed to "1/1/c27"
            interface = re.match(r"(.*c\d+)",interface).group(1)
        cmd = "show port %(interface)s | match 'Admin State|Oper State'" % locals()
        return router_command(key='ifc_status', command=cmd)


    @staticmethod
    def show_flap(peer):
        interface = peer.interface
        if peer.mfg == "cisco":
            cmd = 'show interfaces %(interface)s | include "flap|rate"' % locals()
        elif peer.mfg == "juniper":
            cmd = 'show interfaces %(interface)s | match "flap|rate" | except "FEC"' % locals()
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
        else:
            interface = re.sub("eth-","",interface)
            interface = re.sub(":\d+","",interface)
            if re.match(r"(.*c\d+)",interface) is not None:
                interface = re.match(r"(.*c\d+)",interface).group(1)
            cmd = "show port %(interface)s optical | match 'Tx Output|Rx Optical|Value'" % locals()

        return router_command(key='show_power', command=cmd)

    @staticmethod
    def show_error(peer):
        interface = peer.interface.split('.')[0]
        if peer.mfg == "cisco":
            cmd = 'show interfaces %(interface)s | include "error|runt|clearing"' % locals()
        elif peer.mfg == "juniper":
            #cmd = 'show interfaces %(interface)s extensive | match "FIFO errors:"' % locals()
            cmd = 'show interfaces %(interface)s extensive | match "cleared|rror|FIFO|Code" | except PDU' % locals() 
        else:
            interface = re.sub("eth-","",interface)
            interface = re.sub(":\d+","",interface)
            cmd = 'show port %(interface)s | match Errors' % locals()
#### Changed due to addition for lacp check

        return router_command(key='show_error', command=cmd)

    @staticmethod
    def ifc_log(peer):
        interface = peer.interface
        if peer.mfg == "cisco":
            if peer.os_rev == '5.3.4':
                cmd = 'show log | utility fgrep -i %(interface)s | utility tail count 15' % locals()
            else:
                cmd = 'show log | utility fgrep %(interface)s -i | utility tail count 15' % locals()
        elif peer.mfg == "juniper":
            cmd = 'show log messages | match %(interface)s | last 15 | no-more | except cast | match "SNMP_TRAP"' % locals()
        else:
            interface = re.sub("eth-","",interface)
            interface = re.sub(":\d+","",interface)
            cmd = 'show log log-id 101 message %(interface)s count 15' % locals()
            

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

    @staticmethod
    def bgp_asn_log(peer, last=10):
        asn = peer.asn
        if peer.mfg == "cisco":
            cmd = 'show logging | include \" %(asn)s\\\\)\" | utility tail -n %(last)s' % locals()
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
        else:
            interface = peer.interface
            if '.' not in interface:
                interface += '.0'
            cmd = 'ping mpls l2circuit interface %(interface)s reply-mode application-level-control-channel ' % locals()
            cmd += 'detail size 4000'

        return router_command(key='l2vpn_log', command=cmd)

    @staticmethod
    def show_lastflap(peer):
        # interface = peer.interface.split('.')[0]
        interface = peer.interface
        if peer.mfg == "cisco":
            cmd = 'show interfaces %(interface)s | include "Description|line protocol|Last link flapped"' % locals()
        elif mfg == "juniper":
            cmd = 'show interfaces %(interface)s | match "Description|Physical interface|Last flapped"' % locals()
        else:
            interface = re.sub("eth-","",interface)
            interface = re.sub(":\d+","",interface)
            "show port %(interface)s | match 'Description|Interface|Last State Change'" % locals()
        return router_command(key='show_lastflap', command=cmd)

    @staticmethod
    def show_ifc_lastflap(ifc, mfg):
        # interface = ifc.split('.')[0]
        interface = ifc
        if mfg == "cisco":
            cmd = 'show interfaces %(interface)s | include "Description|line protocol|Last link flapped"' % locals()
        elif mfg == "juniper":
            cmd = 'show interfaces %(interface)s | match "Description|Physical interface|Last flapped"' % locals()
        else:
            interface = re.sub("eth-","",interface)
            interface = re.sub(":\d+","",interface)
            cmd = "show port %(interface)s | match 'Description|Interface|Oper State|Last State Change'" % locals()

        return router_command(key='show_lastflap', command=cmd)

    @staticmethod
    def show_ifc_lastflap_rate(ifc, mfg):
        # interface = ifc.split('.')[0]
        interface = ifc
        if mfg == "cisco":
            cmd = 'show interfaces %(interface)s | include "Description|line protocol|Last link flapped|rate"' % locals()
        elif mfg == "juniper":
            cmd = 'show interfaces %(interface)s | match "Description|Physical interface|Last flapped|rate"' \
                  ' | except Ingress' % locals()
        else:
            interface = re.sub("eth-","",interface)
            interface = re.sub(":\d+","",interface)
            "show port %(interface)s | match 'Description|Interface|Last State Change'" % locals()

        return router_command(key='show_lastflap', command=cmd)

    @staticmethod
    def show_ifc_lastflap_error(ifc, mfg):
        interface = ifc.split('.')[0]
        if mfg == "cisco":
            cmd = 'show interfaces %(interface)s | include "counter|iants|rror"' % locals()
        elif mfg == "juniper":
            cmd = 'show interfaces %(interface)s extensive | match "rror"' % locals()
        else:
            interface = re.sub("eth-","",interface)
            interface = re.sub(":\d+","",interface)
            cmd = 'show port %(interface)s detail | match Error' % locals()
        return router_command(key='show_ifc_lastflap_error', command=cmd)

    @staticmethod
    def show_ifc_lastflap_clear_counter(ifc, mfg):
        interface = ifc.split('.')[0]
        if mfg == "cisco":
            cmd = 'clear counters %(interface)s' % locals()
        elif mfg == "juniper":
            cmd = 'clear interfaces statistics %(interface)s' % locals()
        else:
            interface = re.sub("eth-","",interface)
            interface = re.sub(":\d+","",interface)
            cmd = 'clear port %(interface)s statistics'  % locals()

        return router_command(key='clear_counter', command=cmd)

    @staticmethod
    def show_ifc_lastflap_power(ifc, mfg):
        interface = ifc.split('.')[0]

        if mfg == "cisco":
            if 'Hu' in interface or 'hundredgige' in interface:
                cmd = 'show controllers %(interface)s phy | include "(        \[0-3\].*mW |Lane * Temp)"' % locals()
            elif 'Te' in interface or 'tengige' in interface:
                cmd = 'show controllers %(interface)s phy | include "x P|N/A"' % locals()
            else:
                cmd = 'show controllers %(interface)s phy | include "x P|N/A"' % locals()
        elif mfg == "juniper":
            cmd = 'show interfaces diagnostics optics %(interface)s ' % locals()
            cmd += '| match "Laser output power|Laser receiver power|Laser rx power|Lane ' \
                   '|Receiver signal average optical power" | except alarm | except warning'
        else:
            interface = re.sub("eth-","",interface)
            interface = re.sub(":\d+","",interface)
            cmd = "show port %(interface)s optical | match 'Tx Output|Rx Optical|Value'" % locals()

        return router_command(key='show_power', command=cmd)


class Check(object):
    def __init__(self, args, psr, sub_cmd_name):
        self.psr = psr

        self.investigate = args.investigate
        self.detail = args.detail

        self.log = args.log

        self.target_interface_list = []

    def get_help(self):
        return self.psr.format_help()

    def get_usage(self):
        return self.psr.format_usage()


class IfcCheck(Check):

    def __init__(self, args, psr):
        super().__init__(args, psr, sub_cmd_name='ifc')

        self.parallel = args.parallel
        self.clear = args.clear

        self.ticket = args.ticket
        self.cids = args.cids
        self.interface_name = args.interface_name
        self.stats = args.stats

        if self.ticket or self.cids or self.interface_name:
            pass
        else:
            print('-t or -c or -n is needed\n')
            print(self.get_help())
            sys.exit(1)

        if self.stats or self.log or self.investigate:
            pass
        else:
            print('-s or -l or -i is needed\n')
            psr.print_help()
            sys.exit(1)

    def print_interface_info(self):
        output_dict_list = []

        for target_interface in self.target_interface_list:
            router = target_interface.split(' ')[0]
            ifc_name = target_interface.split(' ')[1]

            query = ConfigToolsDB.get_interface_info(router, ifc_name)
            interface_info = ConfigToolsDB.search(query, listing=False)

            query = ConfigToolsDB.get_nocfield(router, ifc_name)
            nocfield = ConfigToolsDB.search(query, listing=False) # Get router-name, ifc-name, noc-field

            ######### Beginning of addition #########
            #### Improved from here to check physical interface if user inputed Bundled circuit.
            #### Before, not be able to check physical because this script threw command to router even if the inputed ifc is logical(ae/BE).
            #### Also did not get the interface information associated logical and physical like lacp.
            #### So, I added that if intf_type is 'BL', issue the sql to get physical interface info associated.
            #### Then threw command for only phy interface to check status. by wataru

            ### Check whether or not inputted interface is logical.
            if interface_info.intf_type == "BL":
                bl_target_ifc_list= []

                ### check Only a_end circuit
                query= ConfigToolsDB.get_associated_interface_info(router, ifc_name)
                associated_interface_info= ConfigToolsDB.search(query, listing=True)

                ### For check z_end in Aggrigated-circuits, if not needed, do comment out.
                z_ends= ""
                z_ends_list= []
                for nmd_taple in associated_interface_info:
                    if nmd_taple.z_ifc_id != None and len(str(nmd_taple.z_ifc_id)) > 0:
                        z_ends_list.append(str(nmd_taple.z_ifc_id))

                if len(z_ends_list) > 0:
                        z_ends= ",".join(z_ends_list)
                        query= ConfigToolsDB.get_associated_interface_info_zend(router, ifc_name, z_ends)
                        associated_interface_info_zend= ConfigToolsDB.search(query, listing=True)

                if (associated_interface_info is None) or len(associated_interface_info) == 0: ### equal not existing data on DB
                    print("No data found on DB... {} {}".format(rotuer, ifc_name))
                    sys.exit()

                ### Deal with A-end associated interface in this loop
                for nmd_taple in associated_interface_info:
                    interface= nmd_taple.router + " " + nmd_taple.interface
                    interface_short = Tools.make_short_interface_name(interface)
                    description = '{}: {}'.format(nmd_taple.intf_type, nmd_taple.name)

                    if nmd_taple.telco:
                        abbr= nmd_taple.telco
                    else:
                        abbr= None

                    if abbr or interface_info.cid or interface_info.comment:
                        description += " - {} {} {}".format(Tools.none2empty(abbr), Tools.none2empty(nmd_taple.cid), Tools.none2empty(nmd_taple.comment))

                    if nmd_taple.cust_id:
                        description += " - USID: {}".format(Tools.none2empty(nmd_taple.cust_id))

                    output_dict = collections.OrderedDict()
                    output_dict['interface'] = interface_short
                    output_dict['description'] = description
                    output_dict['state'] = interface_info.state
                    output_dict['nocfield'] = nocfield.nocfield

                    output_dict_list.append(output_dict)
                    #if interface not in self.target_interface_list:
                    #    self.target_interface_list.append(interface)
                    if interface not in bl_target_ifc_list and interface not in bl_target_ifc_list:
                        bl_target_ifc_list.append(interface)

                ### Deal with z_end_inteface if z_ifc_id existed
                if "associated_interface_info_zend" in locals():
                    #print("Into zend Loop")
                    for nmd_taple in associated_interface_info_zend:
                        interface= nmd_taple.router + " " + nmd_taple.interface
                        interface_short = Tools.make_short_interface_name(interface)
                        description = '{}: {}'.format(nmd_taple.intf_type, nmd_taple.name)

                        if nmd_taple.telco:
                            abbr= nmd_taple.telco
                        else:
                            abbr= None

                        if abbr or interface_info.cid or interface_info.comment:
                            description += " - {} {} {}".format(Tools.none2empty(abbr), Tools.none2empty(nmd_taple.cid), Tools.none2empty(nmd_taple.comment))

                        if nmd_taple.cust_id:
                            description += " - USID: {}".format(Tools.none2empty(interface_info.cust_id))

                        output_dict = collections.OrderedDict()
                        output_dict['interface'] = interface_short
                        output_dict['description'] = description
                        output_dict['state'] = interface_info.state
                        output_dict['nocfield'] = nocfield.nocfield

                        output_dict_list.append(output_dict)

                        #if interface not in self.target_interface_list:
                        #    self.target_interface_list.append(interface)
                        if interface not in bl_target_ifc_list and interface not in self.target_interface_list:
                            bl_target_ifc_list.append(interface)


                #print("\n")
                #print(self.target_interface_list)
                #print(bl_target_ifc_list)
                #print(Tools.table_output(output_dict_list))
                continue

#						    ###
#              				            ###
#                                                   ###
           ########## End of addition #################

            #if (interface_info is not None) and (nocfield is not None):
            if (interface_info is not None) and (nocfield is not None) and ("bl_target_ifc_list" not in locals()):
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

                output_dict = collections.OrderedDict()
                output_dict['interface'] = interface_short
                output_dict['description'] = description
                output_dict['state'] = interface_info.state
                output_dict['nocfield'] = nocfield.nocfield

                output_dict_list.append(output_dict)

        ### Marge bundle_interface_list to target_interface_list
        if "bl_target_ifc_list" in locals():
            for val in bl_target_ifc_list:
                if val not in self.target_interface_list: self.target_interface_list.append(val)

        ### Sorting if BL and including A-end/Z-end, output the both of BE at top of line.
        ### This can switch to either original sort or re-sort prioritized with Bundled-ifc using do comment out parts of sort_XXX_list.
        #
        ### Sorting output_dict_list
        sort_output_dict_list= []
        for od_dict in output_dict_list:
            if re.search(r"^bundle|^ae|^be|^Bundle", od_dict["interface"].split(" ")[-1]) != None:
                sort_output_dict_list.append(od_dict)
        for od_dict in output_dict_list:
            if re.search(r"^bundle|^ae|^be|^Bundle", od_dict["interface"].split(" ")[-1]) == None:
                sort_output_dict_list.append(od_dict)
        output_dict_list= []
        output_dict_list= sort_output_dict_list

        ### Sorting self.target_interface_list
        sort_target_interface_list= []
        for val in self.target_interface_list:
            if re.search(r"^bundle|^ae|^be|^Bundle", val.split(" ")[-1]) != None:
                sort_target_interface_list.append(val)
        for val in self.target_interface_list:
            if re.search(r"^bundle|^ae|^be|^Bundle", val.split(" ")[-1]) == None:
                sort_target_interface_list.append(val)
        #test_target_interface_list= sorted(self.target_interface_list, key= lambda x:x.split(" ")[-1])# This can't work because not only ae|be but ifc-num is sorted.
        self.target_interface_list= []
        self.target_interface_list= sort_target_interface_list

								#
								#
						#################

        print(Tools.table_output(output_dict_list))


    def get_ticket_info(self):
        query = ConfigToolsDB.get_marked_interfaces_from_ticket(self.ticket)
        ticket_infos = ConfigToolsDB.search(query, listing=True)

        if not ticket_infos:
            print('Circuit related %(ticket)s is not found...' % locals())
            print()
            print(self.get_help())
            sys.exit(1)

        for ticket_info in ticket_infos:
            ifc_name = ticket_info.router + ' ' + ticket_info.ifc_name
            if ifc_name not in self.target_interface_list:
                self.target_interface_list.append(ifc_name)

    def get_cids_info(self):
        cid_list = self.cids.split('|')

        for cid in cid_list:
            query = ConfigToolsDB.get_ifc_info_from_cids(cid)
            circuit_info_list = ConfigToolsDB.search(query, listing=True)

            if circuit_info_list is None:
                print('%(cid)s : not found' % locals())
                sys.exit(1)

            for circuit_info in circuit_info_list:
                ifc_name = circuit_info.router + ' ' + circuit_info.ifc_name
                if ifc_name not in self.target_interface_list:
                    self.target_interface_list.append(circuit_info.router + ' ' + circuit_info.ifc_name)

    def get_interface_info(self):
        interface_list = self.interface_name.split('|')

        for ifc_name in interface_list:
            try:
                router, interface = ifc_name.split()

                query = ConfigToolsDB.get_interface_info(router, interface)
                circuit_info = ConfigToolsDB.search(query, listing=False)

                if circuit_info:
                    interface_name = circuit_info.router + ' ' + circuit_info.interface
                else:
                    interface = Tools.make_long_interface_name(interface)
                    query = ConfigToolsDB.get_interface_info(router, interface)
                    circuit_info = ConfigToolsDB.search(query, listing=False)

                    if circuit_info:
                        interface_name = circuit_info.router + ' ' + circuit_info.interface
                    else:
                        raise
            except:
                print('%(ifc_name)s : not found' % locals())
                sys.exit(1)

            if interface_name not in self.target_interface_list:
                self.target_interface_list.append(interface_name)

    def print_target_interface_list(self):
        print()
        print(self.target_interface_list)
        print("*" * 100)

        if self.investigate and (len(self.target_interface_list) > 30):
            print('max interface counts are 30 or less :(')
            sys.exit(1)
        elif (not self.ticket) and (len(self.target_interface_list) > 60):
            print('max interface counts are 60 or less :(')
            sys.exit(1)

    def run_stats_mode(self):
        routers_dict = {}
        router_list = []

        ##### Added this regarding improvement for check bundle-physical ifc ###
        if "associated_interface_info" in locals():
            print(self.target_interface_list)

        for target_interface in self.target_interface_list:
            router, interface = target_interface.split()

            if router not in routers_dict:
                routers_dict[router] = [interface]
                router_list.append(router)
            else:
                routers_dict[router].append(interface)

        print('## summary ##')
        for summary in sorted(self.make_summary()):
            print(summary)
        print()

        print('## aggregated stats ##')
        d = Tools.multi_stats_url(routers_dict)
        for router, url in sorted(d.items(), key=lambda x: x[0]):
            print(router + ' : ' + ' '.join(routers_dict[router]))
            print(Tools.colorstring(url, 'blue'))
        print()

        print('## for config install ##')
        print('mkcfg ' + ' '.join(sorted(list(set(router_list)))))
        print()

    def run_log_mode(self):
        print(Tools.colorstring('log analysis mode, not router login', 'red'))
        print("how many days log do you need? [1-20]")

        while True:
            input_line = input('>>>  ')
            try:
                input_line_int = int(input_line)
                if input_line_int < 1 or input_line_int > 20:
                    print('Please input 1-20 :)')
                    continue
                break
            except:
                print('Please input 1-20 :)')
                continue

        if input_line_int == 1:
            print('alright. just today')
        else:
            print('alright. looking {} days log'.format(input_line_int))

        for target_interface in self.target_interface_list:
            IfcCheck.interface_log_search(target_interface, input_line_int)

    def start_investigation(self):

        if self.clear:
            print(Tools.colorstring('do you really want to clear interface counters?', 'red'))
            if not Tools.yes_no_input():
                self.clear = False

        if self.parallel and len(self.target_interface_list) > 1:
            with ThreadPoolExecutor(max_workers=20) as executor:

                alart = 'start investigation by parallel login mode. Bug sometimes happen.\n' \
                        'updating related packages may help this. If bug happpens, please try the commnad below\n'
                alart += Tools.colorstring('pip3 install --user -U netmiko cryptography', 'yellow')

                print(Tools.colorstring(alart, 'red'))
                detail_list = [self.detail for i in range(len(self.target_interface_list))]
                clear_list = [self.clear for _ in range(len(self.target_interface_list))]
                res = executor.map(IfcCheck.investigate_interface, self.target_interface_list, detail_list, clear_list)

            for output in list(res):
                print(output)
        else:
            print(Tools.colorstring('start investigation by login router one by one.....', 'red'))
            for target_interface in self.target_interface_list:

            ########### Beginning of improvement to be able to check logical-physical interface. 9/Feb/2020 by wataru ##########

                output = IfcCheck.investigate_interface(target_interface, self.detail, self.clear)
                print(output)

    def make_summary(self):

        summary_list = []

        for target_interface in self.target_interface_list:

            router, interface = target_interface.split()

            query = ConfigToolsDB.get_interface_info(router, interface)
            interface_info = ConfigToolsDB.search(query, listing=False)

            Aend = interface_info.router + " " + interface_info.interface

            if interface_info.intf_type == 'BB':
                if interface_info.telco:
                    cids = interface_info.cid.split('/')

                    pattern = r'(u\d\d\d\d)'
                    matchOB = re.search(pattern, interface_info.cid)

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

                if telco is not None:
                    bb_subject = '%(Aend)s to %(Zend)s : %(telco)s (%(cid)s)' % locals()
                elif abbr:
                    bb_subject = '%(Aend)s to %(Zend)s : %(abbr)s (%(cid)s)' % locals()
                else:
                    bb_subject = '%(Aend)s to %(Zend)s : %(cid)s' % locals()

                customer_name = interface_info.name.split()[0]
            elif ' ' in interface_info.name:
                customer_name = interface_info.name.split()[1]
            else:
                customer_name = interface_info.name

            if interface_info.intf_type == 'BB':
                subject = bb_subject
            else:
                subject = interface_info.router + " " + interface_info.interface + " - " + customer_name

            summary_list.append(Tools.make_short_interface_name(subject))

        return summary_list

    @staticmethod
    def interface_log_search(target_interface, input_line_int):

        router, interface = target_interface.split()

        query = ConfigToolsDB.get_interface_info(router, interface)
        peerinfo = ConfigToolsDB.search(query, listing=False)

        if peerinfo.mfg == "cisco":
            log_file_today = LOGFILE_CISCO_TODAY
        elif peerinfo.mfg == "juniper":
            log_file_today = LOGFILE_JUNIPER_TODAY
        else:
            log_file_today = LOGFILE_NOKIA_TODAY
            for i in socket.getaddrinfo(router,None):
                if ":" not in i[-1][0]:
                    router = i[-1][0]
                    break

        log_file_list = [log_file_today]

        if input_line_int > 1:
            now = datetime.now()
            for num in range(2, input_line_int + 1):
                yyyymmdd = (now - timedelta(days=(num - 2))).strftime("%Y%m%d")
                log_file_list.append('{}-{}.gz'.format(log_file_today, yyyymmdd))

        print()
        print(Tools.colorstring(target_interface, 'green'),)
        for log_file in log_file_list[::-1]:
            print(Tools.colorstring(log_file, 'blue'))
            output = ''
            if log_file == log_file_today:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as fh:
                    for line in fh:
                        if (router.lower() in line.lower()) and (interface.lower() in line.lower()):
                            tmp = line.strip().split('>', 1)
                            if len(tmp) == 2:
                                output = tmp[1]
                            else:
                                output = tmp[0]
                            print(output)
            else:
                with gzip.open(log_file, 'rt', encoding='utf-8', errors='ignore') as fh:
                    for line in fh:
                        if (router.lower() in line.lower()) and (interface.lower() in line.lower()):
                            tmp = line.strip().split('>', 1)
                            if len(tmp) == 2:
                                output = tmp[1]
                            else:
                                output = tmp[0]
                            print(output)
            if output == '':
                print('--- not found ---')
        print()

    @staticmethod
    def check_ifc(router, interface, detail=True, clear=False):

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

        session = RouterSession(interface_info.router, interface_info.mfg)

        cmds = []
        msg = ''

        #### updated here for fix clear command issue that command is difference depends on OS-revision. 15/Nov/2019 by wataru
        if clear:
            if interface_info.mfg == "cisco":
                if interface_info.os_rev == "5.3.4":#
                    clear_cisco = 'clear counters ' + interface_info.interface#
                else:#
                    clear_cisco = 'clear counters interface ' + interface_info.interface#
                msg += Tools.colorstring('trying to clear counters.... ', 'red')
                tmp_output = session.session.send_command_timing(clear_cisco)
                if '[confirm]' in tmp_output:
                    tmp_output += '\n'
                    tmp_output += session.session.send_command_timing("y")
                    msg += Tools.colorstring('clear counters is successful (maybe)', 'green')
                    msg += '\n'

### These are original code.
#                 clear_cisco = 'clear counters ' + interface_info.interface
#                msg += Tools.colorstring('trying to clear counters.... ', 'red')
#                tmp_output = session.session.send_command_timing(clear_cisco)
#                if '[confirm]' in tmp_output:
#                    tmp_output += '\n'
#                    tmp_output += session.session.send_command_timing("y")
#                    msg += Tools.colorstring('clear counters is successful (maybe)', 'green')
#                    msg += '\n'
#####

            else:
                cmds.append(RouterCommand.clear_counter(interface_info))


        if interface_info.intf_type == "BL" and interface_info.mfg == "cisco":
            cmds.append(RouterCommand.show_cloc(interface_info))
            cmds.append(RouterCommand.show_lacp(interface_info))
            cmds.append(RouterCommand.ifc_desc(interface_info))
            cmds.append(RouterCommand.show_flap(interface_info))
            cmds.append(RouterCommand.show_error(interface_info))
            cmds.append(RouterCommand.ifc_log(interface_info))
        elif interface_info.intf_type == "BL" and interface_info.mfg == "juniper": #netmiko cannot handle "show lacp interfaces aex"
            cmds.append(RouterCommand.show_cloc(interface_info))
            cmds.append(RouterCommand.ifc_desc(interface_info))
            cmds.append(RouterCommand.show_flap(interface_info))
            cmds.append(RouterCommand.show_error(interface_info))
            cmds.append(RouterCommand.ifc_log(interface_info))

        elif interface_info.intf_type == "BL" and interface_info.mfg == "nokia":
            cmds.append(RouterCommand.show_cloc(interface_info))
            cmds.append(RouterCommand.show_lacp(interface_info))
            cmds.append(RouterCommand.ifc_log(interface_info))
        else:
            cmds.append(RouterCommand.show_cloc(interface_info))
            cmds.append(RouterCommand.ifc_desc(interface_info))
            cmds.append(RouterCommand.show_flap(interface_info))
            cmds.append(RouterCommand.show_power(interface_info))
            cmds.append(RouterCommand.show_error(interface_info))
            cmds.append(RouterCommand.ifc_log(interface_info))

######## These are original code before improvement of logical-physical check #########
#        cmds.append(RouterCommand.show_cloc(interface_info))
#        cmds.append(RouterCommand.ifc_desc(interface_info))
#        cmds.append(RouterCommand.show_flap(interface_info))
#        cmds.append(RouterCommand.show_power(interface_info))
#        cmds.append(RouterCommand.show_error(interface_info))
#        cmds.append(RouterCommand.ifc_log(interface_info))

        if interface_info.intf_type == 'BB':
            subject = bb_subject
        else:
            subject = customer_name + " - " + interface_info.router
            subject += " " + interface_info.interface
            subject += " - "

        for response in session(cmds):
            if detail:
                msg += '------------------------------------------------------------\n'
                msg += '%s : %s' % (interface_info.router, re.sub(' {2,}', ' ', response.command)) + '\n'
                msg += '------------------------------------------------------------\n'
            msg += response.response + '\n\n'

        session.close_session()

        return msg, subject

    @staticmethod
    def investigate_interface(target_interface, detail=True, clear=False):

        return_output = '\n'
        return_output += Tools.colorstring(target_interface, 'green')
        return_output += '\n'

        try:
            router, interface = target_interface.split(' ')
            output_line, subject = IfcCheck.check_ifc(router, interface, detail, clear)

            flap = True

            for output in output_line.split('\n'):
                if ('down' in output.lower()) and ('link' not in output.lower()) and ('line' not in output.lower()) and ('Hold time down' not in output):
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

        except:
            return_output = '\n'
            return_output += Tools.colorstring(target_interface, 'green')
            return_output += '\n'
            return_output += ' ** sorry I conuld not invesitigate this interface **\n'
            return_output += ' ** continue to investigate next interface **'
            return_output = Tools.colorstring(return_output, 'red')

        return return_output


class BgpCheck(Check):
    def __init__(self, args, psr):
        super().__init__(args, psr, sub_cmd_name='bgp')

        self.parallel = args.parallel
        self.peer_ip = args.peer_ip

        if self.log or self.investigate:
            pass
        else:
            print('-l or -i is needed\n')
            psr.print_help()
            sys.exit(1)

    def get_peer_info(self):
        peer_ip_list = self.peer_ip.split('|')

        for peer_ip in peer_ip_list:
            try:
                ipaddr = IPAddress(peer_ip)

                query = ConfigToolsDB.get_peer_info(ipaddr=ipaddr.format())
                peerinfo = ConfigToolsDB.search(query, listing=False)

                if peerinfo:
                    target_interface = ' '.join([peerinfo.router,  peerinfo.interface, peerinfo.ip_addr])

                    if target_interface not in self.target_interface_list:
                        self.target_interface_list.append(target_interface)
                else:
                    raise
            except:
                print('%(peer_ip)s : not found' % locals())
                sys.exit(1)

    def print_target_interface_list(self):
        print()
        print(self.target_interface_list)
        print("*" * 100)

        if self.investigate and (len(self.target_interface_list) > 20):
            print('max interface counts are 20 or less :(')
            sys.exit(1)
        elif len(self.target_interface_list) > 40:
            print('max interface counts are 40 or less :(')
            sys.exit(1)

    def run_log_mode(self):
        print(Tools.colorstring('log analysis mode, not router login', 'red'))
        print("how many days log do you need? [1-20]")

        while True:
            input_line = input('>>>  ')
            try:
                input_line_int = int(input_line)
                if input_line_int < 1 or input_line_int > 20:
                    print('Please input 1-20 :)')
                    continue
                break
            except:
                print('Please input 1-20 :)')
                continue

        if input_line_int == 1:
            print('alright. just today')
        else:
            print('alright. looking {} days log'.format(input_line_int))

        for target_interface in self.target_interface_list:
            BgpCheck.bgp_log_search(target_interface, input_line_int)

    @staticmethod
    def bgp_log_search(target_interface, input_line_int):

        router, interface, peer = target_interface.split(' ')
        query = ConfigToolsDB.get_peer_info(router, peer)
        peerinfo = ConfigToolsDB.search(query, listing=False)

        if peerinfo.mfg == "cisco":
            log_file_today = LOGFILE_CISCO_TODAY
        elif peerinfo.mfg == "juniper":
            log_file_today = LOGFILE_JUNIPER_TODAY
        else:
            log_file_today = LOGFILE_NOKIA_TODAY
            for i in socket.getaddrinfo(router,None):
                if ":" not in i[-1][0]:
                    router = i[-1][0]
                    break

        log_file_list = [log_file_today]

        if input_line_int > 1:
            now = datetime.now()
            for num in range(2, input_line_int + 1):
                yyyymmdd = (now - timedelta(days=(num - 2))).strftime("%Y%m%d")
                log_file_list.append('{}-{}.gz'.format(log_file_today, yyyymmdd))

        print()
        print(Tools.colorstring(target_interface, 'green'), )
        for log_file in log_file_list[::-1]:
            print(Tools.colorstring(log_file, 'blue'))
            output = ''
            if log_file == log_file_today:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as fh:
                    for line in fh:
                        if (router.lower() in line.lower()) and (peer in line.lower()):
                            tmp = line.strip().split('>', 1)
                              
                            if len(tmp) == 2:
                                output = tmp[1]
                            else:
                                output = tmp[0]
                            print(output)
            else:
                with gzip.open(log_file, 'rt', encoding='utf-8', errors='ignore') as fh:
                    for line in fh:
                        if (router.lower() in line.lower()) and (peer in line.lower()):
                            tmp = line.strip().split('>', 1)
                            if len(tmp) == 2:
                                output = tmp[1]
                            else:
                                output = tmp[0]
                            print(output)
            if output == '':
                print('--- not found ---')
        print()

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
        if peerinfo.mfg == 'nokia':
            ifc_cmds.append(RouterCommand.ifc_status(peerinfo)) # adding interface status as nokia description does not show it
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

        customer_name_bgp = BgpCheck.combine_descriptions(peerinfo.p_desc, peerinfo.name)

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
            output_line, subject_ifc, subject_bgp = BgpCheck.check_peer(peerinfo, detail)

            target_interface = ' '.join([router, interface])
            flap = True
            ignore = False
            for output in output_line.split('\n'):
                if '-- IGNORE --' in output:
                    red_ignore = Tools.colorstring("-- IGNORE --", 'red')
                    return_output += output.replace("-- IGNORE --", red_ignore) + '\n'
                    ignore = True
                elif ('down' in output.lower()) and ('link' not in output.lower()) and \
                        ('line' not in output.lower()) and ('neighbor' not in output.lower()):
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

        except:
            return_output = '\n'
            return_output += Tools.colorstring(target_interface, 'green')
            return_output += '\n'
            return_output += ' ** sorry I conuld not invesitigate this interface **\n'
            return_output += ' ** continue to investigate next interface **'
            return_output = Tools.colorstring(return_output, 'red')

        return return_output

    def start_investigation(self):
        if self.parallel and len(self.target_interface_list) > 1:
            with ThreadPoolExecutor(max_workers=10) as executor:

                alart = 'start investigation by parallel login mode. Bug sometimes happen.\n' \
                        'updating related packages may help this. If bug happpens, please try the commnad below\n'
                alart += Tools.colorstring('pip3 install --user -U netmiko cryptography', 'yellow')

                print(Tools.colorstring(alart, 'red'))
                detail_list = [self.detail for _ in range(len(self.target_interface_list))]
                res = executor.map(BgpCheck.investigate_peer, self.target_interface_list, detail_list)

            for output in list(res):
                print(output)

        else:
            print(Tools.colorstring('start investigation by login router one by one.....', 'red'))

            for target_interface in self.target_interface_list:
                output = BgpCheck.investigate_peer(target_interface, self.detail)
                print(output)


class VcCheck(Check):
    def __init__(self, args, psr):
        super().__init__(args, psr, sub_cmd_name='vc')

        self.parallel = args.parallel
        self.vcid = args.vcid

        if self.log or self.investigate:
            pass
        else:
            print('-l or -i is needed\n')
            psr.print_help()
            sys.exit(1)

    def get_vc_info(self):
        vcid_list = self.vcid.split('|')

        for vcid in vcid_list:
            try:
                vcid = vcid.lower().replace('vc-', '')
                query = ConfigToolsDB.get_vc_info(vcid)
                vlink = ConfigToolsDB.search(query, listing=True)

                if vlink:
                    if len(vlink) == 2:
                        self.target_interface_list.append(
                            vlink[0].router + ' ' + vlink[0].ifc_name + ' ' + str(vlink[0].id)
                        )
                        self.target_interface_list.append(
                            vlink[1].router + ' ' + vlink[1].ifc_name + ' ' + str(vlink[1].id)
                        )
                    else:
                        raise
                else:
                    raise
            except:
                print('%(vcid)s : not found' % locals())
                sys.exit(1)

    def print_target_interface_list(self):
        print()
        print(self.target_interface_list)
        print("*" * 100)

        if self.investigate and (len(self.target_interface_list) > 20):
            print('max interface counts are 20 or less :(')
            sys.exit(1)
        elif len(self.target_interface_list) > 40:
            print('max interface counts are 40 or less :(')
            sys.exit(1)

    def run_log_mode(self):
        print(Tools.colorstring('log analysis mode, not router login', 'red'))
        print("how many days log do you need? [1-20]")

        while True:
            input_line = input('>>>  ')
            try:
                input_line_int = int(input_line)
                if input_line_int < 1 or input_line_int > 20:
                    print('Please input 1-20 :)')
                    continue
                break
            except:
                print('Please input 1-20 :)')
                continue

        if input_line_int == 1:
            print('alright. just today')
        else:
            print('alright. looking {} days log'.format(input_line_int))

        for target_interface in self.target_interface_list:
            VcCheck.vc_log_search(target_interface, input_line_int)

    @staticmethod
    def vc_log_search(target_interface, input_line_int):

        router, interface, vcid = target_interface.split(' ')

        query = ConfigToolsDB.get_interface_info(router, interface)
        peerinfo = ConfigToolsDB.search(query, listing=False)

        if peerinfo.mfg == "cisco":
            log_file_today = LOGFILE_CISCO_TODAY
        elif peerinfo.mfg == "juniper":
            log_file_today = LOGFILE_JUNIPER_TODAY
        else:
            log_file_today = LOGFILE_NOKIA_TODAY
            for i in socket.getaddrinfo(router,None):
                if ":" not in i[-1][0]:
                    router = i[-1][0]
                    break

        log_file_list = [log_file_today]

        if input_line_int > 1:
            now = datetime.now()
            for num in range(2, input_line_int + 1):
                yyyymmdd = (now - timedelta(days=(num - 2))).strftime("%Y%m%d")
                log_file_list.append('{}-{}.gz'.format(log_file_today, yyyymmdd))

        print()
        print(Tools.colorstring(' '.join([router, interface, 'VC-' + vcid]), 'green'),)

        for log_file in log_file_list[::-1]:
            print(Tools.colorstring(log_file, 'blue'))
            output = ''
            if log_file == log_file_today:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as fh:
                    for line in fh:
                        if (router.lower() in line.lower()) and \
                                ((('id  {},'.format(vcid) in line) and ('L2-L2VPN_PW-3-UPDOWN' in line)) or
                                 ((': {}'.format(vcid) in line) and ('RPD_LAYER2' in line)) or
                                 (('SVCMGR-MINOR-sdpBindStatusChanged' in line) and (vcid in line))):

                            tmp = line.strip().split('>', 1)
                            if len(tmp) == 2:
                                output = tmp[1]
                            else:
                                output = tmp[0]
                            print(output)
            else:
                with gzip.open(log_file, 'rt', encoding='utf-8', errors='ignore') as fh:
                    for line in fh:
                        if (router.lower() in line.lower()) and \
                                ((('id  {},'.format(vcid) in line) and ('L2-L2VPN_PW-3-UPDOWN' in line)) or
                                 ((': {}'.format(vcid) in line) and ('RPD_LAYER2' in line)) or
                                 (('SVCMGR-MINOR-sdpBindStatusChanged' in line) and (vcid in line))):

                            tmp = line.strip().split('>', 1)
                            if len(tmp) == 2:
                                output = tmp[1]
                            else:
                                output = tmp[0]
                            print(output)
            if output == '':
                print('--- not found ---')
        print()

    @staticmethod
    def check_ifc(router, interface, vcid, detail=True):

        query = ConfigToolsDB.get_interface_info(router, interface)
        peerinfo = ConfigToolsDB.search(query, listing=False)

        query = ConfigToolsDB.get_vc_info(vcid)
        vlink = ConfigToolsDB.search(query, listing=True)

        if len(vlink) == 2:
            if vlink[0].router == router:
                another_side = vlink[1].router + ' ' + vlink[1].ifc_name
                another_router = vlink[1].router
            else:
                another_side = vlink[0].router + ' ' + vlink[0].ifc_name
                another_router = vlink[0].router
        else:
            sys.exit()

        session = RouterSession(peerinfo.router, peerinfo.mfg)

        cmds = []
        cmds.append(RouterCommand.show_cloc(peerinfo))
        cmds.append(RouterCommand.ifc_desc(peerinfo))
        if peerinfo.mfg == 'nokia':
            cmds.append(RouterCommand.ifc_status(peerinfo)) # adding interface status as nokia description does not show it
        cmds.append(RouterCommand.show_flap(peerinfo))
        cmds.append(RouterCommand.show_power(peerinfo))
        cmds.append(RouterCommand.show_error(peerinfo))
        cmds.append(RouterCommand.ifc_log(peerinfo))
        cmds.append(RouterCommand.show_l2vpn(peerinfo, vcid))

        if peerinfo.mfg == 'cisco':
            cmds.append(RouterCommand.show_l2vpn_mtu(peerinfo, vcid))
            cmds.append(RouterCommand.show_l2vpn_flap(peerinfo, vcid))
        cmds.append(RouterCommand.l2vpn_log(peerinfo, vcid))

        query = ConfigToolsDB.get_loopback_addr(another_router)
        another_router = ConfigToolsDB.search(query, listing=False)

        if another_router and (peerinfo.mfg == 'cisco' or peerinfo.mfg == 'juniper'):
            cmds.append(RouterCommand.l2vpn_ping(peerinfo, vcid, another_router.loopback))

        Aend = router + " " + interface
        subject = " - ".join([peerinfo.name, 'VC-{}'.format(vcid), Aend + ' to ' + another_side, 'VLINK '])

        msg = ''
        for response in session(cmds):
            if detail:
                msg += '------------------------------------------------------------\n'
                msg += '%s : %s' % (peerinfo.router, re.sub(' {2,}', ' ', response.command)) + '\n'
                msg += '------------------------------------------------------------\n'
            msg += response.response + '\n\n'
        session.close_session()

        return msg, subject

    @staticmethod
    def investigate_interface(target_interface, detail=True):

        router, interface, vcid = target_interface.split(' ')

        return_output = "*" * 100 + '\n'
        return_output += Tools.colorstring(' '.join([router, interface, 'VC-' + vcid]), 'green')
        return_output += '\n'

        try:
            output_line, subject = VcCheck.check_ifc(router, interface, vcid, detail)

            target_interface = ' '.join([router, interface])
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

        except:
            return_output = '\n'
            return_output += Tools.colorstring(target_interface, 'green')
            return_output += '\n'
            return_output += ' ** sorry I conuld not invesitigate this interface **\n'
            return_output += ' ** continue to investigate next interface **'
            return_output = Tools.colorstring(return_output, 'red')

        return return_output

    def start_investigation(self):

        if self.parallel and len(self.target_interface_list) > 1:
            with ThreadPoolExecutor(max_workers=10) as executor:

                alart = 'start investigation by parallel login mode. Bug sometimes happen.\n' \
                        'updating related packages may help this. If bug happpens, please try the commnad below\n'
                alart += Tools.colorstring('pip3 install --user -U netmiko cryptography', 'yellow')

                print(Tools.colorstring(alart, 'red'))
                detail_list = [self.detail for _ in range(len(self.target_interface_list))]
                res = executor.map(VcCheck.investigate_interface, self.target_interface_list, detail_list)

            for output in list(res):
                print(output)
        else:
            print(Tools.colorstring('start investigation by login router one by one.....', 'red'))

            for target_interface in self.target_interface_list:
                output = VcCheck.investigate_interface(target_interface, self.detail)
                print(output)


class JchipCheck(Check):
    def __init__(self, args, psr):
        super().__init__(args, psr, sub_cmd_name='jchip')

        self.router = args.router
        self.slot = args.slot

        if self.log or self.investigate:
            pass
        else:
            print('-l or -i is needed\n')
            psr.print_help()
            sys.exit(1)

    def get_slot_info(self):
        query = ConfigToolsDB.get_slot_interfaces(router=self.router, slot=self.slot)
        interface_list = ConfigToolsDB.search(query, listing=True)

        if interface_list is None:
            print(Tools.colorstring('could not find interface', 'red'))
            sys.exit()
        elif interface_list[0].mfg != 'juniper':
            print(Tools.colorstring('This cmd is for juniper', 'red'))
            sys.exit()

        items = []
        routers_dict = {}

        for interface in interface_list:
            items.append(interface._asdict())
            self.target_interface_list.append(interface.interface)

        print()
        print(Tools.table_output(items))
        print()

        routers_dict[self.router] = self.target_interface_list
        stats_url = Tools.multi_stats_url(routers_dict)[self.router]
        print(Tools.colorstring(stats_url, 'blue'))
        print()

    def run_log_mode(self):
        fpc = 'fpc' + str(self.slot)
        filter = ' | grep {} | grep {}'.format(self.router, fpc)

        today = date.today()
        today_str = today.strftime("%Y%m")

        print(Tools.colorstring('Linux command (just for your reference)', 'green'))
        print(Tools.colorstring('> date', 'green'))
        print(Tools.colorstring('> gzcat /var/log/local5/debug-{}* {}'.format(today_str, filter), 'green'))
        print(Tools.colorstring('> cat /var/log/local5/debug' + filter, 'green'))
        print()

        print(Tools.colorstring('log analysis mode, not router login', 'red'))
        print("how many days log do you need? [1-20]")

        while True:
            input_line = input('>>>  ')
            try:
                input_line_int = int(input_line)
                if input_line_int < 1 or input_line_int > 20:
                    print('Please input 1-20 :)')
                    continue
                break
            except:
                print('Please input 1-20 :)')
                continue

        if input_line_int == 1:
            print('alright. just today')
        else:
            print('alright. looking {} days log'.format(input_line_int))

        JchipCheck.jchip_log_search(self.router, self.slot, input_line_int)

    @staticmethod
    def jchip_log_search(router, slot, input_line_int):

        fpc = 'fpc' + str(slot)

        log_file_today = LOGFILE_JUNIPER_TODAY
        log_file_list = [log_file_today]

        if input_line_int > 1:
            now = datetime.now()
            for num in range(2, input_line_int + 1):
                yyyymmdd = (now - timedelta(days=(num - 2))).strftime("%Y%m%d")
                log_file_list.append('{}-{}.gz'.format(log_file_today, yyyymmdd))

        print()
        print(Tools.colorstring('{} {}'.format(router, fpc), 'green'), )
        for log_file in log_file_list[::-1]:
            print(Tools.colorstring(log_file, 'blue'))

            output = ''
            if log_file == log_file_today:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as fh:
                    for line in fh:
                        if (router.lower() in line.lower()) and (fpc.lower() in line.lower()):
                            tmp = line.strip().split('>', 1)
                            if len(tmp) == 2:
                                output = tmp[1]
                            else:
                                output = tmp[0]
                            print(output)
            else:
                with gzip.open(log_file, 'rt', encoding='utf-8', errors='ignore') as fh:
                    for line in fh:
                        if (router.lower() in line.lower()) and (fpc.lower() in line.lower()):
                            tmp = line.strip().split('>', 1)
                            if len(tmp) == 2:
                                output = tmp[1]
                            else:
                                output = tmp[0]
                            print(output)
            if output == '':
                print('--- not found ---')
        print()

    def start_investigation(self):
        self.detail = True
        print(Tools.colorstring('start investigation by login router....', 'red'))
        output = JchipCheck.check_chiperror(self)
        print(output)

    def check_chiperror(self):

        def create_cmd(str):
            return router_command(key='check_chiperror', command=str)

        return_output = '\n'
        return_output += Tools.colorstring('{} fpc{}'.format(self.router, self.slot), 'green')
        return_output += '\n'

        try:
            session = RouterSession(self.router, 'juniper')

            cmds = []
            cmds.append(create_cmd('show system uptime | match current'))
            cmds.append(create_cmd('show chassis alarms'))
            cmds.append(create_cmd('show log messages | match LUC'))
            cmds.append(create_cmd('show log messages | match fpc{}'.format(self.slot)))
            cmds.append(create_cmd('show chassis fpc {} detail'.format(self.slot)))
            cmds.append(create_cmd('show interfaces descriptions | match -{}/'.format(self.slot)))

            for response in session(cmds):
                if self.detail:
                    return_output += '------------------------------------------------------------\n'
                    return_output += '%s : %s' % (self.router, re.sub(' {2,}', ' ', response.command)) + '\n'
                    return_output += '------------------------------------------------------------\n'
                return_output += response.response + '\n\n'

            session.close_session()

        except:
            return_output = '\n'
            return_output += Tools.colorstring('investigation failed...', 'red')
            return_output += '\n'

        return return_output


class DownCheck(Check):
    def __init__(self, args, psr):
        self.psr = psr

        self.country = args.country
        self.anoc = args.anoc
        self.batch = args.batch
        self.thread = args.thread
        self.test = args.test

        if (self.thread < 2) or (20 < self.thread):
            print(Tools.colorstring('--thread is 2 ~ 20', 'red'))
            sys.exit()

        if args.include:
            self.include_list = args.include.split('|')
        else:
            self.include_list = None

        if args.exclude:
            self.exclude_list = args.exclude.split('|')
        else:
            self.exclude_list = None

        if self.anoc:
            self.country = Tools.get_anoc_coutry_fiter()

        self.target_router_list = []
        self.all_router_list = []
        self.target_interface_list = []

    def get_target_routers(self):
        query = ConfigToolsDB.get_all_routers()
        all_routers = ConfigToolsDB.search(query, listing=True)

        sort_router_list = []

        for router in all_routers:
            if ('test' not in router.name) and ('lab' not in router.name) and router.state == 'up': 
                tmp_list = []
                tmp_list.append(router)
                tmp_list.extend(router.name.split('.'))
                sort_router_list.append(tmp_list)

        sort_router_list.sort(key=lambda x: (x[3], x[2], x[1]))

        for sort_router in sort_router_list:
            self.all_router_list.append(sort_router[0].name)

            if self.country:
                if not re.search(self.country, sort_router[3]):
                    continue
            self.target_router_list.append(sort_router[0])

    def ifc_desc(self, peer):

        if peer.mfg == "cisco":
            show_desc = 'show interfaces description'

            include = 'down'

            if not self.test:
                exclude = 'unused|Mg0|PT0|IGNORE|OUTAGE|MAINT|FAILURE|admin-down'
                exclude = 'unused|Mg0|PT0|^nG|^nT|IGNORE|OUTAGE|MAINT|FAILURE|admin-down'
            else:
                exclude = 'unused|Mg0|PT0|IGNORE|admin-down'

            if self.exclude_list:
                exclude += '|' + '|'.join(self.exclude_list)

            cmd = '{} | include "{}" | exclude "{}" '.format(show_desc, include, exclude)

            if self.include_list:
                cmd += '| include "{}"'.format('|'.join(self.include_list))

        elif peer.mfg == "juniper":
            show_desc = 'show interfaces descriptions'

            include = 'down'
            if not self.test:
                exclude = 'unused|IGNORE|OUTAGE|MAINT|FAILURE'
            else:
                exclude = 'unused|IGNORE'

            if self.exclude_list:
                exclude += '|' + '|'.join(self.exclude_list)

            cmd = '{} | match "{}" | except "{}"'.format(show_desc, include, exclude)

            if self.include_list:
                cmd += '| match "{}"'.format('|'.join(self.include_list))
        else: #Nokia
            show_desc = 'show port description detail'
            include = 'Down'
            if not self.test:
                #exclude = 'Ethernet|SFP28|unused|IGNORE|OUTAGE|MAINT|FAILURE'
                exclude = 'Ethernet|QSFP-DD|SFP28|unused|OUTAGE|MAINT|FAILURE'#DEBUG rikea
            else:
                exclude = 'SFP28|unused|IGNORE'
            if self.exclude_list:
                exclude += '|' + '|'.join(self.exclude_list)

            cmd = "{} | match '{}' | match '{}' invert-match".format(show_desc, include, exclude)

            if self.include_list:
                cmd += '| match "{}"'.format('|'.join(self.include_list))


        return router_command(key='ifc_desc', command=cmd)

    def investigate_router(self, target_router):
        try:
            session = RouterSession(target_router.name, target_router.mfg)

            output = ''
            down_interface_list = []

            cmds = []
            cmds.append(self.ifc_desc(target_router))

            for response in session(cmds):
                output = target_router.name
                for line in response.response.split('\n'):
                    if 'down' in line or 'Down' in line:
                        output += '\n' + line
                        
                        down_interface = [target_router.name]
                        down_interface.extend(re.split('\s+', line, 3))
                        down_interface_list.append(down_interface)
            session.close_session()

            if 'down' not in output and 'Down' not in output:
                output = None
                down_interface_list = None
        except:
            output = None
            down_interface_list = None
        return output, down_interface_list

    def start_investigation(self):
        if not self.batch:
            print('Checking {} Routers....'.format(len(self.target_router_list)))
        Tools.logging(status=True,
                      message='Checking {} Routers....'.format(len(self.target_router_list)),
                      logfile=NOCCHECK_DOWN_LOGFILE)

        router_count = len(self.target_router_list)
        parallel_count = self.thread
        q, mod = divmod(router_count, parallel_count)

        loop_count = 0
        while True:
            start = loop_count * parallel_count

            if loop_count < q:
                end = start + parallel_count - 1
                target_routers = self.target_router_list[start:end]
            else:
                target_routers = self.target_router_list[start:]

            with ThreadPoolExecutor(max_workers=20) as executor:
                res = executor.map(self.investigate_router, target_routers)

            for output, down_interface_list in list(res):
                if output:
                    for line in output.split('\n'):
                        if 'down' not in line and 'Down' not in line:
                            print(Tools.colorstring(line, 'green'))
                            Tools.logging(status=True, message=line, logfile=NOCCHECK_DOWN_LOGFILE)

                        else:
                            print(Tools.colorstring(line, 'red'))
                            Tools.logging(status=True, message=line, logfile=NOCCHECK_DOWN_LOGFILE)

                    for down_interface in down_interface_list:
                        self.target_interface_list.append(down_interface)

            if loop_count < q:
                loop_count += 1
            else:
                break

    @staticmethod
    def check_ifc_list_lastflap(router, interface_list, mfg, detail=False):

        session = RouterSession(router, mfg)

        cmds = []
        for interface in interface_list:
            cmds.append(RouterCommand.show_ifc_lastflap(interface, mfg))

        msg = ''
        for response in session(cmds):
            if detail:
                msg += '### %s : %s ###' % (router, re.sub(' {2,}', ' ', response.command)) + '\n'
            msg += response.response + '\n\n'
            msg += '*' * 10 + '\n'
        session.close_session()

        return msg

    def notification_all_in_one(self):
        print('\nnotification start\n')
        Tools.logging(status=True, message='notification start', logfile=NOCCHECK_DOWN_LOGFILE)

        fields = []
        actions = []
        graph_stats_link_list = []
        graph_search_stats_interface_list = []
        target_router_dict = {}
        sorted_target_router_dict = collections.OrderedDict()

        for target_interface in self.target_interface_list:
            router = target_interface[0]

            if router not in target_router_dict:
                target_router_dict[router] = [target_interface]
            else:
                target_router_dict[router].append(target_interface)

        sorted_target_router_list = sorted(target_router_dict, key=lambda k: len(target_router_dict[k]), reverse=True)
        for sorted_target_router in sorted_target_router_list:
            sorted_target_router_dict[sorted_target_router] = target_router_dict[sorted_target_router]

        for router, interface_info_list in sorted_target_router_dict.items():
            query = ConfigToolsDB.get_router_info(router)
            router_info = ConfigToolsDB.search(query, listing=False)

            interface_list = []

            for interface_info in interface_info_list:
                interface_list.append(Tools.make_long_interface_name(interface_info[1].lower()))

            try:
                result = DownCheck.check_ifc_list_lastflap(router, interface_list, router_info.mfg)
            except KeyboardInterrupt:
                print("pressed control-c by user")
                sys.exit()
            #except:
            except Exception as e:
                print(e)
                import traceback
                print(traceback.format_exc())

                print('could not get interfaces information from {}'.format(router))
                Tools.logging(status=True, message='could not get interfaces information from {}'.format(router),
                              logfile=NOCCHECK_DOWN_LOGFILE)
                continue

            output_list = result.split('*' * 10 + '\n')

            while output_list.count("") > 0:
                output_list.remove("")

            print()
            print(Tools.colorstring('{} {} {}'.format(router, router_info.mfg, str(interface_list)), 'red'))
            print(Tools.colorstring(str(output_list), 'green'))
            Tools.logging(status=True,
                          message='{} {} {}'.format(router, router_info.mfg, str(interface_list)),
                          logfile=NOCCHECK_DOWN_LOGFILE)
            Tools.logging(status=True,
                          message=str(output_list),
                          logfile=NOCCHECK_DOWN_LOGFILE)

            slack_output = ''
            stats_interface_list = []

            for output in output_list:
                print()

                if router_info.mfg == 'juniper':
                    pattern = r"Physical interface: (\S+), \S+, Physical link is Down.*Description: (.*)\n.*" \
                              r"Last flapped .* UTC \((.*) ago\)"
                elif router_info.mfg == 'cisco':
                    pattern = r"(\S+) is \S+, line protocol is down.*Description: (.*)\n.*Last link flapped (\S+)"
                else: #Nokia
                    pattern = 'Description +: +(.*)\n.*Interface +: +([1-9/a-z-]+).*\n.*Oper +State +: +.*\nLast State Change +: +([0-9/]+ +[0-9:]+)'
                matchOB = re.search(pattern, output, flags=(re.MULTILINE | re.DOTALL))

                if matchOB:
                    if router_info.mfg == 'nokia':
                        ifc_name = matchOB.group(2).lower()
                        ifc_desc = matchOB.group(1)
                        downtime_str = matchOB.group(3)
                    else:
                        ifc_name = matchOB.group(1).lower()
                        ifc_desc = matchOB.group(2)
                        downtime_str = matchOB.group(3)

                    for donw_ignore_word in donw_ignore_list:
                        if donw_ignore_word in ifc_desc:
                            print('{} {} : skip... {} is in ignore list'.format(router, ifc_name, donw_ignore_word))
                            Tools.logging(status=False,
                                          message='{} {} : skip... {} is in ignore list'.format(router, ifc_name,
                                                                                                donw_ignore_word),
                                          logfile=NOCCHECK_DOWN_LOGFILE)
                            continue

                    if router_info.mfg == 'juniper':
                        ifc_name_desc = '{} {}'.format(ifc_name, ifc_desc)
                    elif router_info.mfg == 'cisco':
                        ifc_name_desc = '{} {}'.format(Tools.make_short_interface_name(ifc_name), ifc_desc)
                    else:
                        ifc_name_desc = '{} {}'.format(ifc_name, ifc_desc)

                    if len(ifc_name_desc) > 59:
                        ifc_name_desc = ifc_name_desc[:55] + '...'

                    if router_info.mfg == 'nokia':
                        total_down_secs = (datetime.now() - datetime.strptime(downtime_str,"%m/%d/%Y %H:%M:%S")).total_seconds()
                        total_down_mins = total_down_secs/60
                        # total_down_secs = down_days*24*60 + down_hours*60 + down_mins
                        down_days = math.floor(total_down_secs/24/60/60)
                        down_hours = math.floor(total_down_secs/60/60%24)
                        down_mins = math.floor(total_down_secs/60%60)
                        down_secs = round(total_down_secs%60)

                        down_duration = f"{down_days}d {down_hours}:{down_mins}:{down_secs}" 
                        if total_down_mins <= 30:
                            print('{} {} : down time is less than 30 mins : {} ago '.format(router, ifc_name, down_duration))
                        elif total_down_mins > 30:
                            if down_days >= 1:
                                print('{} {} : down time is more 1 day+ : {} ago'.format(router, ifc_name, down_duration))
                            else:
                                print('{} {} : down time is more than 30 mins :  {} ago'.format(router, ifc_name, down_duration))

                            if 'BB:' in ifc_name_desc:
                                z_info = Tools.get_z_interface(router, ifc_name)
                                print("z_info:",z_info)
                                if z_info:
                                    if z_info.router not in self.all_router_list:
                                        print('z_router ({}) is not in up_router_list, '
                                              'not added to notification'.format(z_info.router))

                                        Tools.logging(status=True,
                                                      message='z_router ({}) is not in up_router_list, '
                                                              'not added to notification'.format(z_info.router),
                                                      logfile=NOCCHECK_DOWN_LOGFILE)

                                        continue

                                    z_interface = ' '.join([z_info.router, z_info.interface])
                                    if z_interface in graph_search_stats_interface_list:
                                        print('{} {} : z_interface is exist, '
                                              'not added to notification'.format(router, ifc_name))

                                        Tools.logging(status=True,
                                                      message='{} {} : z_interface is exist, '
                                                              'not added to notification'.format(router,
                                                                                                 ifc_name),
                                                      logfile=NOCCHECK_DOWN_LOGFILE)

                                        continue

                            slack_output += '{} ({} ago)\n'.format(ifc_name_desc, down_duration)
                            stats_interface_list.append(ifc_name)
                            graph_search_stats_interface_list.append(' '.join([router, ifc_name]))




                    elif (router_info.mfg == 'juniper' and ' ' in downtime_str) \
                            or (router_info.mfg == 'cisco' and ':' not in downtime_str):

                        print('{} {} : down time is more 1 day+ : {} ago'.format(router, ifc_name, downtime_str))
                        Tools.logging(status=False,
                                      message='{} {} : down time is more 1 day+ : {} ago'.format(router, ifc_name,
                                                                                                 downtime_str),
                                      logfile=NOCCHECK_DOWN_LOGFILE)

                    else:
                        if re.match(r"\d\d:\d\d:\d\d", downtime_str):
                            downtime = datetime.strptime(downtime_str, '%H:%M:%S')

                            if (downtime.hour == 0) and (downtime.minute < 30):
                                print('{} {} : down time is less than 30 min : {} ago'.format(router, ifc_name,
                                                                                              downtime_str))
                                Tools.logging(status=False,
                                              message='{} {} : down time is less than 30 min : {} ago'.format(
                                                  router, ifc_name, downtime_str), logfile=NOCCHECK_DOWN_LOGFILE)
                            else:
                                print('{} {} : down time is more 30 min+ : {} ago'.format(router, ifc_name,
                                                                                          downtime_str))
                                Tools.logging(status=True,
                                              message='{} {} : down time is more 30 min+ : {} ago'.format(
                                                  router, ifc_name, downtime_str), logfile=NOCCHECK_DOWN_LOGFILE)

                                if 'BB:' in ifc_name_desc:
                                    z_info = Tools.get_z_interface(router, ifc_name)

                                    if z_info:
                                        if z_info.router not in self.all_router_list:
                                            print('z_router ({}) is not in up_router_list, '
                                                  'not added to notification'.format(z_info.router))

                                            Tools.logging(status=True,
                                                          message='z_router ({}) is not in up_router_list, '
                                                                  'not added to notification'.format(z_info.router),
                                                          logfile=NOCCHECK_DOWN_LOGFILE)

                                            continue

                                        z_interface = ' '.join([z_info.router, z_info.interface])
                                        if z_interface in graph_search_stats_interface_list:
                                            print('{} {} : z_interface is exist, '
                                                  'not added to notification'.format(router, ifc_name))

                                            Tools.logging(status=True,
                                                          message='{} {} : z_interface is exist, '
                                                                  'not added to notification'.format(router,
                                                                                                     ifc_name),
                                                          logfile=NOCCHECK_DOWN_LOGFILE)

                                            continue

                                slack_output += '{} ({} ago)\n'.format(ifc_name_desc, downtime_str)
                                stats_interface_list.append(ifc_name)
                                graph_search_stats_interface_list.append(' '.join([router, ifc_name]))
                        else:
                            print(Tools.colorstring('{} : unexpected time format'.format(downtime_str), 'red'))
                            Tools.logging(status=False, message='{} : unexpected time format'.format(downtime_str),
                                          logfile=NOCCHECK_DOWN_LOGFILE)

                else:
                    print('this interface is something unusual / sub interface, satellite interface or so on')
                    Tools.logging(status=True, message='this interface is something unusual / '
                                                       'sub interface, satellite interface or so on',
                                  logfile=NOCCHECK_DOWN_LOGFILE)

            if len(stats_interface_list) > 0:
                print(Tools.colorstring(slack_output, 'yellow'))
                d = Tools.multi_stats_url({router: stats_interface_list})
                print(Tools.colorstring(d[router], 'blue'))

                fields.append({
                        "title": router,
                        "value": slack_output,
                    }
                )
                actions.append({
                        "type": "button",
                        "text": router,
                        "url": d[router],
                        "style": "danger"
                    }
                )

                graph_stats_link_list.append("<{}|{}>".format(d[router], router))

        if len(graph_search_stats_interface_list) > 0:

            print('sending slack notification')
            Tools.logging(status=True, message='sending slack notification', logfile=NOCCHECK_DOWN_LOGFILE)

            username = 'downlink_checker'
            color = 'danger'
            title_tag = ':heavy_exclamation_mark:'

            if len(graph_search_stats_interface_list) == 1:
                if not self.test:
                    msg = 'Please check. There is {} circuit 30min+ down and unmarked.'.format(
                        len(graph_search_stats_interface_list))
                else:
                    msg = 'Please check. There is {} circuit 30min+ down (include marked)'.format(
                        len(graph_search_stats_interface_list))
            else:
                if not self.test:
                    msg = 'Please check. There are {} circuits 30min+ down and unmarked.'.format(
                        len(graph_search_stats_interface_list))
                else:
                    msg = 'Please check. There are {} circuits 30min+ down (include marked)'.format(
                        len(graph_search_stats_interface_list))

            title = "{} {}".format(title_tag, msg)

            title_link = Tools.graph_search_stats_url(graph_search_stats_interface_list)

            graph_stats_link_text = ', '.join(graph_stats_link_list)

            if len(fields) > 5:

                attachments = [
                    {
                        "color": color,
                        "fallback": msg,
                        "title": title,
                        "title_link": title_link,
                        "fields": fields,
                        # "actions": actions
                    }
                ]

            else:
                fields.append({
                    "title": '** Stats URL per router (you can see both sides) **',
                    # "value": graph_stats_link_text,
                }
                )

                attachments = [
                    {
                        "color": color,
                        "fallback": msg,
                        "title": title,
                        "title_link": title_link,
                        "fields": fields,
                        "actions": actions
                    }
                ]

            Tools.send_slack_notification(SLACK_END_POINT, username, attachments) 


class OutageCheck(IfcCheck):
    def __init__(self, args, psr):

        self.investigate = args.investigate
        self.parallel = args.parallel
        self.stats = args.stats

        self.ticket = args.ticket
        self.target_interface_list = []

        self.noc144_dict = OutageCheck.get_ticketinfo_from_noc_144()
        # self.noc149_dict = OutageCheck.get_ticketinfo_from_noc_149()

        self.light = args.light
        self.clear = args.clear
        if self.clear:
            print(Tools.colorstring('do you really want to clear interface counters?', 'red'))
            if not Tools.yes_no_input():
                self.clear = False

    def get_outage_info_from_ticket(self, target_ticket):
        query = ConfigToolsDB.get_marked_interfaces_from_ticket(target_ticket)
        ticket_infos = ConfigToolsDB.search(query, listing=True)

        if not ticket_infos:
            print('Circuit related %(target_ticket)s is not found...' % locals())
        else:
            for ticket_info in ticket_infos:
                ifc_name = ticket_info.router + ' ' + ticket_info.ifc_name
                if ifc_name not in self.target_interface_list:
                    self.target_interface_list.append(ifc_name)

    def run_outagecheck(self, target_ticket):
        print('#' * 150)
        self.get_outage_info_from_ticket(target_ticket)

        print(Tools.colorstring('{} : marked interface check'.format(target_ticket), 'green'))
        self.print_interface_info()

        print()
        # print(Tools.colorstring('{} : NOC-144/149 check'.format(target_ticket), 'green'))
        print(Tools.colorstring('{} : NOC-144 check'.format(target_ticket), 'green'))

        isNOC144 = False
        # isNOC149 = False

        if target_ticket in self.noc144_dict:
            isNOC144 = True
            print(json.dumps(self.noc144_dict[target_ticket], indent=4))

        # if target_ticket in self.noc149_dict:
        #     isNOC149 = True
        #     print(json.dumps(self.noc149_dict[target_ticket], indent=4))

        # if isNOC144 and isNOC149:
        #     msg = '{} is on both NOC-144 and NOC-149. Please close ether one'.format(target_ticket)
        #     print(Tools.colorstring(msg, 'red'))

        # if not (isNOC144 or isNOC149):
        if not isNOC144:
            msg = '{} is not found on NOC-144. Is this OK ?'.format(target_ticket)
            # msg = '{} is not found on either NOC-144 or NOC-149. Is this OK ?'.format(target_ticket)
            print(Tools.colorstring(msg, 'red'))

        target_interface_dict = collections.OrderedDict()

        for target_interface in self.target_interface_list:
            router = target_interface.split()[0]
            interface = target_interface.split()[1]

            if router not in target_interface_dict:
                target_interface_dict[router] = [interface]
            else:
                target_interface_dict[router].append(interface)

        for k, v in target_interface_dict.items():
            target_interface_dict[k] = sorted(list(set(v)))

        if self.stats:
            msg = '\n{} : Stats URL'.format(target_ticket)
            print(Tools.colorstring(msg, 'green'))

            d = Tools.multi_stats_url(target_interface_dict)
            for router, url in sorted(d.items(), key=lambda x: x[0]):
                print(router + ' : ' + ' '.join(target_interface_dict[router]))
                print(Tools.colorstring(url, 'blue'))

        if self.investigate and len(self.target_interface_list) > 0:
            msg = '\n{} : Start Investigation  (Router Login) mode .....'.format(target_ticket)
            print(Tools.colorstring(msg, 'green'))

            isDown = False

            if self.parallel and len(target_interface_dict) > 1:
                with ThreadPoolExecutor(max_workers=20) as executor:
                    multi_router = []
                    multi_interface_list = []
                    for key, value in target_interface_dict.items():
                        multi_router.append(key)
                        multi_interface_list.append(value)

                        if len(multi_router) > 20:
                            print('Must be 20 or less routers on terse mode :)')
                            sys.exit()

                    res = executor.map(self.investigate_interface_terse, multi_router, multi_interface_list)

                for output in list(res):
                    print(re.sub(r'\n{3,}', '\n', output))

                    if 'down' in output.lower():
                        isDown = True

            else:
                for key, value in target_interface_dict.items():
                    output = self.investigate_interface_terse(key, value)
                    print(re.sub(r'\n{3,}', '\n', output))

                    if 'down' in output.lower():
                        isDown = True

            if not isDown:
                msg = 'There are no DOWN interfaces, outage is really ongoing?'.format(target_ticket)
                print(Tools.colorstring(msg, 'red'))

    def check_ifc_list_lastflap(self, router, interface_list, mfg):

        session = RouterSession(router, mfg)
        msg = ''
        msg += Tools.colorstring('\nChecking {} : {}\n'.format(
            router,
            ', '.join([Tools.make_short_interface_name(interface) for interface in interface_list])), 'blue')

        cmds = []
        for interface in interface_list:
            cmds.append(RouterCommand.show_ifc_lastflap_rate(interface, mfg))
            cmds.append(RouterCommand.show_ifc_lastflap_power(interface, mfg))
            cmds.append(RouterCommand.show_ifc_lastflap_error(interface, mfg))

        for response in session.call_rstrip(cmds):
            msg += '> %s : %s ' % (router, re.sub(' {2,}', ' ', response.command)) + '\n'
            msg += response.response + '\n\n'

        if self.clear:
            for interface in interface_list:
                if mfg == "cisco":
                    clear_cisco = 'clear counters ' + interface
                    msg += Tools.colorstring('trying to clear counters ({} {}).... '.format(router, interface), 'cyan')
                    tmp_output = session.session.send_command_timing(clear_cisco)
                    if '[confirm]' in tmp_output:
                        tmp_output += '\n'
                        tmp_output += session.session.send_command_timing("y")
                        msg += Tools.colorstring('clear counters may be successful', 'cyan')
                        msg += '\n'
                    else:
                        msg += Tools.colorstring('clear counters may NOT be successful', 'red')
                        msg += '\n'
                else:
                    cmds = []
                    msg += Tools.colorstring('trying to clear counters ({} {}).... \n'.format(router, interface),
                                             'cyan')
                    cmds.append(RouterCommand.show_ifc_lastflap_clear_counter(interface, mfg))
                    for response in session.call_rstrip(cmds):
                        msg += '> %s : %s ' % (router, re.sub(' {2,}', ' ', response.command)) + '\n'
                        msg += response.response + '\n\n'

            msg += Tools.colorstring('sleeping 5[sec]........', 'purple')
            time.sleep(5)
            msg += Tools.colorstring('done\n\n', 'purple')

            cmds = []
            for interface in interface_list:
                cmds.append(RouterCommand.show_ifc_lastflap_error(interface, mfg))

            for response in session.call_rstrip(cmds):
                msg += '> %s : %s ' % (router, re.sub(' {2,}', ' ', response.command)) + '\n'
                msg += response.response + '\n\n'

        session.close_session()

        return_output = ''
        for output in msg.split('\n'):
            if 'down' in output.lower():
                return_output += Tools.colorstring(output, 'yellow') + '\n'
            elif 'rate 0 bits/sec' in output:
                return_output += Tools.colorstring(output, 'yellow') + '\n'
            elif ' 0 bps ' in output:
                return_output += Tools.colorstring(output, 'yellow') + '\n'
            else:
                return_output += output + '\n'

        return return_output

    def investigate_interface_terse(self, router, interface_list):
        query = ConfigToolsDB.get_router_info(router)
        router_info = ConfigToolsDB.search(query, listing=False)

        try:
            result = self.check_ifc_list_lastflap(router, interface_list, router_info.mfg)
        except KeyboardInterrupt:
            print("pressed control-c by user")
            sys.exit()
        except:
            print('could not get interfaces information from {}'.format(router))
            result = None

        return result

    @staticmethod
    def get_ticketinfo_from_noc_144():
        noc144_url = "https://noc.gin.ntt.net/NOC/noc-issues/"
        noc144_dict = collections.OrderedDict()

        clogin = Cloginrc()
        auth = (clogin.username, clogin.password)

        querystring = {}

        try:
            response = requests.request("GET", noc144_url, auth=auth, params=querystring, timeout=5, verify=False)
        except requests.exceptions.RequestException:
            # print('timeout')
            return noc144_dict

        pattern = r"<tr bgcolor=\S+><td><a href=/NOC/noc-issues/index.php\?func=modify&id=\d+>(?P<noc144_id>\d+)</a>" \
                  r"</td>\n<td>(?P<category>.*)</td>\n<td>(?P<subject>.*)</td>\n<td>(?P<notes>.*)</td>\n" \
                  r"<td>(?P<last_modified>.*)</td>\n<td>(?P<ticket_from>.*)</td>\n<td>(?P<ticket_to>.*)</td>"

        for block in response.text.split('</tr>'):

            matchOB = re.search(pattern, block, flags=(re.MULTILINE | re.DOTALL))

            if matchOB:
                noc144_id = matchOB.group('noc144_id')
                subject = matchOB.group('subject')
                notes = matchOB.group('notes')
                last_modified = matchOB.group('last_modified')

                ticket_number = None
                m = re.search(r'\[(VNOC-\d-\d+|V-\d-\d+|GIN-\d-\d+)\]', subject)
                if m:
                    ticket_number = m.group(1)

                if ticket_number:
                    noc144_dict[ticket_number] = collections.OrderedDict()
                    noc144_dict[ticket_number]['type'] = 'NOC-144'
                    noc144_dict[ticket_number]['subject'] = subject
                    noc144_dict[ticket_number]['notes'] = notes
                    noc144_dict[ticket_number]['last_modified'] = last_modified
                else:
                    ticket_number = 'NOC144-{}'.format(noc144_id)
                    noc144_dict[ticket_number] = collections.OrderedDict()
                    noc144_dict[ticket_number]['type'] = 'NOC-144'
                    noc144_dict[ticket_number]['subject'] = subject
                    noc144_dict[ticket_number]['notes'] = notes
                    noc144_dict[ticket_number]['last_modified'] = last_modified
            else:
                pass

        return noc144_dict

    @staticmethod
    def get_ticketinfo_from_noc_149():
        noc149_url = "https://noc.gin.ntt.net/NOC/noc-issues-long/"
        noc149_dict = collections.OrderedDict()

        clogin = Cloginrc()
        auth = (clogin.username, clogin.password)

        querystring = {}

        try:
            response = requests.request("GET", noc149_url, auth=auth, params=querystring, timeout=5, verify=False)
        except requests.exceptions.RequestException:
            # print('timeout')
            return noc149_dict

        output = response.text.replace('\xa0', '')

        pattern = r"<tr bgcolor=\S+><td><a href=/NOC/noc-issues-long/index.php\?func=modify&id=\d+>(?P<noc149_id>\d+)" \
                  r"</a></td>\n<td>(?P<category>.*)</td>\n<td>(?P<subject>.*)</td>\n<td>(?P<notes>.*)</td>\n" \
                  r"<td>(?P<last_modified>.*)</td>"

        for block in output.split('</tr>'):

            matchOB = re.search(pattern, block, flags=(re.MULTILINE | re.DOTALL))

            if matchOB:
                noc149_id = matchOB.group('noc149_id')
                subject = matchOB.group('subject')
                notes = matchOB.group('notes')
                last_modified = matchOB.group('last_modified')

                ticket_number = None
                m = re.search(r'\[(VNOC-\d-\d+|V-\d-\d+|GIN-\d-\d+)\]', subject)
                if m:
                    ticket_number = m.group(1)

                if ticket_number:
                    noc149_dict[ticket_number] = collections.OrderedDict()
                    noc149_dict[ticket_number]['type'] = 'NOC-149'
                    noc149_dict[ticket_number]['subject'] = subject
                    noc149_dict[ticket_number]['notes'] = notes
                    noc149_dict[ticket_number]['last_modified'] = last_modified
                else:
                    ticket_number = 'NOC149-{}'.format(noc149_id)
                    noc149_dict[ticket_number] = collections.OrderedDict()
                    noc149_dict[ticket_number]['type'] = 'NOC-149'
                    noc149_dict[ticket_number]['subject'] = subject
                    noc149_dict[ticket_number]['notes'] = notes
                    noc149_dict[ticket_number]['last_modified'] = last_modified
            else:
                pass

        return noc149_dict


class MaintCheck(OutageCheck):
    def __init__(self, args, psr):
        self.investigate = args.investigate
        self.parallel = args.parallel
        self.stats = args.stats

        self.ticket = args.ticket
        self.target_interface_list = []

        self.noc144_dict = MaintCheck.get_ticketinfo_from_noc_144()
        # self.noc149_dict = MaintCheck.get_ticketinfo_from_noc_149()

        d = datetime.now()
        self.maint_dict = MaintCheck.get_all_maint(d.year, d.month, d.day)

        self.hhmm = d.strftime('%H%M')

        self.light = args.light
        self.clear = args.clear
        if self.clear:
            print(Tools.colorstring('do you really want to clear interface counters?', 'red'))
            if not Tools.yes_no_input():
                self.clear = False

    def run_maintcheck(self, target_ticket):
        print('#' * 150)
        self.get_outage_info_from_ticket(target_ticket)

        print(Tools.colorstring('{} : marked interface check'.format(target_ticket), 'green'))
        self.print_interface_info()

        noc_check = ''
        isNOC144 = False
        # isNOC149 = False

        if target_ticket in self.noc144_dict:
            isNOC144 = True
            noc_check += json.dumps(self.noc144_dict[target_ticket], indent=4)
            noc_check += '\n'

        # if target_ticket in self.noc149_dict:
        #     isNOC149 = True
        #     noc_check += json.dumps(self.noc149_dict[target_ticket], indent=4)
        #     noc_check += '\n'

        # if isNOC144 or isNOC149:
        if isNOC144:
            print()
            # print(Tools.colorstring('{} : NOC-144/149 check'.format(target_ticket), 'green'))
            print(Tools.colorstring('{} : NOC-144 check'.format(target_ticket), 'green'))
            print(noc_check)

        print()
        print(Tools.colorstring('{} : NOC Calendar check'.format(target_ticket), 'green'))

        if '[{}]'.format(target_ticket) in self.maint_dict:
            start_time = self.maint_dict['[{}]'.format(target_ticket)]["start_time"]
            end_time = self.maint_dict['[{}]'.format(target_ticket)]["end_time"]

            print('{}-{}'.format(start_time, end_time))
            print(self.maint_dict['[{}]'.format(target_ticket)]["subject"])

            if end_time == '0000':
                pass
            elif self.hhmm < end_time:
                pass
            else:
                msg = '{} : MW is over. This maint is really ongoing?'.format(target_ticket)
                print(Tools.colorstring(msg, 'red'))
        else:
            msg = '{} is not on Maint Cal. This maint is really ongoing?'.format(target_ticket)
            print(Tools.colorstring(msg, 'red'))

        target_interface_dict = collections.OrderedDict()

        for target_interface in self.target_interface_list:
            router = target_interface.split()[0]
            interface = target_interface.split()[1]

            if router not in target_interface_dict:
                target_interface_dict[router] = [interface]
            else:
                target_interface_dict[router].append(interface)

        for k, v in target_interface_dict.items():
            target_interface_dict[k] = sorted(list(set(v)))

        if self.stats:
            msg = '\n{} : Stats URL'.format(target_ticket)
            print(Tools.colorstring(msg, 'green'))

            d = Tools.multi_stats_url(target_interface_dict)
            for router, url in sorted(d.items(), key=lambda x: x[0]):
                print(router + ' : ' + ' '.join(target_interface_dict[router]))
                print(Tools.colorstring(url, 'blue'))

        if self.investigate and len(self.target_interface_list) > 0:
            msg = '\n{} : Start Investigation  (Router Login) mode .....'.format(target_ticket)
            print(Tools.colorstring(msg, 'green'))

            isDown = False

            if self.parallel and len(target_interface_dict) > 1:
                with ThreadPoolExecutor(max_workers=20) as executor:
                    multi_router = []
                    multi_interface_list = []
                    for key, value in target_interface_dict.items():
                        multi_router.append(key)
                        multi_interface_list.append(value)

                        if len(multi_router) > 20:
                            print('Must be 20 or less routers on terse mode :)')
                            sys.exit()

                    res = executor.map(self.investigate_interface_terse, multi_router, multi_interface_list)

                for output in list(res):
                    print(re.sub(r'\n{3,}', '\n', output))

                    if 'down' in output.lower():
                        isDown = True

            else:
                for key, value in target_interface_dict.items():
                    output = self.investigate_interface_terse(key, value)
                    print(re.sub(r'\n{3,}', '\n', output))

    @staticmethod
    def get_all_maint(year, month, day):
        maintcal_url = "https://web1.noc.gin.ntt.net/CAL/CAL-FLAT/webcalng.pl?"

        params = [
            'op=day',
            'calendar=Maintenance',
            'year=%s' % year,
            'month=%s' % month,
            'day=%s' % day,
        ]

        maintcal_url += '&'.join(params)

        clogin = Cloginrc()
        auth = (clogin.username, clogin.password)

        response = requests.request("GET", maintcal_url, auth=auth, timeout=5, verify=False)

        tmp_output = ''

        for line in response.text.split('\n'):
            if 'FONT' in line:
                tmp_output += line.strip()

        tmp_output_blocks = tmp_output.split('[Delete]')
        maint_dict = collections.OrderedDict()
        #pattern = r"(\d{4}-\d{4}).*?>.*?(\[VNOC-1-\d+\])(.*?)<"
        pattern = r"(\d{4}-\d{4}).*?>.*?(\[VNOC-\d-\d+\]|\[V-\d-\d+\]|\[GIN-\d-\d+\])(.*?)<"

        for block in tmp_output_blocks:
            match = re.search(pattern, block, flags=(re.MULTILINE | re.DOTALL))
            if match:
                start_time = match.group(1).split('-')[0]
                end_time = match.group(1).split('-')[1]
                vnoc_number = match.group(2)
                subject = '{} {}'.format(match.group(2), match.group(3))
                maint_dict[vnoc_number] = collections.OrderedDict()
                maint_dict[vnoc_number]['start_time'] = start_time
                maint_dict[vnoc_number]['end_time'] = end_time
                maint_dict[vnoc_number]['subject'] = subject

        return maint_dict


####################################################################################
def command_ifc(args, psr):
    ifc_check = IfcCheck(args, psr)

    if ifc_check.ticket:
        ifc_check.get_ticket_info()
    elif ifc_check.cids:
        ifc_check.get_cids_info()
    elif args.interface_name:
        ifc_check.get_interface_info()

    ifc_check.print_interface_info()
    ifc_check.print_target_interface_list()

    if ifc_check.stats:
        ifc_check.run_stats_mode()
    elif ifc_check.log:
        ifc_check.run_log_mode()
    elif ifc_check.investigate:
        ifc_check.start_investigation()


def command_bgp(args, psr):
    bgp_check = BgpCheck(args, psr)

    bgp_check.get_peer_info()
    bgp_check.print_target_interface_list()

    if bgp_check.log:
        bgp_check.run_log_mode()
    elif bgp_check.investigate:
        bgp_check.start_investigation()


def command_vc(args, psr):
    vc_check = VcCheck(args, psr)

    vc_check.get_vc_info()
    vc_check.print_target_interface_list()

    if vc_check.log:
        vc_check.run_log_mode()
    elif vc_check.investigate:
        vc_check.start_investigation()


def command_jchip(args, psr):
    jchip_check = JchipCheck(args, psr)
    jchip_check.get_slot_info()

    if jchip_check.log:
        jchip_check.run_log_mode()
    elif jchip_check.investigate:
        jchip_check.start_investigation()


def command_down(args, psr):

    if (args.thread < 2) or (20 < args.thread):
        print(Tools.colorstring('--thread is 2 ~ 20', 'red'))
        print(psr.format_help())
        sys.exit()

    if not args.batch:
        print(Tools.colorstring('please run this command before you use this mode.', 'green'))
        print(Tools.colorstring('pip3 install --user -U netmiko cryptography', 'red'))
        print()
        print(Tools.colorstring('This mode takes about {} minutes.'.format(int(40/args.thread)), 'green'))
        print(Tools.colorstring('do you really start this mode?', 'green'))

        if not Tools.yes_no_input():
            sys.exit()

        start_time = time.time()

    down_check = DownCheck(args, psr)
    down_check.get_target_routers()
    down_check.start_investigation()

    if not args.batch:
        print()
        elapsed_time = time.time() - start_time
        print("elapsed_time:{0}".format(elapsed_time) + "[sec]")
        Tools.logging(status=True, message="elapsed_time:{0}".format(elapsed_time) + "[sec]",
                      logfile=NOCCHECK_DOWN_LOGFILE)

    if args.notification:
        print('notification start')
        print(datetime.now().strftime("%Y/%m/%d %H:%M:%S"))
        Tools.logging(status=Tools, message='notification start')

        down_check.notification_all_in_one()

        print(datetime.now().strftime("%Y/%m/%d %H:%M:%S"))
        print('notification end')
        Tools.logging(status=Tools, message='notification end')


def command_outage(args, psr):
    outage_check = OutageCheck(args, psr)

    if outage_check.ticket:

        for ticket in outage_check.ticket.split('|'):
            outage_check.run_outagecheck(ticket)
            outage_check.target_interface_list = []

    else:
        query = ConfigToolsDB.get_outage_interfaces_from_ticket()
        outage_infos = ConfigToolsDB.search(query, listing=True)

        outage_ticket_list = []

        if outage_infos:
            for outage_info in outage_infos:
                if outage_info.noc_field:
                    if outage_info.noc_field not in outage_ticket_list:
                        outage_ticket_list.append(outage_info.noc_field)
                else:
                    print()
                    msg = '{} {} is marked as {}, but does not have Ticket number....'.format(outage_info.router,
                                                                                              outage_info.ifc_name,
                                                                                              outage_info.state)
                    print(Tools.colorstring(msg, 'red'))
                    print()

            for outage_ticket in outage_ticket_list:
                outage_check.run_outagecheck(outage_ticket)
                outage_check.target_interface_list = []
        else:
            msg = '\nThere are no circuits marked as outage\n'
            print(msg)


def command_maint(args, psr):

    maint_check = MaintCheck(args, psr)

    if maint_check.ticket:
        for ticket in maint_check.ticket.split('|'):
            maint_check.run_maintcheck(ticket)
            maint_check.target_interface_list = []

    else:
        query = ConfigToolsDB.get_maint_routers()
        maint_routers = ConfigToolsDB.search(query, listing=True)

        if maint_routers:
            print('#' * 150)
            for maint_router in maint_routers:
                msg = '{} is marked as {} on {}, still ongoing ? '.format(maint_router.router,
                                                                          maint_router.state, maint_router.noc_field)
                print(Tools.colorstring(msg, 'red'))

        query = ConfigToolsDB.get_maint_interfaces_from_ticket()
        maint_infos = ConfigToolsDB.search(query, listing=True)

        maint_ticket_list = []

        if maint_infos:
            for maint_info in maint_infos:
                if maint_info.noc_field:
                    if maint_info.noc_field not in maint_ticket_list:
                        maint_ticket_list.append(maint_info.noc_field)
                else:
                    print()
                    msg = '{} {} is marked as {}, but does not have Ticket number....'.format(maint_info.router,
                                                                                              maint_info.ifc_name,
                                                                                              maint_info.state)
                    print(Tools.colorstring(msg, 'red'))
                    print()

            for maint_ticket in maint_ticket_list:
                maint_check.run_maintcheck(maint_ticket)
                maint_check.target_interface_list = []
        else:
            msg = '\nThere are no circuits marked as maint\n'
            print(msg)


def main():
    def make_sub_command(psr, sub_cmd_name):

        if sub_cmd_name == 'ifc':
            # for serach interface
            psr.add_argument('-t', '--ticket', help='ex) GIN-xxxxx')
            psr.add_argument('-c', '--cids', help='ex) \'P1505000437|P1609003341|P0609006090|P0609006091|U032\'')
            psr.add_argument('-n', '--interface_name', help='ex) \'r00.tokyjp01.jp.bb tengige0/0/0/0\'')

            # router login mode option
            psr.add_argument('-i', '--investigate', action='store_true', help='display result of show commands')
            psr.add_argument('-d', '--detail', action='store_true', help='display commands info. use with -i')

            psr.add_argument('-p', '--parallel', action='store_true',
                             help='parallel ssh function. use with -i. There may be some bugs..\n'
                                  'updating related packages may help this........\n'
                                  + Tools.colorstring('pip3 install --user -U netmiko cryptography', 'red'))

            psr.add_argument('--clear', action='store_true', help='clear interaces statistics before investigation')

            # log analysis mode, not router login
            psr.add_argument('-l', '--log', action='store_true', help='log analysis mode, not router login')

            # only stats mode, not router login
            psr.add_argument('-s', '--stats', action="store_true", help='display stats info')

        elif sub_cmd_name == 'bgp':
            psr.add_argument('peer_ip', help='ex) 203.105.72.34 or 2001:218:2000:5000::2')

            # router login mode option
            psr.add_argument('-i', '--investigate', action='store_true', help='display result of show commands')
            psr.add_argument('-d', '--detail', action='store_true', help='display commands info. use with -i')

            psr.add_argument('-p', '--parallel', action='store_true',
                             help='parallel ssh function. use with -i. There may be some bugs..\n'
                                  'updating related packages may help this........\n'
                                  + Tools.colorstring('pip3 install --user -U netmiko cryptography', 'red'))

            # log analysis mode, not router login
            psr.add_argument('-l', '--log', action='store_true', help='log analysis mode, not router login')

        elif sub_cmd_name == 'vc':
            psr.add_argument('vcid', help='ex) VC-207 or \'VC-207|VC-209\'')

            # router login mode option
            psr.add_argument('-i', '--investigate', action='store_true', help='display result of show commands')
            psr.add_argument('-d', '--detail', action='store_true', help='display commands info. use with -i')

            psr.add_argument('-p', '--parallel', action='store_true',
                             help='parallel ssh function. use with -i. There may be some bugs..\n'
                                  'updating related packages may help this........\n'
                                  + Tools.colorstring('pip3 install --user -U netmiko cryptography', 'red'))

            # log analysis mode, not router login
            psr.add_argument('-l', '--log', action='store_true', help='log analysis mode, not router login')

        elif sub_cmd_name == 'jchip':
            psr.add_argument('-r', '--router', help='ex) r20.sttlwa01.us.bb', required=True)
            psr.add_argument('-s', '--slot', help='ex) 0', required=True)

            # router login mode option
            psr.add_argument('-i', '--investigate', action='store_true', help='display result of show commands')
            psr.add_argument('-d', '--detail', action='store_true', help='display commands info. use with -i')

            # log analysis mode, not router login
            psr.add_argument('-l', '--log', action='store_true', help='log analysis mode, not router login')

        elif sub_cmd_name == 'down':
            psr.add_argument('-c', '--country', type=str, help='filter devices by country (ex: us or \'us|jp\')')

            psr.add_argument('--include', type=str, help='BB:, akamai')
            psr.add_argument('--exclude', type=str, help='BL:, akamai, \'BL:|akamai\', \'BL:|akamai|facebook\'')

            psr.add_argument('-a', '--anoc', action='store_true',
                             help='for anoc. same as -c \'{}\''.format(Tools.get_anoc_coutry_fiter()))
            psr.add_argument('-b', '--batch', action='store_true',
                             help='batch mode, display only output')

            psr.add_argument('--notification', action='store_true',
                             help='notification mode, notification to slack if more than 30 min down')

            psr.add_argument('--thread', type=int, default=2, help='please choose 2 ~ 20')

            psr.add_argument('--test', action='store_true', help='also check OUTAGE/MAINT/FAILURE/IGNORE')

        # elif sub_cmd_name == 'outage' or sub_cmd_name == 'maint' or sub_cmd_name == 'marked':
        elif sub_cmd_name == 'outage' or sub_cmd_name == 'maint':
            psr.add_argument('-i', '--investigate', action='store_true', help='display result of show commands')
            psr.add_argument('-p', '--parallel', action='store_true',
                             help='parallel ssh function. use with -i. There may be some bugs..\n'
                                  'updating related packages may help this........\n'
                                  + Tools.colorstring('pip3 install --user -U netmiko cryptography', 'red'))
            psr.add_argument('-s', '--stats', action="store_true", help='display stats info')
            psr.add_argument('-t', '--ticket', type=str, help='ex) GIN-xxxxx')
            psr.add_argument('--clear', action='store_true', help='clear interaces statistics before investigation')
            psr.add_argument('--light', action='store_true', help='show light level, using with -i')

        psr.add_argument('-v', '--version', action='version', version='%(prog)s ' + VERSION)

    Tools.logging(status=True, message=' '.join(sys.argv) + ' / start', logfile=NOCCHECK_LOGFILE)

    # main command
    parser = argparse.ArgumentParser(description='check script for investigating '
                                                 'ifc/bgp/vc/jchip/down/outage/maint')
    subparsers = parser.add_subparsers()

    # ifc command
    parser_ifc = subparsers.add_parser('ifc', help='see `ifc -h`')
    make_sub_command(parser_ifc, 'ifc')
    parser_ifc.set_defaults(fn=command_ifc)

    # bgp command
    parser_bgp = subparsers.add_parser('bgp', help='see `bgp -h`')
    make_sub_command(parser_bgp, 'bgp')
    parser_bgp.set_defaults(fn=command_bgp)

    # vc command
    parser_vc = subparsers.add_parser('vc', help='see `vc -h`')
    make_sub_command(parser_vc, 'vc')
    parser_vc.set_defaults(fn=command_vc)

    # jchip command
    parser_jchip = subparsers.add_parser('jchip', help='see `jchip -h`')
    make_sub_command(parser_jchip, 'jchip')
    parser_jchip.set_defaults(fn=command_jchip)

    # down command
    parser_down = subparsers.add_parser('down', help='see `down -h`')
    make_sub_command(parser_down, 'down')
    parser_down.set_defaults(fn=command_down)

    # outage command
    parser_outage = subparsers.add_parser('outage', help='see `outage -h`')
    make_sub_command(parser_outage, 'outage')
    parser_outage.set_defaults(fn=command_outage)

    # maint command
    parser_maint = subparsers.add_parser('maint', help='see `maint -h`')
    make_sub_command(parser_maint, 'maint')
    parser_maint.set_defaults(fn=command_maint)

    args = parser.parse_args()

    if hasattr(args, 'fn'):
        if args.fn == command_ifc:
            args.fn(args, parser_ifc)
        elif args.fn == command_bgp:
            args.fn(args, parser_bgp)
        elif args.fn == command_vc:
            args.fn(args, parser_vc)
        elif args.fn == command_jchip:
            args.fn(args, parser_jchip)
        elif args.fn == command_down:
            Tools.logging(status=True, message=' '.join(sys.argv) + ' / start', logfile=NOCCHECK_DOWN_LOGFILE)
            args.fn(args, parser_down)
            Tools.logging(status=True, message=' '.join(sys.argv) + ' / end', logfile=NOCCHECK_DOWN_LOGFILE)
        elif args.fn == command_outage:
            args.fn(args, parser_outage)
        elif args.fn == command_maint:
            args.fn(args, parser_maint)

    else:
        print(parser.format_help())

    Tools.logging(status=True, message=' '.join(sys.argv) + ' / end', logfile=NOCCHECK_LOGFILE)

if __name__ == '__main__':
    main()
