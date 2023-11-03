#! /opt/gums/bin/python2

import re
import csv
import os
import sys
import argparse
from operator import itemgetter, attrgetter
import psycopg2
from psycopg2.extras import NamedTupleCursor
from pysnmp.entity.rfc3413.oneliner import cmdgen
from datetime import datetime

def get_smus(router):
    path = os.path.join('/home/rancid/ntt/configs/', router)
    smus = []
    try:
        with open(path) as f:
            start = 0
            for line in f:
                if not start and 'Node 0/R' in line:
                    start = 1
                    continue
                if start and 'Node' in line:
                    break
                if start and 'CSC' in line:
                    if 'Boot Image' not in line:
                        smus.append(line.replace('!       disk0:', '').replace('    [Host]', '').replace('!        ', '').replace('\n', '').strip() )
        return smus
    except EnvironmentError:
        return []

def get_conf_sizes(router):
        if router:
                try:
                    cfilesize = (os.path.getsize(os.path.join('/srv/tftp/', router + '-confg')))
                except:
                    raise
                if ( cfilesize > 999999 ):
                    cfilesize = str('{:.0f}'.format(cfilesize / float(1<<20)) +" MB")
                else:
                    cfilesize = str('{:.0f}'.format(cfilesize/float(1<<10)) +" KB")
                return cfilesize

# print rows
def print_header():
    print('region\tver\tsmu\trouter\t\t\tuptime (ddd:hh:mm:ss)\t\t#cust\t#vcix\tconfig size')
    print('-------\t------\t----\t--------------------\t---------------------\t\t-----\t-----\t-----------')

def build_device_info():

    conn = psycopg2.connect("dbname = 'cfgtools'")
    cursor = conn.cursor(cursor_factory=psycopg2.extras.NamedTupleCursor)
    query = "SELECT d.device_name||'.gin.ntt.net' as fqdn, d.os_rev, d.snmp_ro, cr.comm_region_descr AS region, (select count(*) as customercount from interfaces WHERE router = d.device_name AND intf_type NOT IN ('UR', 'UU', 'BO', 'BB', 'BP') AND name NOT SIMILAR TO '%.(bb|sa|to) ?%' AND ifc_name NOT SIMILAR TO '(lo|loopback)%' AND state ='up') AS customercount, (SELECT count(*) AS vcix FROM interfaces WHERE router = d.device_name AND intf_type IN ('BD', 'BN') AND state = 'up' AND cust_id IS NOT NULL) AS vcix FROM ct_devices d LEFT JOIN ct_devices_state s ON d.device_state_id = s.state_id JOIN ct_comm_msa m ON m.comm_msa_id = d.comm_msa_id JOIN ct_comm_country c ON c.comm_country_id = m.comm_country_id JOIN ct_comm_region cr ON cr.comm_region_id = c.comm_region_id WHERE config_dir = 'bb' AND os_name_id = 2 AND device_state NOT IN ('shutdown', 'down') AND device_name LIKE 'r%' AND device_name NOT LIKE '%test%' ORDER BY (split_part(device_name, '.', 2))"
    cursor.execute(query)

    rows = cursor.fetchall()

    cursor.close()
    conn.close()


    result = []
    for row in rows:
        # skip if no snmp community
        if row.snmp_ro == None:
            continue

        cmdGen = cmdgen.CommandGenerator()

        errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
            cmdgen.CommunityData(row.snmp_ro),
            cmdgen.UdpTransportTarget((row.fqdn, 161),timeout=2,retries=5),
            #cmdgen.Udp6TransportTarget((row[0], 161),timeout=2,retries=5),
            cmdgen.MibVariable('.1.3.6.1.6.3.10.2.1.3.0')
        )

        # Check for errors and print out results
        value = 0
        import pprint
        pp = pprint.PrettyPrinter(indent=4)
        if errorStatus:
            print('%s at %s querying %s' % (
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex)-1] or '?', row.fqdn
                )
            )
        else:
            for name, val in varBinds:
                value = int( val.prettyPrint() )

            m, s = divmod(value, 60)
            h, m = divmod(m, 60)
            d, h = divmod(h, 24)
            hdur = "%03d:%02d:%02d:%02d" % (d, h, m, s)
            region = row.region.replace('ASIA', 'AP').replace('EUROPE', 'EU')
            smu_list = []
            smu_list = get_smus(row.fqdn)
            size = get_conf_sizes(row.fqdn.replace('.gin.ntt.net', ''))

            result.append([region, row.os_rev, str(len(smu_list)).zfill(2), row.fqdn.replace('.gin.ntt.net', ''), hdur, '\t',row.customercount, row.vcix, size])
            #pprint.pprint(smu_list)

    # sort by smu number (asc) then uptime (desc), then version (asc)
    # doing this method because .sort is 'stable'
    result.sort(key=itemgetter(2))
    result.sort(key=itemgetter(4), reverse=True)
    result.sort(key=itemgetter(1))

    for line in result:
      print '\t'.join(map(str, line))

def main():
    time = datetime.now()
    date_time = time.strftime("%m%d%Y-%H%M")

    parser = argparse.ArgumentParser(description ='Cisco uptime, customer count and config size')
    parser.add_argument('-c', '--csv', help='export to csv', action='store_true')
    args = parser.parse_args()

    if args.csv:
        os.chdir(os.path.expanduser('~'))
        orig_stdout = sys.stdout
        logfile = date_time + 'uptime.log'
        csvfile = date_time + 'uptime.csv'
        with open ( logfile, 'w+' ) as txtlog:
            sys.stdout = txtlog
            print_header()
            build_device_info()
            sys.stdout = orig_stdout
        
        with open ( logfile, 'r') as txt_in, open(csvfile, 'w+') as csv_out:
            txt_in_data = csv.reader(txt_in, delimiter='\t')
            csv_out_data = csv.writer(csv_out)
        
            for row in txt_in_data:
               csv_out_data.writerow(row)

        print('Filename is: ' + csvfile )
    else:
        print_header()
        build_device_info()

if __name__ == '__main__':
    main()
