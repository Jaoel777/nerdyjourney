#!/opt/gums/bin/python3.6

# Script by Joseph Nicholson (josephn@gin.ntt.net) and
# Troy Boudreau ( tboudreau@us.ntt.net) - Version 1.0 December 2017
# Usage - ./noc_search.py <search type> <value>
# Current Version 2.1.2 - June 14, 2021

# Import Statments
import argparse
import csv
import ipaddress
import json
import os
import psycopg2 as db
import re
import requests
import subprocess
import sys

# Functions after this line fetch the search results, format it,
# and output it to the screen


# Grab results from database


def grab_output(query, value2):
    table = []
    try:
        cur = conn.cursor()
        cur.execute((query), (value2))
        table = cur.fetchall()
        cur.close()
    except db.DatabaseError as ex:
        print()
        print('#' * 80)
        print('{}'.format(ex))
        print('#' * 80)
        sys.exit(1)
    return table

# Format results for display


def output_table(data, headers=None):
    result = ""
    rowsizes = []
    if headers:
        for count, h in enumerate(headers):
            rowsizes.append(len(h) + 2)
    else:
        # hack to get around when we do not want a table header (oob notes)
        rowsizes.append(1)
    for d in data:
        for count, rowdata in enumerate(d):
            if rowdata is not None:
                rowsizes[count] = max(rowsizes[count], len(str(rowdata)))
    if headers:
        for count, i in enumerate(headers):
            if count != 0:
                result += "  "
            result += "{:{size}s}".format(i, size=rowsizes[count])
        result += "\n"
        for count, i in enumerate(rowsizes):
            if count != 0:
                result += "  "
            result += "{}".format("-" * i, size=rowsizes[count])
        result += "\n"
    for d in data:
        for count, i in enumerate(d):
            if count != 0:
                result += "  "
            if i is None:
                result += "{:{size}s}".format("", size=rowsizes[count])
            else:
                result += "{:{size}s}".format(str(i), size=rowsizes[count])
        result += "\n"
    return result

# Determine where to output results - screen or csv file


def do_output(output, headers):
    try:
        if args.csv is None:
            do_table(output, headers)
        else:
            headers = [item.replace(" ", "_") for item in headers]
            do_csv(output, headers)
            print("\n" + "Results have been saved to " + args.csv + "\n")
    except (BrokenPipeError, IOError):
        pass

# Output results to the screen


def do_table(table, headers):
    if table:
        print("\n{}\n".format(output_table(table, headers)))
    else:
        not_gin()


def do_table_endless(table):
    if table:
        table.sort()
        print("{}".format(table[0][0] + ' - ' + table[0][1] + ' => CID: ' + value))
    else:
        not_gin()


def do_table_endless_check_4_warn(table):
    if table:
        table.sort()
        print("{}".format(table[0][0] + ' - ' + table[0][1]))
    else:
        not_gin()


def do_table_usid_endless(table):
    if table:
        table.sort()
        print("{}".format(table[0][0] + ' ' + table[0][1] + ' - ' + table[0][2] + ' => USID: ' + value))
    else:
        not_gin()

# Output results to the csv file


def do_csv(table, headers):
    csv_data = [table]
    csvfile = args.csv
    if table:
        with open(csvfile, 'a', newline='') as csv_file:
            writer = csv.writer(csv_file, delimiter=',')
            for line in csv_data:
                writer.writerow(headers)
                writer.writerows(line)
    else:
        not_gin()

# Functions after this point are for getting the trail hops via gums-dwdm api.


# Classes
class Cloginrc:
    def __init__(self, file="~/.cloginrc"):
        self.file = os.path.expanduser(file)
        self._parse()

    def _parse(self):
        with open(self.file, 'r') as f:
            for line in f:
                if re.match(r"add user\s+", line):
                    self.username = line.split()[-1]
                elif re.match(r"add password\s+\*", line):
                    self.password = line.split()[-2][1:-1]
                    break

# L100s the device/shelf/slot/subslot must match to be on the same
# module/connected port


def compare_ports(port_a, port_b):
    if (port_a['device_name'] == port_b['device_name'] and
        port_a['shelf_name'] == port_b['shelf_name'] and
        port_a['slot_name'] == port_b['slot_name'] and
       port_a['subslot_name'] == port_b['subslot_name']):
        return True
    return False


# Gets client side A port info
def get_client_a(line, channel_num):

    #  Get A side router and client info

    if line['port_a']['port_name'] == 'E1' and channel_num == 0:
        client_a = 'C1'
    elif line['port_a']['port_name'] == 'E1' and channel_num == 1:
        client_a = 'C2'
    elif line['port_a']['port_name'] == 'E2' and channel_num == 0:
        client_a = 'C3'
    elif line['port_a']['port_name'] == 'E2' and channel_num == 1:
        client_a = 'C4'

    client_a_side = ("{} {}/{}/{}/{}".format(
        line['port_a']['device_name'],
        line['port_a']['shelf_name'],
        line['port_a']['slot_name'],
        line['port_a']['subslot_name'],
        client_a))

    device_name = line['port_a']['device_name']
    shelf_name = line['port_a']['shelf_name']
    slot_name = line['port_a']['slot_name']
    subslot_name = line['port_a']['subslot_name']

    address = (db + 'optical/node/' + device_name + '/shelf/' + shelf_name +
               '/slot/' + slot_name + '/subslot/' + subslot_name + '/port/' + client_a + '/link')

    obj2 = json.loads(requests.get(address, auth=(Cloginrc().username, Cloginrc().password)).content)
    if not obj2 or ('element' in obj2 and obj2['element'] is None):
        client_hop_a = '\n' + client_a_side + '\33[33m does not have an optical-router configuration.\033[0m' + '\n'

    else:
        for lines in obj2:
            router = lines['remote_device_name'] + ' ' + lines['remote_port_name']

        client_hop_a = router + ' <-> ' + client_a_side

    return client_hop_a


# Gets client side Z port info
def get_client_z(line, channel_num):

    #  Get Z side router and client info

    if line['port_z']['port_name'] == 'E1' and channel_num == 0:
        client_z = 'C1'
    elif line['port_z']['port_name'] == 'E1' and channel_num == 1:
        client_z = 'C2'
    elif line['port_z']['port_name'] == 'E2' and channel_num == 0:
        client_z = 'C3'
    elif line['port_z']['port_name'] == 'E2' and channel_num == 1:
        client_z = 'C4'

    client_z_side = ("{} {}/{}/{}/{}".format(
        line['port_z']['device_name'],
        line['port_z']['shelf_name'],
        line['port_z']['slot_name'],
        line['port_z']['subslot_name'],
        client_z))

    device_name = line['port_z']['device_name']
    shelf_name = line['port_z']['shelf_name']
    slot_name = line['port_z']['slot_name']
    subslot_name = line['port_z']['subslot_name']

    address = (db + 'optical/node/' + device_name + '/shelf/' + shelf_name +
               '/slot/' + slot_name + '/subslot/' + subslot_name + '/port/' + client_z + '/link')

    obj2 = json.loads(requests.get(address, auth=(Cloginrc().username, Cloginrc().password)).content)

    if not obj2 or ('element' in obj2 and obj2['element'] is None):
        client_hop_z = '\n' + client_z_side + '\33[33m does not have an optical-router configuration.\033[0m' + '\n'

    else:
        for lines in obj2:
            router = lines['remote_device_name'] + ' ' + lines['remote_port_name']

        client_hop_z = client_z_side + ' <-> ' + router

    return client_hop_z


# Gets and prints hops
def get_hops(path, line, channel_num):

    print(get_client_a(line, channel_num))

    last_p = line['port_a']
    for hop in line['paths'][path]['hops']:
        # store the hops in order, then check and change
        # order if required
        ordered_hop = (hop['port_a'], hop['port_b'])

        if compare_ports(last_p, hop['port_b']):
            ordered_hop = ordered_hop[::-1]
        last_p = ordered_hop[1]

        # hops should be printed as pairs, as that indicates where there
        # are fiber links.  hops are connected together but modules
        # which are device/shelf/slot/subslot
        if ordered_hop[0]['port_name'] in ('E1', 'E2') and ordered_hop[1]['port_name'] in ('E1', 'E2'):

            device_name = ordered_hop[0]['device_name']
            shelf_name = ordered_hop[0]['shelf_name']
            slot_name = ordered_hop[0]['slot_name']
            subslot_name = ordered_hop[0]['subslot_name']
            port_name = ordered_hop[0]['port_name']

            vendor_list = []

            address = (db + 'optical/node/' + device_name + '/shelf/' + shelf_name +
                       '/slot/' + slot_name + '/subslot/' + subslot_name + '/port/' + port_name + '/link')

            obj3 = json.loads(requests.get(address, auth=(Cloginrc().username, Cloginrc().password)).content)

            if not obj3[0]['circuits']:
                dark_fiber_trail = "\33[33mThere is no Dark Fiber information in the database.\033[0m"
            else:
                for value in obj3[0]['circuits']:
                    vendor_list.append(value['vendor'] + ' ' + value['cid'])
                dark_fiber_trail = '/'.join(vendor_list)

            try:
                trail = ("{} {}/{}/{}/{} <- {} -> {} {}/{}/{}/{}".format(
                    ordered_hop[0]['device_name'],
                    ordered_hop[0]['shelf_name'],
                    ordered_hop[0]['slot_name'],
                    ordered_hop[0]['subslot_name'],
                    ordered_hop[0]['port_name'],

                    dark_fiber_trail,

                    ordered_hop[1]['device_name'],
                    ordered_hop[1]['shelf_name'],
                    ordered_hop[1]['slot_name'],
                    ordered_hop[1]['subslot_name'],
                    ordered_hop[1]['port_name']
                ))
                print(trail)
            except IndexError:
                trail = ("{} {}/{}/{}/{} <- Check DLR for DF info -> {} {}/{}/{}/{}".format(
                    ordered_hop[0]['device_name'],
                    ordered_hop[0]['shelf_name'],
                    ordered_hop[0]['slot_name'],
                    ordered_hop[0]['subslot_name'],
                    ordered_hop[0]['port_name'],

                    ordered_hop[1]['device_name'],
                    ordered_hop[1]['shelf_name'],
                    ordered_hop[1]['slot_name'],
                    ordered_hop[1]['subslot_name'],
                    ordered_hop[1]['port_name']
                ))
                print(trail)
        else:
            trail = ("{} {}/{}/{}/{} <-> {} {}/{}/{}/{}".format(
                ordered_hop[0]['device_name'],
                ordered_hop[0]['shelf_name'],
                ordered_hop[0]['slot_name'],
                ordered_hop[0]['subslot_name'],
                ordered_hop[0]['port_name'],

                ordered_hop[1]['device_name'],
                ordered_hop[1]['shelf_name'],
                ordered_hop[1]['slot_name'],
                ordered_hop[1]['subslot_name'],
                ordered_hop[1]['port_name']
            ))
            print(trail)

    print(get_client_z(line, channel_num))


# Functions after this line provide the search parameters for cfgtools

# Peer Search Section

# Get ASN Info - Uses asn as value


def get_asn(asn):
    return grab_output("SELECT p.asn, p.peer_descr, d.device_name, p.ip_addr, pg.peergroup_name, p.route_set, \
        pt.peertype_name, aut.as_macro, aut.as6_macro, pi.metric, ps.peer_state \
        FROM ct_peers p \
        JOIN ct_ifcs i on p.ifc_id = i.ifc_id \
        JOIN ct_devices d on i.device_id = d.device_id \
        LEFT JOIN ct_proto_isis pi on i.ifc_id = pi.ifc_id \
        LEFT JOIN ct_peergroups pg on p.peergroup_id = pg.peergroup_id \
        LEFT JOIN ct_peers_peertype pt on p.peertype_id = pt.peertype_id \
        LEFT JOIN ct_peers_state ps on p.peer_state_id = ps.peer_state_id \
        LEFT JOIN autnum aut on p.asn = aut.asn \
        WHERE p.asn = (%s) \
        ORDER BY d.device_name, p.ip_addr;", (asn,))


# Get ASN Info - Uses AS description as value


def get_asn_descr(descr):
    return grab_output("SELECT p.asn, p.description, p.router, p.ip_addr, p.peergroup, p.route_set, p.peertype, \
        aut.as_macro, aut.as6_macro, p.state \
        FROM peers p \
        LEFT JOIN autnum aut on p.asn = aut.asn \
        WHERE p.description ~* (%s) \
        ORDER BY p.router, p.ip_addr;", (descr,))


# Get ASN Info - Uses AS Set as value


def get_bgp_set(bgpset):
    return grab_output("SELECT p.asn, peer_descr, d.device_name as router, p.ip_addr, pg.peergroup_name, p.route_set,\
        pt.peertype_name, aut.as_macro, aut.as6_macro, ps.peer_state \
        FROM ct_peers p \
        LEFT JOIN autnum aut on p.asn = aut.asn \
        LEFT JOIN ct_ifcs i on p.ifc_id = i.ifc_id \
        JOIN ct_devices d on d.device_id = i.device_id \
        JOIN ct_peergroups pg ON p.peergroup_id = pg.peergroup_id \
        JOIN ct_peers_peertype pt on p.peertype_id = pt.peertype_id \
        JOIN ct_peers_state ps on p.peer_state_id = ps.peer_state_id \
        WHERE aut.as_macro ~* (%s) or aut.as6_macro ~* (%s) or p.route_set ~* (%s) \
        ORDER BY router, p.ip_addr;", (bgpset, bgpset, bgpset,))


# Get AS Macro Info from Autnum


def get_asn_macro(asn):
    return grab_output("SELECT asn, name, as_macro, pfx_count, allow_specifics, as6_macro, irr6_count, \
        allow6_specifics, irr_srcs \
        FROM autnum \
        WHERE asn = (%s);", (asn,))


# Get Peer Contact Info - Uses asn as value


def get_peerc(asn):
    return grab_output("SELECT name, asn, nocemail, peeremail, tpoc1email \
        FROM pcontact \
        WHERE asn = (%s);", (asn,))


# Get Peers by peergroup or route set name


def get_peergroup(peerg):
    return grab_output("SELECT asn, description, router, ip_addr, peergroup, route_set, state \
        FROM peers \
        WHERE peergroup ~* (%s) or route_set ~* (%s) \
        ORDER BY asn, router, ip_addr;", (peerg, peerg,))


# Get Peer Info by IP - Uses peerip as value


def get_peerip(peerip):
    return grab_output("SELECT p.asn, peer_descr, d.device_name as router, p.ip_addr, pg.peergroup_name, \
        p.route_set, pt.peertype_name, aut.as_macro, aut.as6_macro, ps.peer_state \
        FROM ct_peers p \
        LEFT JOIN autnum aut on p.asn = aut.asn \
        LEFT JOIN ct_ifcs i on p.ifc_id = i.ifc_id \
        JOIN ct_devices d on d.device_id = i.device_id \
        JOIN ct_peergroups pg ON p.peergroup_id = pg.peergroup_id \
        JOIN ct_peers_peertype pt on p.peertype_id = pt.peertype_id \
        JOIN ct_peers_state ps on p.peer_state_id = ps.peer_state_id \
        WHERE p.ip_addr = (%s) \
        ORDER BY router, p.ip_addr;", (peerip,))


# Circuit Search Section

# Get Circuit ID Info - Uses cid as value


def get_circuit(cid):
    return grab_output("SELECT concat(device_name, ' ', i.ifc_name) as router, \
        regexp_replace(regexp_replace(regexp_replace(regexp_replace(i.ifc_descr, \
        '(\\d{1,})-(\\d{1,})-(\\d{1,})', '\\1/\\2/\\3'), 'xe-(\\d{1,})/(\\d{1,})/(\\d{1,})-(\\d{1,})-(\\d{1,})', \
        'tengige\\1/\\2/\\3/\\4/\\5'), 'ce-(\\d{1,})/(\\d{1,})/(\\d{1,})-(\\d{1,})', 'hundredgige\\1/\\2/\\3/\\4'), \
        'ce-(\\d{1,})/(\\d{1,})/(\\d{1,})', 'et-\\1/\\2/\\3'), trim(leading ' ' from \
        concat(ifc_descr_type, ':', ' ', v.name, ' ', i.cid, ' ', i.ifc_comment)) as description, \
        i.cust_id, i2.ifc_name, cis.ifc_state \
        FROM ct_ifcs i \
        JOIN ct_devices d on d.device_id = i.device_id \
        JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id \
        JOIN ct_ifcs_descr_type t ON i.ifc_descr_type_id = t.ifc_descr_type_id \
        LEFT JOIN ct_proto_proto_agg pa ON i.ifc_id = pa.ifc_id \
        LEFT JOIN ct_ifcs i2 on pa.agg_ifc_id = i2.ifc_id \
        LEFT JOIN ct_vendor v ON i.telco_id = v.vendor_id \
        WHERE i.cust_id ~* (%s) or i.ifc_comment ~* (%s) or i.cid ~* (%s) or abbr ~* (%s) \
        ORDER BY router;", (cid, cid, cid, cid))


def get_circuit_quit(cid):
    return grab_output("SELECT concat(device_name, ' ', i.ifc_name) as router, \
        regexp_replace(regexp_replace(regexp_replace(regexp_replace(i.ifc_descr, \
        '(\\d{1,})-(\\d{1,})-(\\d{1,})', '\\1/\\2/\\3'), 'xe-(\\d{1,})/(\\d{1,})/(\\d{1,})-(\\d{1,})-(\\d{1,})', \
        'tengige\\1/\\2/\\3/\\4/\\5'), 'ce-(\\d{1,})/(\\d{1,})/(\\d{1,})-(\\d{1,})', 'hundredgige\\1/\\2/\\3/\\4'), \
        'ce-(\\d{1,})/(\\d{1,})/(\\d{1,})', 'et-\\1/\\2/\\3'), trim(leading ' ' from \
        concat(ifc_descr_type, ':', ' ', v.name, ' ', i.cid, ' ', i.ifc_comment)) as description, \
        i.cust_id, pa.agg_ifc_id, cis.ifc_state \
        FROM ct_ifcs i \
        JOIN ct_devices d on d.device_id = i.device_id \
        JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id \
        JOIN ct_ifcs_descr_type t ON i.ifc_descr_type_id = t.ifc_descr_type_id \
        LEFT JOIN ct_proto_proto_agg pa ON i.ifc_id = pa.ifc_id \
        LEFT JOIN ct_vendor v ON i.telco_id = v.vendor_id \
        WHERE i.cid ~* (%s) or i.ifc_comment ~* (%s) ORDER BY router;", (cid, cid))


def get_bundle(bundle_cid):
    return grab_output("SELECT device_name as router, i2.ifc_name, trim(leading ' ' from concat(ifc_descr_type, ' ', \
        i2.ifc_descr, ' ', '-', ' ', abbr, ' ', i2.cid, ' ', i2.ifc_comment)) AS description, i2.cust_id, ipv4, \
        ipv6, i2.bps_limit_in, i2.bps_limit_out, cis.ifc_state as state, \
        round(ss.capacity / (1000 * 1000 * 1000)::DECIMAL, 2) AS bw, i.noc_field \
        FROM ct_ifcs i \
        JOIN ct_proto_proto_agg pa ON i.ifc_id = pa.ifc_id \
        JOIN ct_ifcs i2 on pa.agg_ifc_id = i2.ifc_id \
        JOIN ct_devices d on d.device_id = i.device_id \
        LEFT JOIN ct_proto_ipv4 v4 on v4.ifc_id = i2.ifc_id and isprimary \
        LEFT JOIN ct_proto_ipv6 v6 on v6.ifc_id = i2.ifc_id \
        JOIN ct_ifcs_state cis ON cis.ifc_state_id = i2.ifc_state_id \
        LEFT JOIN ct_vendor v ON v.vendor_id = i.telco_id \
        JOIN ct_ifcs_descr_type t ON i.ifc_descr_type_id = t.ifc_descr_type_id \
        JOIN ct_snmp_speed ss ON i2.ifc_id = ss.ifc_id \
        WHERE i.cust_id ~* (%s) or i.cid ~* (%s) or i.ifc_comment ~* (%s);", (bundle_cid, bundle_cid, bundle_cid,))


def get_bundle_bw(bw):
    return grab_output("SELECT device_name as router, i2.ifc_name, trim(leading ' ' from concat(ifc_descr_type, ' ', \
        i2.ifc_descr, ' ', '-', ' ', abbr, ' ', i2.cid, ' ', i2.ifc_comment)) AS description, i2.cust_id, ipv4, \
        ipv6, i2.bps_limit_in, i2.bps_limit_out, cis.ifc_state as state, \
        round(ss.capacity / (1000 * 1000 * 1000)::DECIMAL, 2) AS bw, i.noc_field \
        FROM ct_ifcs i \
        JOIN ct_proto_proto_agg pa ON i.ifc_id = pa.ifc_id \
        JOIN ct_ifcs i2 on pa.agg_ifc_id = i2.ifc_id \
        JOIN ct_devices d on d.device_id = i.device_id \
        LEFT JOIN ct_proto_ipv4 v4 on v4.ifc_id = i2.ifc_id and isprimary \
        LEFT JOIN ct_proto_ipv6 v6 on v6.ifc_id = i2.ifc_id \
        JOIN ct_ifcs_state cis ON cis.ifc_state_id = i2.ifc_state_id \
        LEFT JOIN ct_vendor v ON v.vendor_id = i.telco_id \
        JOIN ct_ifcs_descr_type t ON i.ifc_descr_type_id = t.ifc_descr_type_id \
        JOIN ct_snmp_speed ss ON i2.ifc_id = ss.ifc_id \
        WHERE round(ss.capacity / (1000 * 1000 * 1000)::DECIMAL, 2) >= (%s);", (bw, ))


def get_bundle_bb(cid):
    return grab_output("SELECT concat(device_name, ' ', i2.ifc_name) as router, \
        regexp_replace(regexp_replace(i2.ifc_descr, 'ae-(\\d{1,})', 'ae\\1'), 'be-(\\d{1,})', 'be\\1'), \
        ipv4, ipv6, cis.ifc_state as state, round(ss.capacity / (1000 * 1000 * 1000)::DECIMAL, 2) AS bw \
        FROM ct_ifcs i \
        JOIN ct_proto_proto_agg pa ON i.ifc_id = pa.ifc_id \
        JOIN ct_ifcs i2 on pa.agg_ifc_id = i2.ifc_id \
        JOIN ct_devices d on d.device_id = i.device_id \
        LEFT JOIN ct_proto_ipv4 v4 on v4.ifc_id = i2.ifc_id and isprimary \
        LEFT JOIN ct_proto_ipv6 v6 on v6.ifc_id = i2.ifc_id \
        JOIN ct_ifcs_state cis ON cis.ifc_state_id = i2.ifc_state_id \
        LEFT JOIN ct_vendor v ON v.vendor_id = i.telco_id \
        JOIN ct_ifcs_descr_type t ON i.ifc_descr_type_id = t.ifc_descr_type_id \
        JOIN ct_snmp_speed ss ON i2.ifc_id = ss.ifc_id \
        WHERE i.cust_id ~* (%s) or i.cid ~* (%s) or i.ifc_comment ~* (%s) LIMIT 1;", (cid, cid, cid,))


def get_check_4_warn(cid):
    return grab_output("SELECT concat(device_name, ' ', i.ifc_name) as router, \
        regexp_replace(regexp_replace(regexp_replace(regexp_replace(i.ifc_descr, \
        '(\\d{1,})-(\\d{1,})-(\\d{1,})', '\\1/\\2/\\3'), 'xe-(\\d{1,})/(\\d{1,})/(\\d{1,})-(\\d{1,})-(\\d{1,})', \
        'tengige\\1/\\2/\\3/\\4/\\5'), 'ce-(\\d{1,})/(\\d{1,})/(\\d{1,})-(\\d{1,})', 'hundredgige\\1/\\2/\\3/\\4'), \
        'ce-(\\d{1,})/(\\d{1,})/(\\d{1,})', 'et-\\1/\\2/\\3'), trim(leading ' ' from \
        concat(ifc_descr_type, ':', ' ', v.name, ' ', i.cid, ' ', i.ifc_comment)) as description, \
        i.cust_id, pa.agg_ifc_id, cis.ifc_state \
        FROM ct_ifcs i \
        JOIN ct_devices d on d.device_id = i.device_id \
        JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id \
        JOIN ct_ifcs_descr_type t ON i.ifc_descr_type_id = t.ifc_descr_type_id \
        LEFT JOIN ct_proto_proto_agg pa ON i.ifc_id = pa.ifc_id \
        LEFT JOIN ct_vendor v ON i.telco_id = v.vendor_id \
        WHERE i.cid ~* (%s) AND i.ifc_comment ~* 'check-4' ORDER BY router;", (cid,))

# Get Customer Info - Uses customer name as value


def get_desc(desc):
    return grab_output("SELECT device_name as router, i.ifc_name, trim(leading ' ' from concat(ifc_descr_type, \
        ' ', i.ifc_descr, ' ', abbr, ' ', i.cid, ' ', i.ifc_comment)) as description, i2.ifc_name, i.cust_id, \
        ipv4, ipv6, cis.ifc_state AS state, i.noc_field\
        FROM ct_ifcs i \
        JOIN ct_devices d on d.device_id = i.device_id \
        LEFT JOIN ct_proto_ipv4 v4 on v4.ifc_id = i.ifc_id and isprimary \
        LEFT JOIN ct_proto_ipv6 v6 on v6.ifc_id = i.ifc_id \
        JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id \
        LEFT JOIN ct_vendor v ON v.vendor_id = i.telco_id \
        LEFT JOIN ct_proto_proto_agg pa ON i.ifc_id = pa.ifc_id \
        LEFT JOIN ct_ifcs i2 on pa.agg_ifc_id = i2.ifc_id \
        JOIN ct_ifcs_descr_type t ON i.ifc_descr_type_id = t.ifc_descr_type_id \
        WHERE i.ifc_descr ~* (%s) or i.cust_id ~* (%s) or i.ifc_comment ~* (%s) or i.cid ~* (%s) or abbr ~* (%s) \
        ORDER BY substring(device_name from 5), i.ifc_name;", (desc, desc, desc, desc, desc,))


# Get DWDM interfaces by device and port info


def get_dwdm(dwdm):
    return grab_output("SELECT device_name as router, ifc_name, ifc_descr, cid, cust_id, \
        cis.ifc_state AS state, ifc_comment, i.noc_field \
        FROM ct_ifcs i \
        JOIN ct_devices d on d.device_id = i.device_id \
        JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id \
        JOIN ct_ifcs_descr_type t ON i.ifc_descr_type_id = t.ifc_descr_type_id \
        WHERE device_name ~* (%s) AND device_name LIKE 'd%%' ORDER BY ifc_name, cid, \
        substring(device_name from 5);", (dwdm,))


# Get DWDM interfaces by device and port info


def get_dwdm_trail(dwdm_trail):
    return grab_output("SELECT device_name as router, ifc_name, ifc_descr, cid, cust_id, \
        cis.ifc_state AS state, ifc_comment, i.noc_field \
        FROM ct_ifcs i \
        JOIN ct_devices d on d.device_id = i.device_id \
        JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id \
        JOIN ct_ifcs_descr_type t ON i.ifc_descr_type_id = t.ifc_descr_type_id \
        WHERE cid ~* (%s) \
        ORDER BY substring(device_name from 5), ifc_name, cid LIMIT 1;", (dwdm_trail,))


# Get BGP session info for DWDM trail


def get_dwdm_bgp(dwdm_trail):
    return grab_output("SELECT p.asn, peer_descr, d.device_name as router, p.ip_addr, pg.peergroup_name, \
        p.route_set, pt.peertype_name, aut.as_macro, aut.as6_macro, ps.peer_state \
        FROM ct_peers p \
        LEFT JOIN ct_ifcs i on p.ifc_id = i.ifc_id \
        JOIN ct_devices d on d.device_id = i.device_id \
        JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id \
        JOIN ct_ifcs_descr_type t ON i.ifc_descr_type_id = t.ifc_descr_type_id \
        LEFT JOIN autnum aut on p.asn = aut.asn \
        JOIN ct_peergroups pg ON p.peergroup_id = pg.peergroup_id \
        JOIN ct_peers_peertype pt on p.peertype_id = pt.peertype_id \
        JOIN ct_peers_state ps on p.peer_state_id = ps.peer_state_id \
        WHERE cid ~* (%s) \
        ORDER BY p.asn;", (dwdm_trail,))


def get_trail_path(trail_id):
    # get service_id
    service_id = trail_id

    obj = json.loads(requests.get('https://gums-dwdm.gin.ntt.net/api/v2/optical/services',
                     auth=(Cloginrc().username, Cloginrc().password)).content)

    for line in obj:
        # match the speed, src pop, dst pop of the trail-id first
        if line['name'][0:20] == service_id[0:20]:
            # check to see if the trail id integer falls within the number of channels of a service
            # based on 100g channels
            if int(line['name'][20:]) <= int(service_id[20:]) and int(line['name'][20:]) + (int(line['service_type'][0:3]) / 100) > int(service_id[20:]):
                channel_num = int(service_id[20:]) % int(line['name'][20:])
                if line['paths'][0]['active'] == bool(True):
                    get_hops(0, line, channel_num)
                elif line['paths'][1]['active'] == bool(True):
                    get_hops(1, line, channel_num)


# Get circuits by ip address


def get_ip(ip):
    return grab_output("SELECT device_name as router, ifc_name, trim(leading ' ' from \
        concat(ifc_descr_type, ' ', ifc_descr, ' ', abbr, ' ', cid, ' ', ifc_comment)) AS description, \
        cust_id, ipv4, ipv6, ifc_state, i.noc_field \
        FROM ct_ifcs i \
        JOIN ct_devices d on i.device_id = d.device_id \
        JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id \
        JOIN ct_ifcs_descr_type t ON i.ifc_descr_type_id = t.ifc_descr_type_id \
        LEFT JOIN ct_vendor v ON v.vendor_id = i.telco_id \
        LEFT JOIN ct_proto_ipv4 v4 on v4.ifc_id = i.ifc_id \
        LEFT JOIN ct_proto_ipv6 v6 ON v6.ifc_id = i.ifc_id  \
        WHERE v4.ipv4 >>= (%s) or v6.ipv6 >>= (%s) \
        ORDER BY router;", (ip, ip,))


# Get Marked Circuit Info - Uses maint, outage, or failure as value


def get_mark(mark):
    if mark == "all":
        mark = ''
    return grab_output("SELECT cis.ifc_state AS state, i.noc_field, \
        concat_ws(' ', d.device_name, regexp_replace(regexp_replace(\
        regexp_replace(regexp_replace(i.ifc_name, 'tengigabitethernet|tengige|x-eth', 'Te'), \
        'hundredgige', 'Hu'), '^pos', 'so-'), '^gigabitethernet', 'Gi')) AS source, \
        regexp_replace(regexp_replace(regexp_replace(regexp_replace(i.ifc_descr, \
        'tengigabitethernet|tengige|x-eth', 'Te'), 'hundredgige', 'Hu'), '^pos', 'so-'), \
        '^gigabitethernet', 'Gi') AS dest, concat_ws(' ', v.abbr, i.cid, i.ifc_comment) AS cid \
        FROM ct_ifcs i \
        JOIN ct_devices d ON d.device_id = i.device_id \
        JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id \
        LEFT JOIN ct_vendor v ON v.vendor_id = i.telco_id \
        WHERE cis.ifc_state IN ('maint', 'outage', 'failure') AND (cis.ifc_state = (%s) OR i.noc_field ~* (%s) \
                                OR i.noc_field = (%s)) \
                                ORDER BY cis.ifc_state, i.noc_field, cid;", (mark, mark, mark))


# Search submarine data file for circuit


def get_submarine(cid):
    with open("/home/clandon/subsea-cid.txt") as file:
        for line in file:
            if cid.lower() in line.lower():
                # print("\n" + 'Submarine Cable ID Search Results: '"\n" + line)
                print(line, end='')


def get_submarine_endless(cid):
    with open("/home/clandon/subsea-cid.txt") as file:
        for line in file:
            if cid.lower() in line.lower():
                print(line, end='')


# Get USID Info - Uses usid as value


def get_usid(usid):
    return grab_output("SELECT device_name as router, i.ifc_name, trim(leading ' ' from concat(ifc_descr_type, ' ', \
        i.ifc_descr, ' ', '-', ' ', abbr, ' ', i.cid, ' ', i.ifc_comment)) \
        AS description, i.cust_id, i2.ifc_name, ipv4, ipv6, i.bps_limit_in, \
        i.bps_limit_out, cis.ifc_state as state, i.noc_field \
        FROM ct_ifcs i \
        JOIN ct_devices d on d.device_id = i.device_id \
        LEFT JOIN ct_proto_ipv4 v4 on v4.ifc_id = i.ifc_id and isprimary \
        LEFT JOIN ct_proto_ipv6 v6 on v6.ifc_id = i.ifc_id \
        LEFT JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id \
        LEFT JOIN ct_vendor v ON v.vendor_id = i.telco_id \
        LEFT JOIN ct_ifcs_descr_type t ON i.ifc_descr_type_id = t.ifc_descr_type_id \
        LEFT JOIN ct_proto_proto_agg pa ON i.ifc_id = pa.ifc_id \
        LEFT JOIN ct_ifcs i2 on pa.agg_ifc_id = i2.ifc_id \
        WHERE i.cust_id ~* (%s) or i.ifc_comment ~* (%s);", (usid, usid,))


def get_usid_quit(usid):
    return grab_output("SELECT device_name as router, i.ifc_name, i.ifc_descr, abbr, i.cid, i.ifc_comment, \
        i.cust_id, i2.ifc_name, ipv4, ipv6, i.bps_limit_in, i.bps_limit_out, cis.ifc_state as state \
        FROM ct_ifcs i \
        JOIN ct_devices d on d.device_id = i.device_id \
        LEFT JOIN ct_proto_ipv4 v4 on v4.ifc_id = i.ifc_id and isprimary \
        LEFT JOIN ct_proto_ipv6 v6 on v6.ifc_id = i.ifc_id \
        LEFT JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id \
        LEFT JOIN ct_vendor v ON v.vendor_id = i.telco_id \
        LEFT JOIN ct_ifcs_descr_type t ON i.ifc_descr_type_id = t.ifc_descr_type_id \
        LEFT JOIN ct_proto_proto_agg pa ON i.ifc_id = pa.ifc_id \
        LEFT JOIN ct_ifcs i2 on pa.agg_ifc_id = i2.ifc_id \
        WHERE i.cust_id ~* (%s) or i.ifc_comment ~* (%s);", (usid, usid,))


def get_usid_session(usid):
    return grab_output("SELECT p.asn, peer_descr, d.device_name as router, p.ip_addr, pg.peergroup_name, \
        p.route_set, pt.peertype_name, aut.as_macro, aut.as6_macro, ps.peer_state \
        FROM ct_peers p \
        LEFT JOIN autnum aut on p.asn = aut.asn \
        LEFT JOIN ct_ifcs i on p.ifc_id = i.ifc_id \
        JOIN ct_devices d on d.device_id = i.device_id \
        JOIN ct_peergroups pg ON p.peergroup_id = pg.peergroup_id \
        JOIN ct_peers_peertype pt on p.peertype_id = pt.peertype_id \
        JOIN ct_peers_state ps on p.peer_state_id = ps.peer_state_id \
        WHERE i.cust_id ~* (%s) or i.ifc_comment ~* (%s) \
        ORDER BY router, p.ip_addr;", (usid, usid,))


# Get USID Info - Uses peerip as value


def get_usid_peerip(peerip):
    return grab_output("SELECT device_name as router, ifc_name, trim(leading ' ' from concat(ifc_descr_type, ' ', \
        ifc_descr, ' ', abbr, ' ', cid, ' ', ifc_comment)) AS description, cust_id, ipv4, ipv6, bps_limit_in, \
        bps_limit_out, cis.ifc_state as state, i.noc_field \
        FROM ct_ifcs i \
        JOIN ct_devices d on d.device_id = i.device_id \
        LEFT JOIN ct_proto_ipv4 v4 on v4.ifc_id = i.ifc_id and isprimary \
        LEFT JOIN ct_proto_ipv6 v6 on v6.ifc_id = i.ifc_id \
        JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id \
        LEFT JOIN ct_vendor v ON v.vendor_id = i.telco_id \
        JOIN ct_ifcs_descr_type t ON i.ifc_descr_type_id = t.ifc_descr_type_id \
        JOIN ct_peers p ON i.ifc_id = p.ifc_id \
        WHERE p.ip_addr = (%s) \
        ORDER BY router, p.ip_addr;", (peerip,))


# Device Search Section

# Get Route Reflector Info by Router Name, Client Name, Cluster ID
# Uses router name as value


def get_cluster(cluster):
    return grab_output("SELECT d.device_name as router, d2.device_name as client, rr.cluster_id \
        FROM ct_devices d \
        JOIN ct_route_reflectors rr ON d.device_id = rr.device_id \
        JOIN ct_rr_clients rrc ON rr.cluster_id = rrc.cluster_id \
        JOIN ct_devices d2 ON rrc.device_id = d2.device_id\
        WHERE rr.cluster_id = (%s)", (cluster,))


# Get OOB based on the last octect of the IP address


def get_findoob(oobip1, oobip2):
    return grab_output("SELECT device_name, p.platform_name as platform, v4.ipv4, os.os_name, os_rev \
        FROM ct_devices d \
        JOIN ct_platform p on d.platform_id = p.platform_id \
        JOIN ct_ifcs i on i.device_id = d.device_id and ifc_name = 'loopback0' \
        LEFT JOIN ct_proto_ipv4 v4 on v4.ifc_id = i.ifc_id \
        JOIN ct_os_name os on os.os_name_id = d.os_name_id \
        WHERE v4.ipv4 = (%s) or v4.ipv4 = (%s) \
        ORDER BY device_name;", (oobip1, oobip2))

# Get iperf server info


def get_iperf(iperf):
    return grab_output("SELECT ifc_descr, device_name as router, ifc_name, ipv4, ipv6 \
        FROM ct_ifcs i \
        JOIN ct_devices d on d.device_id = i.device_id \
        LEFT JOIN ct_proto_ipv4 v4 on v4.ifc_id = i.ifc_id and isprimary \
        LEFT JOIN ct_proto_ipv6 v6 on v6.ifc_id = i.ifc_id \
        WHERE ifc_descr ~* (%s) and ifc_descr ~* 'iperf' ORDER BY substring(device_name from 5), ifc_name, \
        ifc_descr;", (iperf,))


# Get modem numbers by device name


def get_modem(modem):
    return grab_output("SELECT d.device_name, o.location, l.linetype, o.status \
        FROM ct_oob o \
        JOIN ct_devices d ON d.device_id = o.device_id \
        JOIN ct_oob_linetype l ON l.linetype_id = o.linetype_id \
        WHERE d.device_name ~* (%s) AND l.linetype = 'modem' \
        ORDER BY d.device_name;", (modem,))


# Get OOB lines info by device name


def get_oob(oob):
    return grab_output("SELECT d.device_name, o.linenum, o.location, l.linetype, o.aaa, o.acl, o.active, \
        o.enable_conserver \
        FROM ct_oob o \
        JOIN ct_devices d ON d.device_id = o.device_id \
        JOIN ct_oob_linetype l ON l.linetype_id = o.linetype_id \
        WHERE d.device_name ~* (%s) OR o.location ~* (%s) \
        ORDER BY d.device_name, o.linenum;", (oob, oob))


# Get Customer Info - Uses customer name as value


def get_oob_wan(desc):
    return grab_output("SELECT device_name as router, ifc_name, trim(leading ' ' from concat(ifc_descr_type, ' ', \
        ifc_descr, ' ', abbr, ' ', cid, ' ', ifc_comment)) as description, ipv4, cis.ifc_state AS state, i.noc_field \
        FROM ct_ifcs i \
        JOIN ct_devices d on d.device_id = i.device_id \
        LEFT JOIN ct_proto_ipv4 v4 on v4.ifc_id = i.ifc_id and isprimary \
        LEFT JOIN ct_proto_ipv6 v6 on v6.ifc_id = i.ifc_id \
        JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id \
        LEFT JOIN ct_vendor v ON v.vendor_id = i.telco_id \
        JOIN ct_ifcs_descr_type t ON i.ifc_descr_type_id = t.ifc_descr_type_id \
        WHERE device_name ~* (%s) and ifc_descr ~* 'out-of-band' \
        ORDER BY substring(device_name from 5), ifc_name;", (desc,))

# Get OOB notes


def get_oob_notes(oob):
    return grab_output("SELECT o.notes \
        FROM ct_oob o \
        JOIN ct_devices d ON d.device_id = o.device_id \
        JOIN ct_oob_linetype l ON l.linetype_id = o.linetype_id \
        WHERE o.notes IS NOT NULL AND linenum = 0 AND d.device_name ~* (%s);", (oob,))

# Get Route Reflector Info by Router Name or Client Name
# Uses server or client router name as value


def get_reflector(router):
    return grab_output("SELECT d.device_name as router, d2.device_name as client, rr.cluster_id \
        FROM ct_devices d \
        JOIN ct_route_reflectors rr ON d.device_id = rr.device_id \
        JOIN ct_rr_clients rrc ON rr.cluster_id = rrc.cluster_id \
        JOIN ct_devices d2 ON rrc.device_id = d2.device_id\
        WHERE d.device_name ~* (%s) OR d2.device_name ~* (%s)", (router, router,))


# Get Router Info by Router Name - Uses router name, os revision, platform name, or os name as value


def get_router(router):
    return grab_output("SELECT d.device_name as name, p.platform_name as platform, host(v4.ipv4) as loopback, \
        o.os_name, d.os_rev, s.device_state as state, cr.comm_region_descr, d.config_dir as dir \
        FROM ct_devices d \
        FULL JOIN ct_routers r ON r.device_id = d.device_id \
        LEFT JOIN ct_devices_state s ON d.device_state_id = s.state_id \
        LEFT JOIN ct_os_name o ON d.os_name_id = o.os_name_id \
        LEFT JOIN ct_platform p ON d.platform_id = p.platform_id \
        LEFT JOIN ct_mfg ON p.mfg_id = ct_mfg.mfg_id \
        LEFT JOIN ct_ifcs i ON i.device_id = d.device_id AND i.issource_ifc \
        LEFT JOIN ct_proto_ipv4 v4 ON v4.ifc_id = i.ifc_id AND v4.isprimary \
        LEFT JOIN ct_comm_msa cm on d.comm_msa_id = cm.comm_msa_id \
        LEFT JOIN ct_comm_country cc on cm.comm_country_id = cc.comm_country_id \
        LEFT JOIN ct_comm_region cr on cc.comm_region_id = cr.comm_region_id \
        WHERE d.device_name ~* (%s) or d.os_rev ~* (%s) or p.platform_name ~* (%s) or o.os_name ~* (%s) or \
        cr.comm_region_descr ~* (%s) or d.config_dir ~* (%s) \
        ORDER BY d.config_dir, p.platform_name, d.os_rev, d.device_name;",
                       (router, router, router, router, router, router))


# Get Satellite or Customer EX device uplinks


def get_sat(sat):
    return grab_output("SELECT ifc_descr, device_name as router, ifc_name, cis.ifc_state \
        FROM ct_ifcs i \
        JOIN ct_devices d on d.device_id = i.device_id \
        JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id \
        WHERE ifc_descr ~* (%s) and ifc_descr LIKE 'c10%%';", (sat,))


# Other Search Section

# Get Extended ACL's by name


def get_eacl(desc, filter):
    return grab_output("SELECT a.interim_extended_acl_name as acl_name, device_name as router, i.ifc_name, \
        i2.ifc_name, cis.ifc_state as state, i.cust_id as usid, o.os_name, b.afi_name, cr.comm_region_descr AS region \
        FROM ct_ifcs i \
        LEFT JOIN ct_interim_extended_acl a ON (i.interim_extended_acl_v4_in = a.interim_extended_acl_id OR \
        i.interim_extended_acl_v6_in = a.interim_extended_acl_id OR i.interim_extended_acl_v4_out = \
        a.interim_extended_acl_id OR i.interim_extended_acl_v6_out = a.interim_extended_acl_id) \
        LEFT JOIN ct_acl_templates_afi b ON a.afi_id = b.afi_id \
        JOIN ct_devices d ON d.device_id = i.device_id \
        JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id \
        JOIN ct_os_name o ON d.os_name_id = o.os_name_id \
        JOIN ct_comm_msa m ON m.comm_msa_id = d.comm_msa_id \
        JOIN ct_comm_country c ON c.comm_country_id = m.comm_country_id \
        JOIN ct_comm_region cr ON cr.comm_region_id = c.comm_region_id \
        LEFT JOIN ct_proto_proto_agg pa ON i.ifc_id = pa.ifc_id \
        LEFT JOIN ct_ifcs i2 on pa.agg_ifc_id = i2.ifc_id \
        WHERE i.ifc_name NOT LIKE (%s) \
        AND ( (i.ifc_descr ~* (%s) AND a.interim_extended_acl_name ~* (%s)) OR (i.ifc_descr ~* (%s) \
        AND cr.comm_region_descr ~* (%s)) ) \
        ORDER BY (split_part(device_name, '.', 2)), split_part(device_name, '.', 1), \
        i2.ifc_name, i.ifc_name,b.afi_name;", ('tunnel%', desc, filter, desc, filter))


# Get BH routes on r99.dllstx09.us.bb


def get_bh(bh):
    if bh == "all":
        bh = ''
    return grab_output("SELECT device_name as router, prefix, nexthop_null0, communities_descr, statics_descr, \
        date_configured \
        FROM ct_devices d  \
        LEFT JOIN ct_statics s on s.device_id = d.device_id \
        LEFT JOIN ct_ifcs i on i.ifc_id = s.nexthop_ifc_id \
        JOIN ct_statics_communities_list cl on s.communities_list_id = cl.communities_list_id \
        WHERE d.device_name = 'r99.dllstx09.us.bb' AND ( CAST(prefix as text) ~* (%s) or statics_descr ~* (%s) \
        or CAST(date_configured as text)  ~* (%s) ) ORDER BY date_configured DESC, prefix;", (bh, bh, bh))


# Get customer bgp info by router name


def get_cb(router):
    return grab_output("SELECT d.device_name as router, i.ifc_name, i.ifc_descr as description, p.asn, p.ip_addr \
        FROM ct_devices d \
        LEFT JOIN ct_ifcs i on d.device_id = i.device_id \
        LEFT JOIN ct_peers p on i.ifc_id = p.ifc_id \
        WHERE d.device_name ~* (%s) and i.ifc_descr != 'unused' \
        ORDER BY d.device_name, i.ifc_name;", (router,))


# Get LSP info by lsp name


def get_lsp(lsp):
    return grab_output("SELECT lsp_name, cspf, bw, priority \
        FROM ct_lsp \
        WHERE lsp_name ~* (%s) \
        ORDER BY device_id, z_device_id;", (lsp,))


# Get ISIS metrics based on rotuer name


def get_metric_string(metric):
    return grab_output("SELECT device_name as router, i.ifc_name, \
        regexp_replace(regexp_replace(i.ifc_descr, 'ae-(\\d{1,})', 'ae\\1'), 'be-(\\d{1,})', 'be\\1'), metric \
        FROM ct_ifcs i \
        JOIN ct_devices d on d.device_id = i.device_id \
        JOIN ct_proto_isis ii on ii.ifc_id = i.ifc_id \
        WHERE d.device_name ~* (%s) ORDER BY router;", (metric,))


def get_metric_int(metric):
    return grab_output("SELECT device_name as router, i.ifc_name, \
        regexp_replace(regexp_replace(i.ifc_descr, 'ae-(\\d{1,})', 'ae\\1'), 'be-(\\d{1,})', 'be\\1'), metric \
        FROM ct_ifcs i \
        JOIN ct_devices d on d.device_id = i.device_id \
        JOIN ct_proto_isis ii on ii.ifc_id = i.ifc_id \
        WHERE ii.metric = (%s) ORDER BY router;", (metric, ))


# Check circuits for mtu values less than 9174


def get_mtucheck(mtucheck):
    return grab_output("SELECT device_name as router, ifc_name, concat(ifc_descr_type, ' ', ifc_descr) as \
        description, mtu \
        FROM ct_ifcs i \
        JOIN ct_devices d on d.device_id = i.device_id \
        JOIN ct_ifcs_descr_type t ON i.ifc_descr_type_id = t.ifc_descr_type_id \
        WHERE (ifc_descr_type = 'BL' or ifc_descr like 'bb') and (mtu <= (%s)) \
        ORDER BY mtu, substring(device_name from 5), device_name, ifc_name, ifc_descr;", (mtucheck,))


# Get Statics by router name


def get_statics(statics):
    return grab_output("SELECT device_name as router, prefix, i.ifc_name, nexthop_ip, nexthop_null0, statics_descr, \
        date_configured \
        FROM ct_devices d  \
        LEFT JOIN ct_statics s on s.device_id = d.device_id \
        LEFT JOIN ct_ifcs i on i.ifc_id = s.nexthop_ifc_id \
        WHERE d.device_name ~* (%s);", (statics,))


# Get Statics by prefix


def get_statics_ip(statics):
    return grab_output("SELECT device_name as router, prefix, i.ifc_name, nexthop_ip, nexthop_null0, statics_descr, \
        date_configured \
        FROM ct_devices d  \
        LEFT JOIN ct_statics s on s.device_id = d.device_id \
        LEFT JOIN ct_ifcs i on i.ifc_id = s.nexthop_ifc_id \
        WHERE s.prefix >>= (%s) AND not s.prefix = '0/0';", (statics,))


# Get Telco info by telco ID


def get_telco(telco):
    return grab_output("SELECT name, abbr, phone, phone800, noc_phone, noc_phone800, noc_email, notes \
        FROM ct_vendor \
        WHERE name ~* (%s)", (telco,))


# Get VC Info - Uses vc number as value


def get_vc(vc):
    return grab_output("SELECT l2.id, ifc.name as name, l2.router, l2.ifc_name, l2.dst, ifc.cust_id as usid, \
            ifc.state \
            FROM l2vpnu l2 \
            LEFT JOIN interfaces ifc ON l2.router = ifc.router and l2.ifc_name = ifc.ifc_name \
            WHERE CAST(l2.id AS text) = (%s) \
            ORDER BY l2.router, l2.ifc_name;", (vc,))


def get_hsrp(q):
    """ Get HSRP entries """
    return grab_output("SELECT d.device_name,i.ifc_name,hp.priority,i.ifc_descr,ct_proto_ipv4.ipv4, \
            h.standby_ip,ifc_comment \
            FROM ct_ifcs i \
            INNER JOIN ct_proto_hsrp h ON (h.ifc_id=i.ifc_id) \
            INNER JOIN ct_proto_ipv4 ON (ct_proto_ipv4.ifc_id=i.ifc_id) \
            INNER JOIN ct_devices d ON (d.device_id=i.device_id) \
            INNER JOIN ct_proto_hsrp_priority hp ON (hp.priority_id=h.priority_id) \
            WHERE d.device_name ~* (%s) OR i.ifc_descr ~* (%s) \
            ORDER BY h.standby_ip,hp.priority;", (q, q,))


def get_vrf(vrf):
    """ Get VRF entries """
    return grab_output("SELECT d.device_name, i.ifc_name, i.ifc_descr, v.vrf_dst_ip, v.vrf_dst_ipv6, t.tms_ip, \
            v.active \
            FROM ct_ifcs i \
            JOIN ct_devices d ON i.device_id = d.device_id \
            JOIN ct_proto_tunnel_w_vrf v ON i.ifc_id = v. ifc_id \
            JOIN ct_proto_tunnel_w_vrf_tms_ip t ON v.tms_ip_id = t.tms_ip_id \
            WHERE i.ifc_descr ~* (%s) OR d.device_name ~* (%s) \
            ORDER BY d.device_name, i.ifc_descr, i.ifc_name;", (vrf, vrf))


def get_vrrp(q):
    """ Get VRRP entries """
    return grab_output("SELECT d.device_name,i.ifc_name,vp.priority,i.ifc_descr,ct_proto_ipv4.ipv4,\
            v.standby_ip,ifc_comment \
            FROM ct_ifcs i \
            INNER JOIN ct_proto_vrrp v ON (v.ifc_id=i.ifc_id) \
            INNER JOIN ct_proto_ipv4 ON (ct_proto_ipv4.ifc_id=i.ifc_id) \
            INNER JOIN ct_devices d ON (d.device_id=i.device_id) \
            INNER JOIN ct_proto_vrrp_priority vp ON (vp.priority_id=v.priority_id) \
            WHERE d.device_name ~* (%s) OR i.ifc_descr ~* (%s) \
            ORDER BY v.standby_ip,vp.priority;", (q, q,))

# Functions after this line provide error checking and help output

# Print function for non-GIN circuit


def not_gin():
    # Peer Search Error Messages
    if error_code in ['asn', 'asnmacro']:
        print("\n" + 'AS' + value + ' does not have a BGP session with AS2914' + "\n")
    elif error_code == 'aslookup':
        print("\n" + value + ' is not a valid peer name' + "\n")
    elif error_code == 'peercontact':
        print("\n" + 'AS' + value + ' does not have contact information in tools')
        print('Make sure AS' + value + ' is a valid NTT peer and not a customer' + "\n")
    elif error_code == 'bgpset':
        print("\n" + value + ' is not a valid AS Set or Route Set' + "\n")
    elif error_code == 'peergroup':
        print("\n" + value + ' is not a valid peergroup or route set' + "\n")
    elif error_code == 'peerip':
        print("\n" + value + ' is not a valid BGP neighbor address' + "\n")
    elif error_code == 'error_peerip':
        print("\n" + value + ' is not associated to a USID' + "\n")

    # Circuit Search Error Messages

    elif error_code in ['bw']:
        print("\n" + 'There are no bundles with a BW of ' + value + "\n")
    elif error_code in ['cid']:
        print("\n" + value + ' is not a GIN circuit' + "\n")
    elif error_code == 'cid_bundle':
        print("\n" + value + ' is not part of a bundle' + "\n")
    elif error_code == 'check-4-warn_error':
        pass
    elif error_code == 'endless_error':
        print(value + ' => NOT GIN')
    elif error_code == 'desc':
        print("\n" + value + ' is not a valid description' + "\n")
    elif error_code == 'dwdm':
        print("\n" + value + ' is not a valid DWDM device' + "\n")
    elif error_code == 'dwdmbgp':
        print("\n" + 'There is not a BGP session associated to trail ID ' + value + "\n")
    elif error_code == 'dwdmlag':
        print("\n" + 'There is not a bundle associated to trail ID ' + value + "\n")
    elif error_code == 'dwdmtrail':
        print("\n" + 'Trail ' + value + ' is not in use at this time.' + "\n")
    elif error_code == 'ip':
        print("\n" + value + ' is not configured for any circuit in config tools' + "\n")
    elif error_code == 'mark':
        print("\n" + 'There are no circuits marked as ' + value + "\n")
    elif error_code == 'submarine_error':
        print("\n" + value + ' is not a submarine circuit' + "\n")
    elif error_code == 'submarine_error_desc':
        print("\n" + value + ' is not a submarine description' + "\n")
    elif error_code == 'submarine_error_endless':
        print(value + ' => NOT SUBMARINE')
    elif error_code in ['usid', 'cust']:
        print("\n" + value + ' is not a valid USID' + "\n")
    elif error_code == 'usid_bundle':
        print("\n" + 'USID ' + value + ' is not part of a bundle' + "\n")
    elif error_code == 'usid_endless_error':
        print(value + ' => NOT A VALID USID')
    elif error_code == 'usid_session':
        print('USID ' + value + ' does not have a BGP sessions associated to it')

    # Device Search Error Messages

    elif error_code == 'cluster':
        print("\n" + 'There are no route reflectors associated to cluster ID ' + value + "\n")
    elif error_code == 'findoob':
        print("\n" + 'There is no OOB with the IP address of ' + value1 + ' or ' + value2 + "\n")
    elif error_code == 'iperf':
        print("\n" + 'There is not an iperf server located in ' + value + "\n")
    elif error_code == 'iperf_server':
        print("\n" + 'There is no iperf server in the listed PoP\n' + 'PoP name must be complete.'
              '  Example: asbnva02' + "\n")
    elif error_code == 'modem':
        print("\n" + 'There are no dial-in modems located in ' + value + "\n")
    elif error_code == 'oob':
        print("\n" + value + ' is not a valid OOB device' + "\n")
    elif error_code == 'error_oob_wan':
        print("\n" + value + ' does not have a WAN circuit' + "\n")
    elif error_code == 'error_oob_notes':
        print("\n")
    elif error_code == 'reflector':
        print("\n" + value + ' is not configured as a router reflector' + "\n")
    elif error_code == 'router':
        print("\n" + value + ' is not a valid GIN router' + "\n")
    elif error_code == 'sat':
        print("\n" + value + ' is not a valid satellite' + "\n")

    # Other Search Error Messages

    elif error_code == 'acl':
        print("\n" + 'There are no extended ACLs for the search term: ' + value + "\n")
    elif error_code == 'bh':
        print("\n" + 'There are no routes configured for Black Hole at this time' + "\n")
    elif error_code == 'lsp':
        print("\n" + 'There are no LSPs labeled as ' + value + "\n")
    elif error_code == 'metric_int':
        print("\n" + 'There are no circuits with the ISIS metric of ' + value + "\n")
    elif error_code == 'metric_string':
        print("\n" + value + ' is not a valid router name' + "\n")
    elif error_code == 'mtucheck':
        print("\n" + 'There are no circuits with MTU values less than ' + value + "\n")
    elif error_code == 'statics':
        print("\n" + 'There are no statics with the value of ' + value + "\n")
    elif error_code == 'error_statics_router':
        print("\n" + 'There are no statics on ' + value + "\n")
    elif error_code == 'telco':
        print("\n" + value + ' is not a valid telco name' + "\n")
    elif error_code == 'vc':
        print("\n" + value + ' is not a valid virtual circuit ID' + "\n")
    elif error_code == 'hsrp':
        print("\n" + 'There are no HSRP for the search term: ' + value + "\n")
    elif error_code == 'vrf':
        print("\n" + 'There are no VRF for the search term: ' + value + "\n")
    elif error_code == 'vrrp':
        print("\n" + 'There are no VRRP for the search term: ' + value + "\n")

# IP address validation


def ip_check(value):
    try:
        _ = ipaddress.ip_address(value)
    except ValueError:
        print("\n" + value + ' is not a valid IP address' + "\n")
        sys.exit(1)

# ASN integer validation


def int_check(value):
    try:
        _ = int(value)
    except ValueError:
        print("\n" + value + ' must be an integer' + "\n")
        sys.exit(1)


# Mida Function


def mida(value):
    if value == 'multitool':
        print(2 * "\n")
        print("Select application: Ballistic engagement. Entrenching tool. Avionics trawl. Troll Smasher. " +
              "Stellar sextant. List continues.")
        print(2 * "\n")
    else:
        print(2 * "\n")
        print("Please use a valid arguement.")
        print(2 * "\n")


# Dictionary for iperf servers

iperf_servers = {

    # North America Region
    "asbnva02": "iperf01.asbnva02.us.to.gin.ntt.net\niperf02.asbnva02.us.to.gin.ntt.net",
    "atlnga05": "iperf01.atlnga05.us.to.gin.ntt.net\niperf02.atlnga05.us.to.gin.ntt.net",
    "chcgil09": "iperf01.chcgil09.us.to.gin.ntt.net\niperf02.chcgil09.us.to.gin.ntt.net",
    "dllstx09": "iperf01.dllstx09.us.to.gin.ntt.net\niperf02.dllstx09.us.to.gin.ntt.net",
    "hstntx01": "iperf01.hstntx01.us.to.gin.ntt.net",
    "lsanca07": "iperf01.lsanca07.us.to.gin.ntt.net\niperf02.lsanca07.us.to.gin.ntt.net",
    "miamfl02": "iperf01.miamfl02.us.to.gin.ntt.net\niperf02.miamfl02.us.to.gin.ntt.net",
    "mlpsca01": "iperf01.mlpsca01.us.to.gin.ntt.net\niperf02.mlpsca01.us.to.gin.ntt.net",
    "nycmny17": "iperf01.nycmny17.us.to.gin.ntt.net\niperf02.nycmny17.us.to.gin.ntt.net",
    "plalca01": "iperf01.plalca01.us.to.gin.ntt.net\niperf02.plalca01.us.to.gin.ntt.net",
    "scrmca02": "iperf01.scrmca02.us.to.gin.ntt.net",
    "snjsca04": "iperf01.snjsca04.us.to.gin.ntt.net\niperf02.snjsca04.us.to.gin.ntt.net",
    "sttlwa01": "iperf01.sttlwa01.us.to.gin.ntt.net\niperf02.sttlwa01.us.to.gin.ntt.net",

    # South America Region
    "saplbr01": "iperf01.saplbr01.br.to.gin.ntt.net",

    # Asia Region

    "jktajk01": "iperf01.jktajk01.id.to.gin.ntt.net",
    "jktajk02": "iperf01.jktajk02.id.to.gin.ntt.net",
    "kslrml02": "iperf01.kslrml02.my.to.gin.ntt.net\niperf02.kslrml02.my.to.gin.ntt.net",
    "osakjp02": "iperf01.osakjp02.jp.to.gin.ntt.net\niperf02.osakjp02.jp.to.gin.ntt.net",
    "seolko02": "iperf01.seolko02.kr.to.gin.ntt.net\niperf02.seolko02.kr.to.gin.ntt.net",
    "sngpsi05": "iperf01.sngpsi05.sg.to.gin.ntt.net",
    "sngpsi07": "iperf01.sngpsi07.sg.to.gin.ntt.net",
    "sydnau02": "iperf01.sydnau02.au.to.gin.ntt.net",
    "sydnau03": "iperf01.sydnau03.au.to.gin.ntt.net",
    "taiptw01": "iperf01.taiptw01.tw.to.gin.ntt.net\niperf02.taiptw01.tw.to.gin.ntt.net",
    "tkokjk01": "iperf01.tkokhk01.hk.to.gin.ntt.net\niperf02.tkokhk01.hk.to.gin.ntt.net",
    "tokyjp05": "iperf01.tokyjp05.jp.to.gin.ntt.net\niperf02.tokyjp05.jp.to.gin.ntt.net",

    # Europe Region

    "amstnl02": "iperf01.amstnl02.nl.to.gin.ntt.net\niperf02.amstnl02.nl.to.gin.ntt.net",
    "buchro01": "iperf01.buchro01.ro.to.gin.ntt.net\niperf02.buchro01.ro.to.gin.ntt.net",
    "frnkge13": "iperf01.frnkge13.de.to.gin.ntt.net\niperf02.frnkge13.de.to.gin.ntt.net",
    "londen03": "iperf01.londen03.uk.to.gin.ntt.net\niperf02.londen03.uk.to.gin.ntt.net",
    "mdrdsp04": "iperf01.mdrdsp04.es.to.gin.ntt.net\niperf02.mdrdsp04.es.to.gin.ntt.net",
    "mlanit01": "iperf01.mlanit01.it.to.gin.ntt.net\niperf02.mlanit01.it.to.gin.ntt.net",
    "parsfr02": "iperf01.parsfr02.fr.to.gin.ntt.net\niperf02.parsfr02.fr.to.gin.ntt.net",
    "vienat02": "iperf01.vienat02.at.to.gin.ntt.net\niperf02.vienat02.at.to.gin.ntt.net"

}

# -h output information for this script - Postional Arguement section


search_type_choices = ['acl', 'bgp', 'bh', 'bw', 'cb', 'cid', 'desc', 'dwdm', 'trail', 'findoob', 'hsrp', 'ip', 'iperf',
                       'irr', 'lsp', 'mark', 'metric', 'modem', 'mtucheck', 'oob', 'reflector', 'router', 'routers',
                       'rr', 'sat', 'statics', 'telco', 'usid', 'vc', 'vrf', 'vrrp']
search_type_examples = """

Circuit Searches:
bw 500                                  Searches for circuits by BW - BW or greater
cid u0458                               Searches for BB circuits by CID
cid endless                             Searches for BB circuits by CID until you quit
desc facebook                           Searches for customer circuits by description
trail 2-nycmny01-nycmny13-000149        Searches for DWDM circuits by trail ID
trail endless                           Searches for DWDM circuits by trail ID until you quit
ip 129.250.2.193                        Searches for circuits by ip address assigned to the circuit
usid 283735                             Searches for customer circuit by USID
usid endless                            Searches for customer circuit by USID until you quit
vc 1068                                 Searches for l2vpn by VC ID

BGP Peer Searches:
bgp                                     Searches for BGP peers by ASN, Description, AS Macro, BGP set, route set,
                                        peer IP, and peergroup name.

Device Searches:
dwdm d00.nycmny13.us.bb                 Searches for interfaces on DWDM devices
findoob 13                              Searches for IP-OOB devices based on the last octet of the device's IP address
iperf dllstx09                          Searches for iperf servers in listed pop
modem dllstx09                          Searches for modem numbers by pop
oob o10.dllstx09.us.bb                  Searches for oob lines by name
router r10.dllstx09.us.bb               Searches for routers by name, os revision, os type, or platform
reflector r22.dllstx09.us.bb            Searches for route reflectors and clients by server, client name, or cluster ID
sat nycmny                              Searches for satellites devices by name

Other Searches:
acl Paypal                              Lists all Extended ACL's by provided input
bh all                                  Lists all Black Hole Routes configured in tools
cb                                      Lists all customers and their bgp sessions on a given router
hsrp r10.dllstx09.us.bb                 Searches for HSRP on device or description.
irr AS-CONNETU                          Searches IRRTree for BGP AS Set entries
lsp r23.sttlwa01-r23.snjsca04-00        Searches for listed lsp
mark [all|maint|outage|failure|ticket]  Searches for circuits that are marked for maint, outage, failure or ticket
metric r24.londen12.uk.bb               Searches for ISIS metric by router name or by metric value
mtucheck 9188                           Lists all circuits with MTU values > supplied value
rr 129.250.54.98                        Searches NTT route registry
statics r22.dllstx09.us.bb              Searches for statics by router or prefix
telco verizon                           Searches for telco info by telco name
vrf r11.dllstx09.us.bb                  Searches for circuits with vrfs by router or customer name
vrrp r11.dllstx09.us.bb                 Searches for VRRP on device or description.

"""


# Main Program

# Error checking for input on command line


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Does various searches for the NOC',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-d', action='store_true', help='prints useful debugging')
    parser.add_argument('-D', metavar='db_name', dest='dbname',
                        help='specifies the database name, defaults to %(default)s',
                        default=os.getenv('RTRCFG_DBNAME', "cfgtools"))
    parser.add_argument('-H', metavar='db_host', dest='dbhost', help='database hostname')
    parser.add_argument('-P', metavar='port', type=int, dest='dbport', help='database port number')
    parser.add_argument('-A', metavar='db_user/db_password', dest='dbup',
                        help='database authentication username/password')
    parser.add_argument('search_type', help='type of search to do, ex:' + search_type_examples,
                        choices=search_type_choices)
    parser.add_argument('value', help='value to search on.')
    parser.add_argument('filter', help='filter results based on string', nargs='?', default='', type=str)
    parser.add_argument('--csv', help='print output to csv file')
    parser.add_argument('-mida', help=argparse.SUPPRESS, type=mida, action='store')
    args = parser.parse_args()
    if args.d:
        print(vars(args))

    # Print result to screen

    try:
        dbuser = None
        dbpwd = None
        if args.dbup:
            try:
                dbuser = args.dbup[0:args.dbup.index('/')]
                dbpwd = args.dbup[args.dbup.index('/') + 1:len(args.dbup)]
            except ValueError:
                print("Error processing '-A", args.dbup + "' no / found")
                sys.exit(1)
        search_type = args.search_type
        value = args.value
        filter = args.filter

        # done procesing args

        with db.connect(database=args.dbname, host=args.dbhost, user=dbuser, password=dbpwd, port=args.dbport) as conn:

            # Heading Colors
            cstart = '\33[32m'
            cend = '\033[0m'
            db = 'https://gums-dwdm.gin.ntt.net/api/v2/'
            # Peer Search Section

            # Search for BGP peering sessions by ASN

            if search_type == 'bgp':
                try:
                    val = int(value)
                except ValueError:
                    try:
                        ip = ipaddress.ip_address(value)
                    except ValueError:
                        print()
                        print(cstart + 'ASN Lookup Search: ' + cend)
                        error_code = 'aslookup'
                        do_output(get_asn_descr(value), ["ASN", "Description", "Router", "IP Address", "Peergroup",
                                  "Route Set", "Peer Type", "IPv4 Macro", "IPv6 Macro", "State"])
                        print()
                        print(cstart + 'AS Set or Route Set Search: ' + cend)
                        error_code = 'bgpset'
                        do_output(get_bgp_set(value), ["ASN", "Description", "Router", "IP Address", "Peergroup",
                                  "Route Set", "Peer Type", "IPv4 Macro", "IPv6 Macro", "State"])
                        print()
                        print(cstart + 'Peergroup Search: ' + cend)
                        error_code = 'peergroup'
                        do_output(get_peergroup(value), ["ASN", "Name", "Router", "IP Address", "Peergroup",
                                  "Route Set", "State"])
                    else:
                        print()
                        print(cstart + 'Peer IP Search: ' + cend)
                        error_code = search_type
                        do_output(get_peerip(value), ["ASN", "Description", "Router", "IP Address", "Peergroup",
                                  "Route Set", "Peer Type", "IPv4 Macro", "IPv6 Macro", "State"])
                        print()
                        print(cstart + 'USID Search: ' + cend)
                        error_code = 'error_peerip'
                        do_output(get_usid_peerip(value), ["Router", "Interface", "Description", "USID", "IPv4",
                                  "IPv6", "Rate Limit In", "Rate Limit Out", "State", "NOC Field"])
                else:
                    print()
                    print(cstart + 'Peer Contact Search: ' + cend)
                    error_code = 'peercontact'
                    do_output(get_peerc(value), ["Name", "ASN", "NOC Email", "Peer Email", "TPOC1 Email"])
                    print(cstart + 'Autnum Search: ' + cend)
                    error_code = 'asn'
                    do_output(get_asn_macro(value), ["ASN", "Name", "IPv4 Macro", "IPv4 Prefix Count",
                              "IPv4 Allow Specifics", "IPv6 Macro", "IPv6 Prefix Count", "IPv6 Allow Specifics",
                                                            "IRR"])
                    print(cstart + 'ASN Search: ' + cend)
                    do_output(get_asn(value), ["ASN", "Description", "Router", "IP Address", "Peergroup", "Route Set",
                              "Peer Type", "IPv4 Macro", "IPv6 Macro", "ISIS Metric", "State"])

            # Search irrtree for AS-Set info

            elif search_type == 'irr':
                subprocess.call(["/opt/gums/bin/irrtree", value])

            # Search irrtree for AS-Set info

            elif search_type == 'rr':
                subprocess.call(["/usr/bin/whois", "-h", "rr.ntt.net", value])

            # Circuit Search Section

            # Search for circuits by CID

            elif search_type == 'cid':
                try:
                    if value == 'endless':
                        value_list = []
                        while True:
                            value = input(cstart + "\nPlease enter the circuit ID or type 'quit': " + cend)
                            print("\n" * 2)
                            if value == 'quit':
                                print(cstart + 'Circuit List: ' + cend)
                                for value in value_list:
                                    error_code = 'endless_error'
                                    do_table_endless(get_circuit_quit(value))
                                print("\n")
                                print('The following circuits have a \033[1;31;40mCHECK-4\033[0;0m warning: ')
                                for value in value_list:
                                    error_code = 'check-4-warn_error'
                                    do_table_endless_check_4_warn(get_check_4_warn(value))
                                print("\n")
                                print(cstart + 'Submarine Circuit List: ' + cend)
                                for value in value_list:
                                    error_code = 'submarine_error_endless'
                                    get_submarine_endless(value)
                                print("\n" * 2)
                                break
                            if value.replace(' ', '') == '':
                                continue
                            print(cstart + 'Circuit Search: ' + cend)
                            value_list.append(value)
                            error_code = search_type
                            do_table(get_circuit(value), ["A-side", "Z-side", "Description", "USID", "Bundle",
                                     "State"])
                            # Search Submarine file for circuit
                            print()
                            error_code = 'submarine_error'
                            print(cstart + 'Submarine Cable Search: ' + cend)
                            get_submarine(value)
                            print("\n")
                    else:
                        print("\n" * 2)
                        print(cstart + 'Circuit Search: ' + cend)
                        error_code = search_type
                        do_output(get_circuit(value), ["A-side", "Z-side", "Description", "USID", "Bundle", "State"])
                        print()
                        print(cstart + 'Bundle Search: ' + cend)
                        error_code = 'cid_bundle'
                        do_output(get_bundle_bb(value), ["A-Side", "Z-side", "IPv4", "IPv6", "State", "BW (Gbps)"])
                        # Search Submarine file for circuit
                        print()
                        error_code = 'submarine_error'
                        print(cstart + 'Submarine Cable Search: ' + cend)
                        get_submarine(value)
                        print("\n")
                except KeyboardInterrupt:
                    print("\n" * 2)
                    print(cstart + "Ctrl-C was used to stop this script" + cend)
                    print("\n" * 2)
                    if value_list:
                        print(cstart + 'Circuit List: ' + cend)
                        for value in value_list:
                            error_code = 'endless_error'
                            do_table_endless(get_circuit_quit(value))
                        print("\n")
                        print(cstart + 'Submarine Circuit List: ' + cend)
                        for value in value_list:
                            error_code = 'submarine_error_endless'
                            get_submarine_endless(value)
                            print("\n")

            # Search for customer circuits by name

            elif search_type == 'desc':
                print()
                print(cstart + 'Circuit Description Search: ' + cend)
                error_code = search_type
                do_output(get_desc(value), ["Router", "Interface", "Description", "Bundle", "USID", "IPv4", "IPv6",
                                            "State", "NOC Field"])
                # Search Submarine file for circuit
                print()
                print(cstart + 'Submarine Cable Search: ' + cend)
                error_code = 'submarine_error_desc'
                get_submarine(value)

            # Search for dwdm trails by trail id

            elif search_type == 'trail':
                try:
                    if value == 'endless':
                        value_list = []
                        while True:
                            value = input(cstart + "\nPlease enter the trail ID or type 'quit': " + cend)
                            print("\n" * 2)
                            if value == 'quit':
                                print(cstart + "This script was stopped by typing quit" + cend)
                                break
                            print(cstart + 'Trail Search: ' + cend)
                            value_list.append(value)
                            get_trail_path(value)
                            print("\n")
                    else:
                        error_code = 'dwdmtrail'
                        print(cstart + 'Trail ID: ' + value + cend)
                        do_output(get_dwdm_trail(value), ["Router", "Interface", "Description", "CID", "USID", "State",
                                                          "Comment", "NOC Field"])
                        print(cstart + 'Bundle for the Trail:' + cend)
                        error_code = 'dwdmlag'
                        do_output(get_bundle_bb(value), ["A-Side", "Z-side", "IPv4", "IPv6", "State", "BW (Gbps)"])
                        print(cstart + "Trail Path: (If no path is listed, check the DLR)" + cend)
                        print()
                        get_trail_path(value)
                        print()
                        print(cstart + 'BGP Associated to Circuit:' + cend)
                        error_code = 'dwdmbgp'
                        do_output(get_dwdm_bgp(value), ["ASN", "Description", "Router", "IP Address", "Peergroup",
                                  "Route Set", "Peer Type", "IPv4 Macro", "IPv6 Macro", "State"])
                except KeyboardInterrupt:
                    print("\n")
                    print(cstart + "Ctrl-C was used to stop this script" + cend)


            # Search for circuits by ip address

            elif search_type == 'ip':
                ip_check(value)
                error_code = search_type
                do_output(get_ip(value), ["Router", "Interface", "Description", "USID", "IPv4 Address",
                          "IPv6 Address", "State", "NOC Field"])

            # Search for circuits marked in maint, outage, or failure - can be filtered by state/ticket

            elif search_type == 'mark':
                error_code = search_type
                do_output(get_mark(value), ["State", "Ticket", "Source", "Destination", "CID"])

            elif search_type == 'bw':
                error_code = search_type
                do_output(get_bundle_bw(value), ["Router", "Interface", "Description", "USID", "IPv4", "IPv6",
                                                 "Rate Limit In", "Rate Limit Out", "State", "BW (Gbps)", "NOC Field"])

            # Search for customer circuits by USID

            elif search_type == 'usid':
                try:
                    if value == 'endless':
                        value_list = []
                        while True:
                            value = input(cstart + "\nPlease enter the customer's USID or type 'quit': " + cend)
                            print("\n" * 2)
                            if value == 'quit':
                                print(cstart + "Circuit List: " + cend)
                                for value in value_list:
                                    error_code = 'usid_endless_error'
                                    do_table_usid_endless(get_usid_quit(value))
                                print("\n")
                                print(cstart + 'Submarine Circuit List: ' + cend)
                                for value in value_list:
                                    error_code = 'submarine_error_endless'
                                    get_submarine_endless(value)
                                print("\n" * 2)
                                break
                            if value.replace(' ', '') == '':
                                continue
                            print(cstart + 'USID Search: ' + cend)
                            value_list.append(value)
                            error_code = search_type
                            do_output(get_usid(value), ["Router", "Interface", "Description", "USID", "Bundle",
                                                        "IPv4", "IPv6", "Rate Limit In", "Rate Limit Out", "State",
                                                        "NOC Field"])
                            # Search Submarine file for circuit
                            print()
                            error_code = 'submarine_error'
                            print(cstart + 'Submarine Cable Search: ' + cend)
                            get_submarine(value)
                            print("\n")
                    else:
                        print("\n" * 2)
                        print(cstart + 'USID Search - https://gnome.ntt.net/index.pl?usid=' + value + cend)
                        error_code = search_type
                        do_output(get_usid(value), ["Router", "Interface", "Description", "USID", "Bundle", "IPv4",
                                  "IPv6", "Rate Limit In", "Rate Limit Out", "State", "NOC Field"])
                        print()
                        print(cstart + 'Bundle Search: ' + cend)
                        error_code = 'usid_bundle'
                        do_output(get_bundle(value), ["Router", "Interface", "Description", "USID", "IPv4", "IPv6",
                                  "Rate Limit In", "Rate Limit Out", "State", "BW (Gbps)", "NOC Field"])
                        print()
                        print(cstart + 'BGP Session Search: ' + cend)
                        error_code = 'usid_session'
                        do_output(get_usid_session(value), ["ASN", "Description", "Router", "IP Address", "Peergroup",
                                  "Route Set", "Peer Type", "IPv4 Macro", "IPv6 Macro", "State"])
                        # Search Submarine file for circuit
                        print()
                        error_code = 'submarine_error'
                        print(cstart + 'Submarine Cable Search: ' + cend)
                        get_submarine(value)
                        print("\n")
                except KeyboardInterrupt:
                    print("\n" * 2)
                    print(cstart + "Ctrl-C was used to stop this script" + cend)
                    print("\n" * 2)
                    if value_list:
                        print(cstart + "Circuit List: " + cend)
                        for value in value_list:
                            error_code = 'usid_endless_error'
                            do_table_usid_endless(get_usid_quit(value))
                            print("\n")
                            # Search Submarine file for circuit
                            print(cstart + 'Submarine Circuit List: ' + cend)
                            for value in value_list:
                                error_code = 'submarine_error_endless'
                                get_submarine_endless(value)
                            print("\n" * 2)

            # Device Search Section

            # Search for dwdm devices

            elif search_type == 'dwdm':
                error_code = search_type
                do_output(get_dwdm(value), ["Router", "Interface", "Description", "CID", "USID", "State", "Comment",
                                            "NOC Field"])

            # Searches for IP-OOB devices based on the last octet of the device's IP address

            elif search_type == 'findoob':
                error_code = search_type
                value1 = '165.254.163.' + value
                value2 = '165.254.164.' + value
                do_output(get_findoob(value1, value2), ["Name", "Platform", "Loopback", "OS Name", "OS Revision"])

            # Search for iperf servers by listed value

            elif search_type == 'iperf':
                error_code = search_type
                do_output(get_iperf(value), ["Name", "Router", "Interface Name", "Ipv4 Address", "IPv6 Address"])
                iperf = value
                if iperf in iperf_servers:
                    print("Servers: \n" + iperf_servers[value] + "\n" * 2)
                else:
                    error_code = 'iperf_server'
                    not_gin()

            # Searches for modem lines by pop

            elif search_type == 'modem':
                error_code = search_type
                do_output(get_modem(value), ["Device Name", "Phone Number", "Linetype", "Status"])

            # Search for oob lines by device name

            elif search_type == 'oob':
                print()
                print(cstart + 'OOB WAN Search:' + cend)
                error_code = 'error_oob_wan'
                do_output(get_oob_wan(value), ["Router", "Interface", "Description", "IPv4", "State", "NOC Field"])
                print()
                print(cstart + 'OOB Line Search: ' + cend)
                error_code = search_type
                do_output(get_oob(value), ["Device Name", "Line Number", "Description", "Line Type", "AAA", "ACL",
                                           "Active", "Conserver?"])
                print(cstart + 'OOB Notes: ' + cend)
                error_code = 'error_oob_notes'
                # do_output(get_oob_notes(value), ["Notes"])
                do_output(get_oob_notes(value), None)

            # Search for routers by os revision

            elif search_type == 'osrev':
                error_code = search_type
                do_output(get_osrev(value), ["Name", "Platform", "Loopback", "OS Name", "OS Revision"])

            # Search for routers by OS Type

            elif search_type == 'ostype':
                error_code = search_type
                do_output(get_ostype(value), ["Name", "Platform", "Loopback", "OS Name", "OS Revision"])

            # Search for routers by Platform

            elif search_type == 'platform':
                error_code = search_type
                do_output(get_platform(value), ["Name", "Platform", "Loopback", "OS Name", "OS Revision"])

            # Search for route reflector clients and servers by server, client name, or cluster ID

            elif search_type == 'reflector':
                try:
                    val = int(value)
                except ValueError:
                    error_code = 'reflector'
                    do_output(get_reflector(value), ["Server", "Client", "Cluster ID"])
                else:
                    error_code = 'cluster'
                    do_output(get_cluster(value), ["Server", "Client", "Cluster ID"])

            # Search for routers by router name

            elif search_type == 'router' or search_type == 'routers':
                error_code = search_type
                do_output(get_router(value), ["Name", "Platform", "Loopback", "OS Name", "OS Revision", "State",
                                              "Region", "Dir"])

            # Search for satellite or ex customer devices by name

            elif search_type == 'sat':
                error_code = search_type
                do_output(get_sat(value), ["Description", "Router", "Interface", "State"])

            # Other Search Section

            # List all extended ACL's by search value

            elif search_type == 'acl':
                print()
                print(cstart + 'Extended ACLs' + cend)
                error_code = search_type
                do_output(get_eacl(value, filter), ["ACL Name", "Router", "Interface", "Bundle", "State", "USID",
                                                    "OS", "AFI", "Region"])

            # List all BH routes configured in tools.

            elif search_type == 'bh':
                error_code = search_type
                do_output(get_bh(value), ["Router", "Prefix", "Null0", "Community", "Description", "Date Configured"])

            # List all customer interfaces and their BGP sessions on the given router

            elif search_type == 'cb':
                error_code = 'router'
                do_output(get_cb(value), ["Router", "Interface", "Description", "ASN", "Neighbor IP"])

            # List the supplied LSP

            elif search_type == 'lsp':
                error_code = search_type
                do_output(get_lsp(value), ["LSP Name", "CSPF", "BW", "Priority"])

            # Lists all ISIS metrics by router name

            elif search_type == 'metric':
                try:
                    val = int(value)
                except ValueError:
                    error_code = 'metric_string'
                    do_output(get_metric_string(value), ["Router Name", "Interface", "Description", "ISIS Metric"])
                else:
                    error_code = 'metric_int'
                    do_output(get_metric_int(value), ["Router Name", "Interface", "Description", "ISIS Metric"])

            # List all circuits with MTU values less than 9174

            elif search_type == 'mtucheck':
                int_check(value)
                error_code = search_type
                do_output(get_mtucheck(value), ["Router", "Interface", "Description", "MTU"])

            # List statics by router or prefix

            elif search_type == 'statics':
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    error_code = 'error_statics_router'
                    do_output(get_statics(value), ["Router", "Prefix", "Next-Hop Interface", "Next-Hop IP", "Null0",
                              "Description", "Date Configured"])
                else:
                    ip_check(value)
                    error_code = search_type
                    do_output(get_statics_ip(value), ["Router", "Prefix", "Next-Hop Interface", "Next-Hop IP",
                              "Null0", "Description", "Date Configured"])

            # Search for telco by telco id

            elif search_type == 'telco':
                error_code = search_type
                do_output(get_telco(value), ["Name", "Abbr", "Phone", "Phone 800", "NOC Phone", "NOC Phone 800",
                          "NOC Email", "Notes"])

            # Search for l2vpn by VC ID

            elif search_type == 'vc':
                error_code = search_type
                do_output(get_vc(value), ["VC ID", "Customer", "Router", "Interface", "Z-Side", "USID",
                          "Int State"])

            # Search for hsrp
            elif search_type == 'hsrp':
                error_code = search_type
                do_output(get_hsrp(value), ["Router", "Interface", "Priority", "Description", "IPv4", "Standby IPv4",
                                            "Comment"])

            # Search for vrf
            elif search_type == 'vrf':
                error_code = search_type
                do_output(get_vrf(value), ["Router", "Interface", "Description", "IPv4 DST", "IPv6 DST", "TMS IP",
                                           "Active"])

            # Search for vrrp
            elif search_type == 'vrrp':
                error_code = search_type
                do_output(get_vrrp(value), ["Router", "Interface", "Priority", "Description", "IPv4", "Standby IPv4",
                                            "Comment"])

    # PSQL DB Error Checking

    except db.OperationalError as e:
        dsn = "postgresql://"
        if dbuser is not None:
            dsn += dbuser + ":" + dbpwd + "@"
        if args.dbhost is None:
            dsn += "localhost"
        else:
            dsn += args.dbhost
        if args.dbport is not None:
            dsn += ":" + str(args.dbport)
        print("ERROR with DSN " + dsn, e)
        sys.exit(1)
