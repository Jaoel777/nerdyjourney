#!/bin/bash
if [ $# -lt 1 ]; then
        echo "Usage : $0 <router>"
        exit
fi
snmp_pw=$(psql -d cfgtools -c "select snmp_ro from routers where fqdn ~* '$1'" -At)
if [ -n "$snmp_pw" ]; then
	echo "snmpwalk -v 2c -c <pw> \"$1\" system"
	snmpwalk -v 2c -c "$snmp_pw" "$1" system
else
	echo "empty pw. exiting"
fi
