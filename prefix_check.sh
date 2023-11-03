#!/bin/bash
if [ -z $1 ] || [ -z $2 ];then
	echo "usage = prefix_check.sh asn prefix"
	exit
else
	:
fi
newserch=`psql -d cfgtools -c "select router,ip_addr from peers left join autnum on autnum.asn = peers.asn left join pcontact on pcontact.asn = peers.asn where peers.asn ='$1';" -t | tr '\n' ',' | sed -e s/,$//g`
psql -d cfgtools -c "select description from peers left join autnum on autnum.asn = peers.asn left join pcontact on pcontact.asn = peers
.asn where peers.asn ='$1';" -t | sort | uniq
echo;echo ------- All neighbors for this ASN ---------
echo $newserch | sed -e 's/ [ar]/\nr/g'
OIFS=$IFS
IFS=','
for item in $newserch; do
router_name=`echo $item | awk -F "|" '{print$1}' | tr -d ' '`
neighbor_add=`echo $item | awk -F "|" '{print$2}' | tr -d ' '`
mfc=`psql -d cfgtools -c "SELECT d.device_name AS name, host(v4.ipv4) AS loopback,ct_mfg.mfg_name AS mfg FROM ct_devices d JOIN ct_routers
r ON r.device_id = d.device_id LEFT JOIN ct_devices_state s ON d.device_state_id = s.state_id LEFT JOIN ct_os_name o ON d.os_name_id
= o.os_name_id LEFT JOIN ct_platform p ON d.platform_id = p.platform_id LEFT JOIN ct_mfg ON p.mfg_id = ct_mfg.mfg_id LEFT JOIN ct_ifcs i
 ON i.device_id = d.device_id AND i.issource_ifc LEFT JOIN ct_proto_ipv4 v4 ON v4.ifc_id = i.ifc_id AND v4.isprimary where d.device_name
='$router_name';"`
if echo $2 | grep ":" > /dev/null; then
	if echo $neighbor_add | grep ":" > /dev/null; then
		flg=ipv6
	fi
else
	if echo $neighbor_add | grep -v ":" > /dev/null; then
		flg=ipv4
	fi
fi

if echo $flg | grep "ip" >/dev/null; then
echo;echo "========== checking "$router_name" (BGP "$neighbor_add") ============"
if echo $mfc | grep "juni" >/dev/null; then
	jlogin -t 35 -c "show route $2;show route receive-protocol bgp $neighbor_add | match $2" $router_name | grep $2
else
	if echo $2 | grep ":" > /dev/null; then
		clogin -t 35 -c "show route ipv6 $2;show bgp ipv6 unicast $2;sh bgp ipv6 unicast neighbors $neighbor_add route | i $2" $r
outer_name | grep $2
	else
		clogin -t 35 -c "show route $2;show bgp $2;sh ip bgp neigh $neighbor_add routes | i $2" $router_name | grep $2
	fi
fi
fi
flg=none

done
IFS=$OIFS
