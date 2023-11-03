#!/bin/bash

IFS=$'\n'

#usage ./thisscript alarm-count
#

LANG="en_US.UTF8" ; export LANG
dated=`date +%Y%m%d%H%M`
dated_forday=`date +%Y%m%d`

if [ $# -lt 1 ]
then
echo
echo "Usage: ./thisscript -b all-routers-recent-alarm-number-you-want | -j junipers-recent-alarm-number-you-want -c ciscos-recent-alarm-number-you-wanti [-y] adding yesterday [-i] ignoring IGNORE and MAINT OUTAGE"
echo "----------"
echo "This script will be serching gin routers syslog messages(only today) and showing interfaces with description which is hard link down."
echo "ex) ./thisscript -b 30"
echo "ex) ./thisscript -j 30 -c 10"
echo "-Matsu"
exit
fi

usage_exit() {
        echo "Usage: ./thisscript -b all-routers-recent-alarm-number-you-want -j junipers-recent-alarm-number-you-want -c ciscos-recent-alarm-number-you-want" 1>&2
        exit 1
}

jcount=0
ccount=0
yesterdayflag=0
ignoreflag=0

echo args=$@

while getopts b:j:c:yi OPT
do
	case $OPT in
                "b")     jcount=$OPTARG
                        ccount=$OPTARG
                        ;;
		"j")	jcount=$OPTARG
			;;
		"c")	ccount=$OPTARG
			;;
		"y")	yesterdayflag=1
			;;
		"i")	ignoreflag=1
			;;
		\?)	usage_exit
			;;
	esac
done
shift $((OPTIND - 1))
forstid=`id`
echo $dated $forstid >> /home/matsu/mtls/multidetstat

if [ $yesterdayflag -eq 1 ] ; then
	for sysloglinesj in $(gzcat /var/log/local5/debug-$dated_forday.gz | grep SNMP_TRAP_LINK) ; do
		echo $sysloglinesj >> $dated.sysloglinesj
	done
	for historycuttedj in $(cat $dated.sysloglinesj | grep -e "SNMP_TRAP_LINK" | awk '{print $1" "$2" "$3" "$4" "$18}') ; do
        	echo $historycuttedj >> $dated.historycuttedj1
	done
	rm $dated.sysloglinesj
fi
for sysloglinesj in $(cat /var/log/local5/debug | grep SNMP_TRAP_LINK) ; do
	echo $sysloglinesj >> $dated.sysloglinesj
done
for historycuttedj in $(cat $dated.sysloglinesj | grep -e "SNMP_TRAP_LINK" | awk '{print $1" "$2" "$3" "$4" "$18}') ; do
	echo $historycuttedj >> $dated.historycuttedj1
done
cat $dated.historycuttedj1 | sort -k1M -k2n -k3n | tail -$jcount >> $dated.historycuttedj
#cat $dated.historycuttedj1 >> $dated.historycuttedj
cat $dated.historycuttedj | awk '{print $4" "$5}' | egrep -v ^s | sort | uniq >> $dated.interfacesj
cp $dated.historycuttedj $dated.updownresultj
for interfaceslinesj in $(cat $dated.interfacesj) ; do
	interfaceslinesjnode=`echo $interfaceslinesj | awk '{print $1}' | sed -e "s/\.gin\.ntt\.net//g"`
	interfaceslinesjint=`echo $interfaceslinesj | awk '{print $2}'`
	intnm=`echo $interfaceslinesjint | sed -e "s/[\r\n]\+//g" | sed -e "s/\.[^.]*$//g"`
	for j in $(psql -d cfgtools --no-align --tuples-only -c "select intf_type from interfaces where ifc_name = '$intnm' and router = '$interfaceslinesjnode'") ; do
		if [ "$j" = "BB" -o "$j" = "BE" ] ; then
			j1=`psql -d cfgtools --no-align --tuples-only -c "select CONCAT(intf_type,': ',name,' - ',telco,' ',cid,' ',comment) as description,state from interfaces where ifc_name = '$intnm' and router = '$interfaceslinesjnode'"`
		elif [ "$j" = "BC" -o "$j" = "BD" ] ; then
			j1=`psql -d cfgtools --no-align --tuples-only -c "select CONCAT(intf_type,': ',name,' - ',telco,' ',cid,' USID ',cust_id,' ',comment) as description,state from interfaces where ifc_name = '$intnm' and router = '$interfaceslinesjnode'"`
		elif [ "$j" = "BP" ] ; then
			j1=`psql -d cfgtools --no-align --tuples-only -c "select CONCAT(intf_type,': ',name,' - ',telco,' ',cid,' ',comment) as description,state from interfaces where ifc_name = '$intnm' and router = '$interfaceslinesjnode'"`
		else
			j1=`psql -d cfgtools --no-align --tuples-only -c "select CONCAT(intf_type,': ',name,' - ',telco,' ',cid,' USID ',cust_id,' ',comment) as description,state from interfaces where ifc_name = '$intnm' and router = '$interfaceslinesjnode'"`
		fi
		forsum=`psql -d cfgtools --no-align --tuples-only -c "select CONCAT(intf_type,': ',name,' - ',telco,' ',cid,' ',comment) as description,state from interfaces where ifc_name = '$intnm' and router = '$interfaceslinesjnode'"`
		echo $interfaceslinesjnode" "$intnm" "$forsum >> $dated.summarycircuits
#		echo $j1 
		j2=`echo ${j1} | sed -e 's/|up//'`
		if [ ! -z $j2 ] ; then
			echo $interfaceslinesj $j2 | sed '/^$/d' >> $dated.descriptionsj
			tmpa=`echo ${interfaceslinesj} | sed -e "s/[\r\n]\+//g"`
			tmpb=`echo ${j2} | sed -e "s/[\r\n]\+//g"`
			sed -i -e "s#$tmpa#$tmpa,$tmpb#" $dated.updownresultj
		fi
	done
done
rm $dated.descriptionsj
rm $dated.historycuttedj
rm $dated.historycuttedj1
rm $dated.interfacesj
rm $dated.sysloglinesj

if [ $yesterdayflag -eq 1 ] ; then
	for sysloglinesc in $(gzcat /var/log/local7/debug-$dated_forday.gz | grep PKT_INFRA-LINEPROTO-5-UPDOWN) ; do
            echo $sysloglinesc >> $dated.sysloglinesc
        done
        for historycuttedc in $(cat $dated.sysloglinesc | grep -e "Down" -e "Up" | awk '{print $1" "$2" "$3" "$4" "$17" "$21}' | tr -d ',') ; do
                echo $historycuttedc >> $dated.historycuttedc1
        done
	rm $dated.sysloglinesc
fi
for sysloglinesc in $(cat /var/log/local7/debug | grep PKT_INFRA-LINEPROTO-5-UPDOWN) ; do
	echo $sysloglinesc >> $dated.sysloglinesc
done
for historycuttedc in $(cat $dated.sysloglinesc | grep -e "Down" -e "Up" | awk '{print $1" "$2" "$3" "$4" "$17" "$21}' | tr -d ',') ; do
        echo $historycuttedc >> $dated.historycuttedc1
done
cat $dated.historycuttedc1 | sort -k1M -k2n -k3n | tail -$ccount >> $dated.historycuttedc
#cat $dated.historycuttedc1 >> $dated.historycuttedc
cat $dated.historycuttedc | awk '{print $4" "$5}' | sort | uniq >> $dated.interfacesc
cp $dated.historycuttedc $dated.updownresultc
for interfaceslinesc in $(cat $dated.interfacesc) ; do
        interfaceslinescnode=`echo $interfaceslinesc | awk '{print $1}' | sed -e "s/\.gin\.ntt\.net//g"`
        interfaceslinescint=`echo $interfaceslinesc | awk '{print $2}'`
	intnm_c=`echo $interfaceslinescint | sed -e "s/[\r\n]\+//g" | sed -e "s/\.[^.]*$//g" | tr '[A-Z]' '[a-z]'`
        for j in $(psql -d cfgtools --no-align --tuples-only -c "select intf_type from interfaces where ifc_name = '$intnm_c' and router = '$interfaceslinescnode'") ; do
                if [ "$j" = "BB" -o "$j" = "BE" ] ; then
                        j1=`psql -d cfgtools --no-align --tuples-only -c "select CONCAT(intf_type,': ',name,' - ',telco,' ',cid,' ',comment) as description,state from interfaces where ifc_name = '$intnm_c' and router = '$interfaceslinescnode'"`
                elif [ "$j" = "BC" -o "$j" = "BD" ] ; then
                        j1=`psql -d cfgtools --no-align --tuples-only -c "select CONCAT(intf_type,': ',name,' - ',telco,' ',cid,' USID ',cust_id,' ',comment) as description,state from interfaces where ifc_name = '$intnm_c' and router = '$interfaceslinescnode'"`
                elif [ "$j" = "BP" ] ; then
                        j1=`psql -d cfgtools --no-align --tuples-only -c "select CONCAT(intf_type,': ',name,' - ',telco,' ',cid,' ',comment) as description,state from interfaces where ifc_name = '$intnm_c' and router = '$interfaceslinescnode'"`
                else
                        j1=`psql -d cfgtools --no-align --tuples-only -c "select CONCAT(intf_type,': ',name,' - ',telco,' ',cid,' USID ',cust_id,' ',comment) as description,state from interfaces where ifc_name = '$intnm_c' and router = '$interfaceslinescnode'"`
                fi
                forsum=`psql -d cfgtools --no-align --tuples-only -c "select CONCAT(intf_type,': ',name,' - ',telco,' ',cid,' ',comment) as description,state from interfaces where ifc_name = '$intnm_c' and router = '$interfaceslinescnode'"`
                echo $interfaceslinescnode" "$intnm_c" "$forsum >> $dated.summarycircuits
#		echo $j1
		j2=`echo ${j1} | sed -e 's/|up//'`
                if [ ! -z $j2 ] ; then
                        echo $interfaceslinesc $j2 | sed '/^$/d' >> $dated.descriptionsc
                        tmpa=`echo ${interfaceslinesc} | sed -e "s/[\r\n]\+//g"`
                        tmpb=`echo ${j2} | sed -e "s/[\r\n]\+//g"`
                        sed -i -e "s#$tmpa#$tmpa,$tmpb#" $dated.updownresultc
                fi
        done
done
rm $dated.descriptionsc
rm $dated.historycuttedc
rm $dated.historycuttedc1
rm $dated.interfacesc
rm $dated.sysloglinesc

sed -i "s/|turn\-up/  --IGNORE--/" $dated.updownresultj
sed -i "s/|turn\-up/  --IGNORE--/" $dated.updownresultc
sed -i "s/|outage/  --OUTAGE--/" $dated.updownresultj
sed -i "s/|outage/  --OUTAGE--/" $dated.updownresultc
sed -i "s/|maint/  --MAINT--/" $dated.updownresultj
sed -i "s/|maint/  --MAINT--/" $dated.updownresultc
sed -i "s/|failure/  --FAILURE--/" $dated.updownresultj
sed -i "s/|failure/  --FAILURE--/" $dated.updownresultc

echo sorted cisco $ccount and juniper $jcount logs as below
#cat $dated.updownresultj $dated.updownresultc | sort -k2M -k3 -k4 | sed -e "s/\.gin\.ntt\.net//g"
cat $dated.updownresultj $dated.updownresultc | grep -v IGNORE | grep -v MAINT | grep -v OUTAGE | grep -v FAILURE | sort -k1M -k2n -k3n | sed -e "s/\.gin\.ntt\.net//g"
echo ""
echo "flapped/down circuits (without IGNORE/MAINT/OUTAGE):"
cat $dated.summarycircuits | grep -v turn-up | grep -v maint | grep -v outage | grep -v failure
echo ""
echo "BB summary:"
cat $dated.updownresultj $dated.updownresultc | sort -k2M -k3 -k4 | sed -e "s/\.gin\.ntt\.net//g" > $dated.all
sed -i -e "s/,/ /g" $dated.all
cat $dated.all | grep BE: | awk '{print $4" "$5" "$7}' | sort | uniq > $dated.BE
cat $dated.all | grep BB: | awk '{print $4" "$5" "$7" "$8}' | sort | uniq | sed -e "s/[0-9]{1,3}-/\//g" > $dated.BB
cat $dated.BE
cat $dated.BB

rm $dated.BE
rm $dated.BB
rm $dated.all
rm $dated.summarycircuits
rm $dated.updownresultc
rm $dated.updownresultj
