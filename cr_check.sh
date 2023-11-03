#!/bin/bash 

IFS=$'\n'

#usage ./thisscript VNOCnumber
#show a maint/outage current status

LANG="en_US.UTF8" ; export LANG
dated=`date +%Y%m%d%H%M`
hflags=0

#Matsu
forstid=`id`
if [[ $forstid =~ "noc" ]];then
	echo $dated $forstid >> /home/matsu/mtls/crcheckstat
fi
if [ $# -lt 1 ]
then
	echo
	echo "Usage: ./thisscript GIN/VNOC-ticket-number"
	echo "Usage: ./thisscript V-ticket-number"
	echo "Usage: ./thisscript cid"
	echo "Usage: ./thisscript cid1 cid2..."
	echo "Usage: ./thisscript -h cid... or GIN/VNOC"
	echo "		-h mode is find circuit history"
        echo "Usage: ./thisscript -c cid... or GIN/VNOC"
        echo "          -c mode is clear each interaces statistics such as errors"
	exit
fi

if [[ $1 =~ ^GIN|VNOC ]] ;
then
	vflags=1
	for listarray in $(psql -d cfgtools -c "SELECT d.device_name AS router, i.ifc_name, i.noc_field, i.cid, cis.ifc_state AS state FROM ct_ifcs i JOIN ct_devices d ON d.device_id = i.device_id JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id LEFT JOIN ct_vendor v ON v.vendor_id = i.telco_id where i.noc_field ~* '$1'" --tuples-only) ; do
        	echo $listarray >> $dated.listarray.tmp
	done
elif [[ $2 =~ ^GIN|VNOC ]] ;
then
	vflags=1
        for listarray in $(psql -d cfgtools -c "SELECT d.device_name AS router, i.ifc_name, i.noc_field, i.cid, cis.ifc_state AS state FROM ct_ifcs i JOIN ct_devices d ON d.device_id = i.device_id JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id LEFT JOIN ct_vendor v ON v.vendor_id = i.telco_id where i.noc_field ~* '$2'" --tuples-only) ; do
                echo $listarray >> $dated.listarray.tmp
        done
elif [[ $1 =~ ^V- ]] ;
then
	vflags=1
        for listarray in $(psql -d cfgtools -c "SELECT d.device_name AS router, i.ifc_name, i.noc_field, cust_id, cis.ifc_state AS state FROM ct_ifcs i JOIN ct_devices d ON d.device_id = i.device_id JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id LEFT JOIN ct_vendor v ON v.vendor_id = i.telco_id where i.noc_field ~* '$1'" --tuples-only) ; do
                echo $listarray >> $dated.listarray.tmp
        done
elif [[ $2 =~ ^V- ]] ;
then
	vflags=1
        for listarray in $(psql -d cfgtools -c "SELECT d.device_name AS router, i.ifc_name, i.noc_field, cust_id, cis.ifc_state AS state FROM ct_ifcs i JOIN ct_devices d ON d.device_id = i.device_id JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id LEFT JOIN ct_vendor v ON v.vendor_id = i.telco_id where i.noc_field ~* '$2'" --tuples-only) ; do
                echo $listarray >> $dated.listarray.tmp
        done
fi
if [ $# -ge 1 ] && [[ $1 = -h ]] ;
then
	echo "find circuit history. the cid or multiple cids here:"
	hflags=1
	for i in $*
	do
		if [[ $i = -h ]];
		then
			continue
		fi
		if [[ $vflags -ne 1 ]] ;
		then
			cidi=${i}
			echo $cidi
			for listarray in $(psql -d cfgtools -c  "SELECT d.device_name AS router, i.ifc_name, i.noc_field, i.cid, cis.ifc_state AS state FROM ct_ifcs i JOIN ct_devices d ON d.device_id = i.device_id JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id LEFT JOIN ct_vendor v ON v.vendor_id = i.telco_id where i.cid ~* '$cidi' " --tuples-only) ; do
				echo $listarray >> $dated.listarray.tmp
			done
		else
			cat $dated.listarray.tmp
			continue
		fi
	done
	echo "how many days log do you need? [1-20, default:1]"
	read logdays
	if [[ $logdays = "" ]];
	then
		logdays=1
	fi
	if [ $logdays -eq 1 ];
	then
		echo "alright. just today"
		echo " "
		cat /var/log/local7/debug > $dated.syslogc
		cat /var/log/local5/debug > $dated.syslogj
	elif [ $logdays -ge 2 ] && [ $logdays -le 20 ];
	then
		echo "alright. $logdays days."
		echo " "
		ls -lt /var/log/local7/ | grep debug | grep .gz | awk '{print $9}' | head -$logdays | sort | xargs -IXXXX gzcat /var/log/local7/XXXX >> $dated.syslogc
		ls -lt /var/log/local5/ | grep debug | grep .gz | awk '{print $9}' | head -$logdays | sort | xargs -IXXXX gzcat /var/log/local5/XXXX >> $dated.syslogj
		cat /var/log/local7/debug >> $dated.syslogc
                cat /var/log/local5/debug >> $dated.syslogj
		#smart!
	else
		echo "something wrong. aborted."
		rm $dated.listarray.tmp
		exit
	fi
elif [ $# -ge 1 ] && [[ $1 = -c ]] ;
then
	echo "clear interfaces mode."
	cflags=1
        echo "do you really want to clear interfaces? [y]"
        read reallyornot
        if [[ $reallyornot != "y" ]];
        then
		echo "meh, whatever. as you wish"
                exit
        fi
fi
if [ $# -ge 1 ] && [[ $vflags -ne 1 ]] && [[ $hflags -ne 1 ]] ;
then
	echo "the cid or multiple cids here:"
	for i in $*
	do
		if [[ $i = -c ]] || [[ $i = -h ]] ;
                then
                        continue
                fi
		cidi=${i}
		echo $cidi
		#for listarray in $(psql -d cfgtools -c  "select router,ifc_name,noc_field,cid,state from interfaces where cid ~* '$cidi' " --tuples-only) ; do
                for listarray in $(psql -d cfgtools -c  "SELECT d.device_name AS router, i.ifc_name, i.noc_field, i.cid, cis.ifc_state AS state FROM ct_ifcs i JOIN ct_devices d ON d.device_id = i.device_id JOIN ct_ifcs_state cis ON cis.ifc_state_id = i.ifc_state_id LEFT JOIN ct_vendor v ON v.vendor_id = i.telco_id where i.cid ~* '$cidi' " --tuples-only) ; do
			echo $listarray >> $dated.listarray.tmp
		done
	done
fi


cat $dated.listarray.tmp | sort -k1 > $dated.listarray
cat $dated.listarray
echo " "

passwd=`grep $USER"@" $HOME/.cloginrc | awk -F "{" '{print $2}' | awk -F "}" '{print $1}'`

for eachnode in $(cat $dated.listarray | awk '{print $1}' | uniq) ; do
	echo $eachnode
        jorc=(`psql -d cfgtools -c "select routers.os_name,routers.os_rev from routers where routers.name = '$eachnode'" | sed 1,2d | sed 1,1\!d | awk -F\| '{print $1 $2}'`)
#	echo ${jorc[0]}
#	if [[ ${jorc[0]} = 5.3.4 ]] ; then
#		echo "Detected 5.3.4"
#	else
#		echo "Detected except 5.3.4"
#	fi
        if [[ ${jorc[0]} =~ iox ]] && [[ $hflags = 0 ]] ; then
		for eachint in $(cat $dated.listarray | grep $eachnode | awk '{print $3}') ; do
#			if [[ $cflags = 1 ]] ; then
### Added below for fix about cisco clear command update due to depends on revision. by Wataru(4th Dec 2019)
			if [[ $cflags = 1 ]] && [[ ${jorc[0]} =~ 5.3.4 ]] ; then
				expect -c "
set timeout 5
log_user 0
spawn ssh $eachnode
expect \"assword:\"
send \"$passwd\n\"
expect \"#\"
log_user 1
send \"clear counters $eachint\n\"
expect \"]\"
send \"y\n\"
log_user 0
expect \"#\"
send \"exit\n\"
"
				echo ""
#			fi
			elif [[ $cflags = 1 ]] ; then
				expect -c "
set timeout 5
log_user 0
spawn ssh $eachnode
expect \"assword:\"
send \"$passwd\n\"
expect \"#\"
log_user 1
send \"clear counters interface $eachint\n\"
expect \"]\"
send \"y\n\"
log_user 0
expect \"#\"
send \"exit\n\"
"
				echo ""
			fi
			tmpcommand="show int "$eachint" desc"
			echo $tmpcommand >> $dated.$eachnode
			tmpcommand2="show contr "$eachint" phy | inc \"x P | dBm\""
                        echo $tmpcommand2 >> $dated.$eachnode
			tmpcommand3="show int "$eachint" | inc \"error|rate\""
			echo $tmpcommand3 >> $dated.$eachnode
			if [[ ${jorc[0]} =~ 5.3.4 ]] ; then
				tmpcommand4="show log | utility fgrep -i $eachint | utility tail count 2"
			else
				tmpcommand4="show log | utility fgrep $eachint -i | utility tail count 2"
				#due to cisco's bug? less than 5.3.4 iox does not accept correctable grep grammer. silly hack.
			fi
			echo $tmpcommand4 >> $dated.$eachnode
		done
	elif [[ ${jorc[0]} =~ iox ]] && [[ $hflags = 1 ]] ; then
		for eachint in $(cat $dated.listarray | grep $eachnode | awk '{print $3}') ; do
			echo $eachint >> $dated.$eachnode
		done
	elif [[ ${jorc[0]} =~ junos ]] && [[ $hflags = 0 ]] ; then
		for eachint in $(cat $dated.listarray | grep $eachnode | awk '{print $3}') ; do
                        if [[ $cflags = 1 ]] ; then
                                tmpcommandc="clear interfaces statistics "$eachint
                                echo $tmpcommandc >> $dated.$eachnode
                        fi
                        tmpcommand="show interfaces "$eachint" descriptions"
                        echo $tmpcommand >> $dated.$eachnode
			tmpcommand2="show interfaces "$eachint" extensive | match \"cleared|flap\""
			echo $tmpcommand2 >> $dated.$eachnode
			tmpcommand3="show interfaces diagnostics optics "$eachint" | match \"output|receive|rx\" |except alarm|except warning"
			echo $tmpcommand3 >> $dated.$eachnode
			tmpcommand4="show interfaces "$eachint" | match rate"
			echo $tmpcommand4 >> $dated.$eachnode
			#tmpcommand5="show interfaces "$eachint" extensive | match \"rrors:\""
                        #echo $tmpcommand5 >> $dated.$eachnode
			tmpcommand5="show interfaces "$eachint" extensive | match \"FIFO errors:\""
                        echo $tmpcommand5 >> $dated.$eachnode
                done
        elif [[ ${jorc[0]} =~ junos ]] && [[ $hflags = 1 ]] ; then
                for eachint in $(cat $dated.listarray | grep $eachnode | awk '{print $3}') ; do
			echo $eachint >> $dated.$eachnode
                done
	fi

#	cat $dated.$eachnode

	if [[ ${jorc[0]} =~ iox ]] && [[ $hflags = 0 ]] ; then
		echo "-----------------------------------------------------------------------"
	        for j in $(/opt/gums/bin/clogin -x $dated.$eachnode $eachnode) ; do
                        echo $j | grep -e "/" -e "second input rate" -e "put errors" -e "(" | grep -v "bb#" | grep -v "Permanently added" | grep -v "Transmit" | grep -v "Receive" > $dated.put.tmp
			if [[ $j =~ down ]] ; then
                                jtmp=`cat $dated.put.tmp`
				echo -e '\033[31m'$jtmp'\033[0m'
                        elif [[ $j =~ "rate 0 bits/sec" ]] ; then
                                jtmp=`cat $dated.put.tmp`
                                echo -e '\033[31m'$jtmp'\033[0m'
                        elif [[ $j =~ "#show" ]] ; then
				echo ""
			else
                                cat $dated.put.tmp
                        fi
			rm $dated.put.tmp
			
			#echo $j | grep "/" | grep -v "#"
			#echo $j | grep "(" | grep -v "#" | grep -v "Transmit" | grep -v "Receive"
        	done
        elif [[ ${jorc[0]} =~ iox ]] && [[ $hflags = 1 ]] ; then
                echo "-----------------------------------------------------------------------"
		for j in $(cat $dated.$eachnode) ; do
			j1=`psql -d cfgtools --no-align --tuples-only -c "select CONCAT(intf_type,': ',name,' - ',telco,' ',cid,' ',comment) as description,state from interfaces where ifc_name = '$j' and router = '$eachnode'"`
			echo $eachnode" "$j" ( "$j1" )"
			echo "----------------------------"
			cat $dated.syslogc | grep $eachnode | grep -i $j | awk '{for(i=5;i<NF;i++){printf("%s%s",$i,OFS=" ")}print $NF}' | sed -e 's/<...>//'
			echo ""
		done
	elif [[ ${jorc[0]} =~ junos ]] && [[ $hflags = 0 ]] ; then
		echo "-----------------------------------------------------------------------"
	        for j in $(/opt/gums/bin/jlogin -x $dated.$eachnode $eachnode) ; do
        	        echo $j | grep -e ":" -e "clear interfaces statistics" | grep -v "assword" | grep -v "JUNOS" | grep -v "rate at Packet Forwarding Engine" | grep -v "Permanently added" > $dated.put.tmp
			if [[ $j =~ down ]] ; then
				jtmp=`cat $dated.put.tmp`
				echo -e '\033[31m'$jtmp'\033[0m'
			elif [[ $j =~ " 0 bps " ]] ; then
				jtmp=`cat $dated.put.tmp`
				echo -e '\033[31m'$jtmp'\033[0m'
			elif [[ $j =~ "> show" ]] ; then
				echo ""
			else
				cat $dated.put.tmp
			fi
			rm $dated.put.tmp
			#sed -i -e "s/down/\033[31m down \033[0m/g" $dated.put.tmp
			#echo $j | grep ":" | grep -v "assword" | grep -v "JUNOS"
	        done
        elif [[ ${jorc[0]} =~ junos ]] && [[ $hflags = 1 ]] ; then
                echo "-----------------------------------------------------------------------"
		for j in $(cat $dated.$eachnode) ; do
                        j1=`psql -d cfgtools --no-align --tuples-only -c "select CONCAT(intf_type,': ',name,' - ',telco,' ',cid,' ',comment) as description,state from interfaces where ifc_name = '$j' and router = '$eachnode'"`
                        echo $eachnode" "$j" ( "$j1" )"
			echo "----------------------------"
			cat $dated.syslogj | grep $eachnode | grep -i $j | awk '{for(i=5;i<NF;i++){printf("%s%s",$i,OFS=" ")}print $NF}' | sed -e 's/<...>//'
			echo ""
		done
	fi
	echo " "
	rm $dated.$eachnode
done

rm $dated.listarray.tmp
rm $dated.listarray

if [[ $hflags = 1 ]] ;
then
	rm $dated.syslogc
	rm $dated.syslogj
fi


