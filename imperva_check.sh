#!/bin/bash

if [[ -z $1 ]] ; then
    echo "no host ip provided"
    exit

else

    while read R N; do (
        O="$(/opt/gums/bin/clogin -c "show clock;show route "$1"" "$R" &)"
        F="$(echo "$O" | grep "$N")"
        if [[ ! -z $F ]]  ; then
            echo "$R $N: found"
        else
            echo "$R $N: not found"
        fi ) &
    done <<EOF
        `$HOME/config/noc/noc-scripts/noc_search.py bgp 19551 | grep up | egrep -v ":|lab" | sed '1d' | awk '{print $(NF-6),$(NF-5)}' | sort`
EOF
    wait
fi
