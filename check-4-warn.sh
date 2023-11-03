#!/bin/csh
# jsaine -- 10/17/2018
echo "Here are the at-risk circuits (CHECK-4-WARN):"
psql -d cfgtools -c "select comment,router,ifc_name,state,name,telco || ' ' || cid as desc from interfaces inh where intf_type = 'BB' AND ifc_name NOT LIKE 'em%' AND router SIMILAR TO '(r|a)%.bb' AND name SIMILAR TO '(r|a)%.bb %' AND router NOT LIKE '%labx%' AND router NOT LIKE '%test%' AND state IN ('up', 'maint', 'outage', 'failure') AND (select count(*) from interfaces our where intf_type = 'BB' AND router SIMILAR TO '(r|a)%.bb' AND name SIMILAR TO '(r|a)%.bb %' AND state IN ('up', 'maint', 'outage', 'failure') AND inh.router=our.router) <=2 ORDER BY split_part(router, '.', 2), split_part(router, '.', 1), ifc_name;" --pset pager=off
echo ""
echo "Circuits wrongly marked at-risk with 'CHECK-4-WARN' comment:"
psql -d cfgtools -c "select comment,router,ifc_name,state,name,telco || ' ' || cid as desc from interfaces inh where comment = 'CHECK-4-WARN' AND (select count(*) from interfaces our where intf_type = 'BB' AND router SIMILAR TO '(r|a)%.bb' AND name SIMILAR TO '(r|a)%.bb %' AND state IN ('up', 'maint', 'outage', 'failure') AND inh.router=our.router) >2 ORDER BY split_part(router, '.', 2), split_part(router, '.', 1), ifc_name;"
# echo ""
#echo "Here is what has CHECK-4-WARN set:"
# psql -d cfgtools -c "SELECT router,ifc_name,name,telco || ' ' || cid as desc, comment FROM interfaces WHERE comment = 'CHECK-4-WARN' ORDER BY split_part(router, '.', 2), split_part(router, '.', 1), ifc_name;" --pset pager=off
