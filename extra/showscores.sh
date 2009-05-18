#!/bin/bash

# May 2008, Dominik Klein
# Display scores of Linux-HA resources

# Known issues:
# * cannot get resource[_failure]_stickiness values for master/slave and clone resources
#   if those values are configured as meta attributes of the master/slave or clone resource
#   instead of as meta attributes of the encapsulated primitive

if [ "$1" = "--help" -o "$1" = "-h" ]
then
	echo "Usage: "
	echo "$0 (to display score information for all resources on all nodes sorted by resource name)"
	echo "$0 node (to display score information for all resources on all nodes sorted by nodename)"
	echo "$0 <resource-id> (to display score information for a specific resource on all nodes)"
	echo "$0 <resource-id> <nodename> (to display score information for a specific resource on a specific node)"
	echo "$0 <resource-id> <nodename> singlescore (to display just the score number (not additional info) for a specific resource on a specific node)"
	exit 0
fi

tmpfile=/tmp/dkshowscorestmpfiledk
tmpfile2=/tmp/dkshowscorestmpfile2dk
tmpfile3=/tmp/dkshowscorestmpfile3dk

if [ `crmadmin -D | cut -d' ' -f4` != `uname -n|tr "[:upper:]" "[:lower:]"` ] 
  then echo "Warning: Script is not running on DC. This will be slow."
fi

sortby=1
if [ "$1" = "node" ] 
then
	sortby=3
fi

export default_stickiness=`cibadmin -Q -o crm_config 2>/dev/null|grep "default[_-]resource[_-]stickiness"|grep -o -E 'value ?= ?"[^ ]*"'|cut -d '"' -f 2|grep -v "^$"`
export default_failurestickiness=`cibadmin -Q -o crm_config 2>/dev/null|grep "resource[_-]failure[_-]stickiness"|grep -o -E 'value ?= ?"[^ ]*"'|cut -d '"' -f 2|grep -v "^$"`

if [ -n "$1" -a "$1" != "node" ]
then
      resource=$1
fi
if [ -n "$2" ]
then
      nodename=$2
fi

2>&1 ptest -LVs | grep -E "$resource" | grep -E "$nodename" | sed 's/dump_node_scores\:\ //' > $tmpfile

parseline() {
	line="$1"
        node=`echo $line|cut -d " " -f 9|sed 's/://'`
        res=`echo $line|cut -d " " -f 5`
        score=`echo $line|cut -d " " -f 10|sed 's/1000000/INFINITY/'`
}

get_stickiness() {
	res="$1"
	# get meta attribute resource_stickiness
	if ! stickiness=`crm_resource -g resource_stickiness -r $res --meta 2>/dev/null`
	then
		# if that doesnt exist, get syntax like <primitive resource-stickiness="100"
		if ! stickiness=`crm_resource -x -r $res 2>/dev/null | grep -E "<master|<primitive|<clone" | grep -o "resource[_-]stickiness=\"[0-9]*\"" | cut -d '"' -f 2 | grep -v "^$"`
		then 
			# if no resource-specific stickiness is confiugured, use the default value
			stickiness="$default_stickiness"
		fi	
	fi

	# get meta attribute resource_failure_stickiness
	if ! failurestickiness=`crm_resource -g resource_failure_stickiness -r $res --meta 2>/dev/null`
	then
		# if that doesnt exist, use the default value
		failurestickiness="$default_failurestickiness"
	fi	
}

get_failcount() {
	res="$1"
	node="$2"
        failcount=`crm_failcount -G -r $res -U $node 2>/dev/null|grep -o -E 'value ?= ?INFINITY|value ?= ?[0-9]*'|cut -d '=' -f 2|grep -v "^$"`
}

unset group_resources
# display group scores
grep group_color $tmpfile | while read line
do
        unset node res score stickiness failcount failurestickiness
        parseline "$line"
        get_stickiness $res
        get_failcount $res $node
        printf "%-20s%-10s%-16s%-11s%-9s%-16s\n" $res $score $node $stickiness $failcount $failurestickiness
	export group_resources="$res $group_resources"
	echo $group_resources > $tmpfile3
done >> $tmpfile2

# display allocation scores
grep -v master_color $tmpfile | grep -v clone_color | grep -v group_color | while read line
do
	unset node res score stickiness failcount failurestickiness
	parseline "$line"
	#skip group resources
	if grep -q -w $res $tmpfile3
	then
		#echo skipping $res as it is part of a group and their score is shown in the group_color lines
		continue
	fi
	get_stickiness $res
	get_failcount $res $node
	printf "%-20s%-10s%-16s%-11s%-9s%-16s\n" $res $score $node $stickiness $failcount $failurestickiness
done >> $tmpfile2

# display promotion scores
grep master_color $tmpfile | while read line
do
	unset node res score stickiness failcount failurestickiness
	parseline "$line"
	inflines=`grep master_color $tmpfile | grep $res | grep 1000000 | wc -l`
	if [ $inflines -eq 1 ]
	then
		# [10:24] <beekhof> the non INFINITY values are the true ones
		# [10:25] <kleind> except for when the actually resulting score is [-]INFINITY
		# [10:25] <beekhof> yeah
		actualline=`grep master_color $tmpfile | grep $res | grep -v 1000000`
		parseline "$actualline"
	fi
	get_stickiness $res
	get_failcount $res $node
	res=$res"_(master)"
	printf "%-20s%-10s%-16s%-11s%-9s%-16s\n" $res $score $node $stickiness $failcount $failurestickiness
done | sort | uniq >> $tmpfile2


if [ "$3" = "singlescore" ]
then
	sed 's/  */ /g' $tmpfile2 | cut -d ' ' -f 2 | tail -n 1
else
	# Heading
	printf "%-20s%-10s%-16s%-11s%-9s%-16s\n" "Resource" "Score" "Node" "Stickiness" "#Fail" "Fail-Stickiness"
	sort -k $sortby $tmpfile2
fi

rm -f $tmpfile $tmpfile2 $tmpfile3
