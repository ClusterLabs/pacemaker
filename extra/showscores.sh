#!/bin/bash
#
# Copyright (C) 2008-2010 Dominik Klein
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

# Display scores of Pacemaker resources

if [ "$1" = "--help" -o "$1" = "-h" ]
then
	echo "showscores.sh - basically parsing crm_simulate -Ls."
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

#doesnt work in ais clusters
if ! ps -ef|grep -q -w aisexec; then
	if [ `crmadmin -D | cut -d' ' -f4` != `uname -n|tr "[:upper:]" "[:lower:]"` ] 
		then echo "Warning: Script is not running on DC. This will be slow."
	fi
fi

sortby=1
if [ "$1" = "node" ] 
then
	sortby=3
fi

export default_stickiness=`crm_attribute -G -n default-resource-stickiness -t rsc_defaults -Q 2>/dev/null`
if [ -z "$default_stickiness" ]; then default_stickiness=0; fi
export default_migrationthreshold=`crm_attribute -G -n migration-threshold -t rsc_defaults -Q 2>/dev/null`

if [ -n "$1" -a "$1" != "node" ]
then
      resource=$1
fi
if [ -n "$2" ]
then
      nodename=$2
fi

2>&1 crm_simulate -Ls | grep -E "$resource" | grep -E "$nodename" > $tmpfile

parseline() { 
	if ! echo $*|grep -q "promotion score"; then
		shift;
	fi
	res=$1; shift; shift; shift; shift; 
	node=$(echo $1|sed 's/:$//'); shift; 
	score=$1; 
}

get_stickiness() {
	res="$1"
	# get meta attribute resource_stickiness
	if ! stickiness=`crm_resource -g resource-stickiness -r $res --meta -Q 2>/dev/null`
	then
		# if no resource-specific stickiness is confiugured, use the default value
		stickiness="$default_stickiness"
	fi

	# get meta attribute resource_failure_stickiness
	if ! migrationthreshold=`crm_resource -g migration-threshold -r $res --meta -Q 2>/dev/null`
	then
		# if that doesnt exist, use the default value
		migrationthreshold="$default_migrationthreshold"
	fi	
}

get_failcount() { #usage $0 res node
        failcount=`crm_failcount -G -r $1 -U $2 -Q 2>/dev/null|grep -o "^[0-9]*$"`
}

#determine the longest resource name to adjust width of the first column
max_res_id_len=0
for res_id in $(tail -n +2 $tmpfile | sed 's/^[a-zA-Z_-]*\:\ //' | cut -d " " -f 1 | sort | uniq); do 
	res_id_len=$(echo $res_id|wc -c) 
	[ $res_id_len -gt $max_res_id_len ] && export max_res_id_len=$res_id_len; 
done
# we'll later add "_(master)" to master scores, so add 9 chars to max_res_id_len
max_res_id_len=$(($max_res_id_len+9))

#same for nodenames
max_node_id_len=0
for node_id in $(sed 's/^[a-zA-Z_-]*\:\ //' $tmpfile | cut -d " " -f 5 | grep -v "^$" | sort | uniq | sed 's/\://'); do
	node_id_len=$(echo $node_id|wc -c)
	[ $node_id_len -gt $max_node_id_len ] && export max_node_id_len=$node_id_len;
done

# display allocation scores
grep native_color $tmpfile | while read line
do
	unset node res score stickiness failcount migrationthreshold
	parseline $line
	get_stickiness $res
	get_failcount $res $node
	printf "%-${max_res_id_len}s%-10s%-${max_node_id_len}s%-11s%-9s%-16s\n" $res $score $node $stickiness $failcount $migrationthreshold
done >> $tmpfile2

# display promotion scores
grep "promotion score" $tmpfile | while read line
do
	unset node res score stickiness failcount migrationthreshold
	parseline $line
	# Skip if node=none. Sometimes happens for clones but is internally mapped to another clone instance, so this is skipped
	[ "$node" = "none" ] && continue
	inflines=`grep "promotion score" $tmpfile | grep $res | grep 1000000 | wc -l`
	if [ $inflines -eq 1 ]
	then
		# [10:24] <beekhof> the non INFINITY values are the true ones
		# [10:25] <kleind> except for when the actually resulting score is [-]INFINITY
		# [10:25] <beekhof> yeah
		actualline=`grep "promotion score" $tmpfile | grep $res | grep -v 1000000`
		parseline $actualline
	fi
	get_stickiness $res
	get_failcount $res $node
	res=$res"_(master)"
	printf "%-${max_res_id_len}s%-10s%-${max_node_id_len}s%-11s%-9s%-16s\n" $res $score $node $stickiness $failcount $migrationthreshold
done | sort | uniq >> $tmpfile2

if [ "$3" = "singlescore" ]
then
	sed 's/  */ /g' $tmpfile2 | cut -d ' ' -f 2 | tail -n 1
else
	# Heading
	printf "%-${max_res_id_len}s%-10s%-${max_node_id_len}s%-11s%-9s%-16s\n" "Resource" "Score" "Node" "Stickiness" "#Fail" "Migration-Threshold"
	sort -k $sortby $tmpfile2
fi

rm -f $tmpfile $tmpfile2
