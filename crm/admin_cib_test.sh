#!/bin/sh
#
# Copyright (C) 2004 Andrew Beekhof
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


#set -x

## change these
CRM_ROOT=/usr/lib/heartbeat
TEST_NODE1=hadev
TEST_NODE2=w3server
TEST_NODE3=gateway
TEST_NODE4=local
ADMIN_BIN=$CRM_ROOT/crmadmin

## probably dont change anything below here

TESTID=0

function do_node()
{
TESTID=$((${TESTID}+1))
TYPE=node
node_xml="<$TYPE id=\"${2}\" description=\"test node: ${2}\" type=\"${3}\"/>";
echo $node_xml | $ADMIN_BIN --${1} -V -o $TYPE --reference=${TESTID}_${TYPE}_${1}

}

function do_resource()
{

TESTID=$((${TESTID}+1))
TYPE=resource
node_xml="<${TYPE} id=\"${2}\" 
		description=\"${3}\" 
		type=\"${4}\" 
		max_instances=\"${5}\"/>";
echo $node_xml | $ADMIN_BIN --${1} -V -o $TYPE --reference=${TESTID}_${TYPE}_${1}

}

function do_resource_modify()
{

TESTID=$((${TESTID}+1))
TYPE=resource
node_xml="<${TYPE} id=\"${2}\" 
		type=\"${4}\" 
		max_instances=\"${5}\"/>";
echo $node_xml | $ADMIN_BIN --${1} -V -o $TYPE --reference=${TESTID}_${TYPE}_${1}

}

function do_constraint()
{

TESTID=$((${TESTID}+1))
TYPE=constraint
node_xml="<${TYPE} id=\"${2}\" 
		description=\"${3}\" 
		type=\"${4}\" 
		clear_on=\"${5}\"
		${6}/>";
echo $node_xml | $ADMIN_BIN --${1} -V -o $TYPE --reference=${TESTID}_${TYPE}_${1}

}


function do_delete()
{
TESTID=$((${TESTID}+1))
OP=delete
TYPE=$1
node_xml="<${TYPE} id=\"${2}\"/>";
echo $node_xml | $ADMIN_BIN --${OP} -V -o $TYPE --reference=${TESTID}_${TYPE}_${OP}

}


TYPE=all
OP=daemon

#clear the CIB
$ADMIN_BIN --$OP --erase --reference=erase_test

# individual node health
#$ADMIN_BIN --$OP --status=$TEST_NODE1 --reference=ping_test_$TEST_NODE1
#$ADMIN_BIN --$OP --health=$TEST_NODE2 --reference=ping_test_$TEST_NODE2
#$ADMIN_BIN --$OP --health=$TEST_NODE3 --reference=ping_test_$TEST_NODE3

# cluster wide health
#$ADMIN_BIN --$OP --health  --reference=ping_test_cluster

#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#

OP=create

# Creation
do_node ${OP} node_1
do_node ${OP} node_2 ping
do_node ${OP} node_3 ping
do_node ${OP} node_4 node

#modification
OP=update
do_node ${OP} node_2 node

#deletion
OP=delete
do_delete node node_4

#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#

OP=create
# Creation
do_resource ${OP} res_1 "corp web server" "apache" 3
do_resource ${OP} res_2 "apache data" "drbd" 2
do_resource ${OP} res_3 "DNS Server" "dns"

#modification
OP=update
do_resource_modify ${OP} res_2 "drbd" 1
do_resource ${OP} res_3 "DHCP Server" "dhcp" 1

#deletion
OP=delete
do_delete resource res_3

#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#

OP=create
# Creation
do_constraint ${OP} con_1 "Start apache after drbd" "after" "never" \
	"res1=\"res_1\" res2=\"res_2\""

do_constraint ${OP} con_2 "Start on the same node as DRBD" "same" "never" \
	"res1=\"res_1\" res2=\"res_2\""

do_constraint ${OP} con_3 "DNS Server - Failed" "block" "stonith" "res1=\"res_3\""

#modification
OP=update

#deletion
OP=delete
do_delete $TYPE con_3

#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#
