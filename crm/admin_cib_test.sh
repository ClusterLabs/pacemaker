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
CRM_ROOT=.
TEST_NODE1=hadev
TEST_NODE2=w3server
TEST_NODE3=gateway
TEST_NODE4=local
ADMIN_BIN=$CRM_ROOT/admin/crmadmin


## probably dont change anything below here
TYPE=all
OP=daemon
# individual node health
$ADMIN_BIN --$OP --status=$TEST_NODE1 --reference=ping_test_$TEST_NODE1
#$ADMIN_BIN --$OP --health=$TEST_NODE2 --reference=ping_test_$TEST_NODE2
#$ADMIN_BIN --$OP --health=$TEST_NODE3 --reference=ping_test_$TEST_NODE3

# cluster wide health
#$ADMIN_BIN --$OP --health  --reference=ping_test_cluster

#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#

TYPE=node
OP=create
# Creation
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_1 -D "test node: $TEST_NODE1" --reference=${TYPE}_${OP}_1
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_2 -D "test node: $TEST_NODE2" -s $TYPE --reference=${TYPE}_${OP}_2
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_3 -D "test node: $TEST_NODE3" -s $TYPE --reference=${TYPE}_${OP}_3
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_4 -D "test node: $TEST_NODE4" -s $TYPE --reference=${TYPE}_${OP}_4

#modification
OP=modify
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_3 -D "modified test node: $TEST_NODE3" -s ping --reference=${TYPE}_${OP}_1

#deletion
OP=delete
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_4  --reference=${TYPE}_${OP}_1

#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#

TYPE=resource
OP=create
# Creation
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_1 -D "corp web server" -s "apache"  -m 3 -a "$TEST_NODE1=10" --reference=${TYPE}_${OP}_1
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_2 -D "apache data" -s "drbd" -m 2 -a "$TEST_NODE1=10" --reference=${TYPE}_${OP}_2
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_3 -D "DNS Server" -s "dns" -a "$TEST_NODE3=20" --reference=${TYPE}_${OP}_3

#modification
OP=modify
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_1 -a "$TEST_NODE2=50" -d "$TEST_NODE2=50" -m 2 --reference=${TYPE}_${OP}_1
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_2 -w --reference=${TYPE}_${OP}_2
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_3 -D "DHCP Server" -s "dhcp" -d "$TEST_NODE3=20" -a "$TEST_NODE2=20" --reference=${TYPE}_${OP}_3

#deletion
OP=delete
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_3 --reference=${TYPE}_${OP}_1


#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#

TYPE=constraint
OP=create
# Creation
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_1 -D "Start apache after drbd" -s "after" -r resource_1 -r resource_2 -c "never" --reference=${TYPE}_${OP}_1
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_2 -D "Start Apache on the same node as DRBD" -s "same" -r resource_1 -r resource_2 -c "never" --reference=${TYPE}_${OP}_2
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_3 -D "DNS Server" -s "block" -r resource_1 --node "node_1" --instance "1" -c "stonith" --reference=${TYPE}_${OP}_3

#modification
OP=modify
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_1 -a "$TEST_NODE2=50" -d "$TEST_NODE2=50" --reference=${TYPE}_${OP}_1
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_2 -w --reference=${TYPE}_${OP}_2
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_3 -D "DHCP Server" -s "dhcp" -d "$TEST_NODE3=20" -a "$TEST_NODE2=20" --reference=${TYPE}_${OP}_3

#deletion
OP=delete
$ADMIN_BIN --$OP -V -o $TYPE -i ${TYPE}_3 --reference=${TYPE}_${OP}_1

#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#

