#!/bin/bash

 # Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 # 
 # This program is free software; you can redistribute it and/or
 # modify it under the terms of the GNU General Public
 # License as published by the Free Software Foundation; either
 # version 2.1 of the License, or (at your option) any later version.
 # 
 # This software is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 # General Public License for more details.
 # 
 # You should have received a copy of the GNU General Public
 # License along with this library; if not, write to the Free Software
 # Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 #

. regression.core.sh

create_mode="true"
echo Generating test outputs for these tests...
#do_test bad7

echo ""

echo Done.
echo ""
echo Performing the following tests...
create_mode="false"
do_test simple1 "Offline	"
do_test simple2 "Start	"
do_test simple3 "Start 2	"
do_test simple4 "Start Failed"
do_test simple6 "Stop Start	"
do_test simple7 "Shutdown	"
#do_test simple8 "Stonith	"
#do_test simple9 "Lower version"
#do_test simple10 "Higher version"
do_test simple11 "Priority (ne)"
do_test simple12 "Priority (eq)"

echo ""
do_test rsc_dep1 "Must not	"
#do_test rsc_dep2 "Should not	"
do_test rsc_dep3 "Must	"
#do_test rsc_dep4 "Should	"
do_test rsc_dep5 "Must not 3	"
#do_test rsc_dep6 "Should not 3"
do_test rsc_dep7 "Must 3	"
#do_test rsc_dep8 "Should 3	"
do_test rsc_dep10 "Must (cant)"
#do_test rsc_dep9 "2*MustNot 1*ShouldNot"

echo ""
do_test order1 "Order start 1"
do_test order2 "Order start 2"
do_test order3 "Order stop	"
do_test order4 "Order (multiple)"

#echo ""
#do_test agent1 "version: lt (empty)"
#do_test agent2 "version: eq	"
#do_test agent3 "version: gt	"

echo ""
do_test attrs1 "string: eq (and)	"
do_test attrs2 "string: lt / gt (and)"
do_test attrs3 "string: ne (or)	"
do_test attrs4 "string: exists	"
do_test attrs5 "string: not_exists	"
do_test attrs6 "is_dc: true	"
do_test attrs7 "is_dc: false	"

echo ""
do_test nodefail1 "Node Fail - Fence	"
do_test nodefail5 "Node Fail - Fence2Block"
do_test nodefail4 "Node Fail - Block&Fence"
do_test nodefail2 "Node Fail - Block	"
do_test nodefail3 "Node Fail - Ignore	"

echo ""
do_test stopfail1 "Stop Fail - Disabled       "
do_test stopfail9 "Stop Fail - Enabled, 1 node"
do_test stopfail2 "Stop Fail - Enabled, 2 node"
do_test stopfail3 "Stop Fail - Ignore (1 node)"
do_test stopfail4 "Stop Fail - Ignore (2 node)"
#do_test stopfail5 "Stop Fail - STONITH (pass2) "
#do_test stopfail6 "Stop Fail - STONITH (pass3) "
#do_test stopfail7 "Stop Fail - STONITH (should fail)"

echo ""
do_test rsc_location1 "Score (not running)	"
do_test rsc_location2 "Score (running)		"
do_test rsc_location3 "Score (not running/no swap)"
do_test rsc_location4 "Score (running/swap)	"
do_test rsc_location5 "Score (running/swap 2)	"

echo ""
do_test multi1 "Multiple Active (stop/start)"

#echo ""
#do_test complex1 "Complex	"

echo ""
do_test group1 "Group		"
do_test group2 "Group + Native	"
do_test group3 "Group + Group	"
do_test group4 "Group + Native (nothing)"
do_test group5 "Group + Native (move)"
do_test group6 "Group + Group (move)"

echo ""
do_test inc1 "Incarnation start					" 
do_test inc2 "Incarnation silent restart, stop, move		"
do_test inc3 "Inter-incarnation ordering, silent restart, stop, move"

echo ""
do_test bad1 "Bad node		"
do_test bad2 "Bad rsc		"
do_test bad3 "No rsc class	"
do_test bad4 "Bad data		"
do_test bad5 "Bad data		"
do_test bad6 "Bad lrm_rsc	"

echo ""

test_results
