#!/bin/bash
#
# Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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

. helper.sh

CRM_ERR_SHUTDOWN=0



# stop all running HAs
do_cmd remote_cmd $INIT_USER $test_node_1 $HALIB_DIR/heartbeat "-k" "2>&1 >/dev/null"
do_cmd remote_cmd $INIT_USER $test_node_2 $HALIB_DIR/heartbeat "-k" "2>&1 >/dev/null"

# be *very* sure everything has stopped
do_cmd remote_cmd $INIT_USER $test_node_1 "killall -q9 heartbeat ccm lrmd crmd"
do_cmd remote_cmd $INIT_USER $test_node_2 "killall -q9 heartbeat ccm lrmd crmd"

# make *sure* theres nothing left over from last time
do_cmd remote_cmd $INIT_USER $test_node_1 "rm -f $HAVAR_DIR/crm/cib*.xml"
do_cmd remote_cmd $INIT_USER $test_node_2 "rm -f $HAVAR_DIR/crm/cib*.xml"

do_cmd remote_cmd $INIT_USER $test_node_1 $HALIB_DIR/heartbeat -M "2>&1 >/dev/null" &

do_cmd echo "wait for HA to start"
do_cmd ./testutils.pl --search -a -m 1500 -s "${test_node_1} ccm(.*): info: Hostname: ${test_node_1}" -s "${test_node_1} heartbeat(.*) info: Starting(.*)lrmd" -e "${test_node_1} heartbeat(.*)Client(.*) respawning too fast"
cts_assert "Startup of Heartbeat on ${test_node_1} failed."

do_cmd remote_cmd $CRMD_USER $test_node_1 $HALIB_DIR/crmd -VVVV "2>&1 >/dev/null" &

do_cmd echo "wait for CRMd to start"
do_cmd ./testutils.pl --search  -a -m 1500 -s "${test_node_1} crmd(.*): info:(.*)FSA Hostname: ${test_node_1}"
cts_assert "CRMd startup on ${test_node_1} failed."

do_cmd wait_for_state S_IDLE 30 $test_node_1 
cts_assert "S_IDLE not reached on $test_node_1 (startup)!"

# Erase the contents of the CIB and wait for things to settle down
#do_cmd remote_cmd $CRMD_USER $test_node_1 $HALIB_DIR/cibadmin -E 
#do_cmd wait_for_state S_IDLE 10 $test_node_1 
#cts_assert "S_IDLE not reached on $test_node_1 after CIB erase"

# Create the CIB for this test and wait for all transitions to complete
#do_cmd make_node $test_node_1 $test_node_1
#do_cmd make_node $test_node_1 $test_node_2
args="<nvpair name=\"1\" value=\"${ip_rsc_1}\"/>"
do_cmd make_resource $test_node_1 rsc1 heartbeat IPaddr - - $args
args="<nvpair name=\"1\" value=\"${ip_rsc_2}\"/>"
do_cmd make_resource $test_node_1 rsc2 heartbeat IPaddr - - $args

#do_cmd make_constraint $test_node_1 rsc1 can
uuid1=`uuidgen`
uuid2=`uuidgen`
uuid3=`uuidgen`
rsc=rsc1
    
node_xml="'<rsc_location id=\"${uuid1}\" rsc=\"${rsc}\">
        <rule id=\"${uuid2}\" result=\"can\"/>
	<rule id=\"${uuid3}\" score=\"1000\" boolean_op=\"or\">
	  <expression attribute=\"uname\" operation=\"eq\" value=\"${test_node_1}\"/>
	</rule>
      </rsc_location>'"
do_cmd make_constraint_adv $test_node_1 $node_xml

#do_cmd make_constraint $test_node_1 rsc2 can
uuid1=`uuidgen`
uuid2=`uuidgen`
uuid3=`uuidgen`
rsc=rsc2
    
node_xml="'<rsc_location id=\"${uuid1}\" rsc=\"${rsc}\">
	        <rule id=\"${uuid2}\" result=\"can\"/>
		<rule id=\"${uuid3}\" score=\"1000\" boolean_op=\"or\">
		   <expression attribute=\"uname\" operation=\"eq\" value=\"${test_node_2}\"/>
		</rule>
	   </rsc_location>'"
do_cmd make_constraint_adv $test_node_1 $node_xml

do_cmd wait_for_state S_IDLE 10 $test_node_1 
cts_assert "S_IDLE not reached on $test_node_1 (CIB create)!"

do_cmd is_running rsc1 $test_node_1
cts_assert "rsc1 NOT running"

do_cmd is_running rsc2 $test_node_1
cts_assert "rsc2 NOT running"

do_cmd is_dc $test_node_1
cts_assert "$test_node_1 is supposed to be the DC"

do_cmd is_running rsc1 $test_node_1 x$test_node_1
cts_assert_false "rsc1 IS running on x$test_node_1"

do_cmd is_running rsc1 $test_node_1 $test_node_1
cts_assert "rsc1 NOT running on $test_node_1"

do_cmd is_running rsc2 $test_node_1 $test_node_1
cts_assert "rsc2 NOT running on $test_node_1"

do_cmd remote_cmd $INIT_USER $test_node_2 $HALIB_DIR/heartbeat -M "2>&1 >/dev/null" &
do_cmd echo "wait for HA to start on $test_node_2"
do_cmd ./testutils.pl --search -a -m 1500 -s "${test_node_2} ccm(.*) Hostname: ${test_node_2}" -s "${test_node_2} heartbeat(.*): info: Starting (.*)lrmd" -e "${test_node_2} heartbeat(.*) Client (.*) respawning too fast"
cts_assert "Startup of Heartbeat on ${test_node_2} failed."

do_cmd remote_cmd $CRMD_USER $test_node_2 $HALIB_DIR/crmd  "-VVVV" "2>&1 >/dev/null" &

#do_cmd wait_for_state S_INTEGRATION 30 $test_node_1 
#cts_assert "S_INTEGRATION not reached on $test_node_1 (new node)!"
do_cmd echo "wait for CRMd to start on $test_node_2"
do_cmd ./testutils.pl --search -a -m 1500  -s "${test_node_2} crmd(.*)FSA Hostname: ${test_node_2}" -s "${test_node_2} crmd(.*) Performing op start(.*) on rsc2"
cts_assert "CRMd startup on ${test_node_2} failed."

#do_cmd echo "wait for transition to complete"
#do_cmd ./testutils.pl --search $logfile '"${test_node_2} crmd(.*)erforming op start(.*) on rsc2"' 1 1500
#cts_assert "Transition of rsc2 to ${test_node_2} failed."

do_cmd wait_for_state S_NOT_DC 30 $test_node_2 
cts_assert "S_NOT_DC not reached on $test_node_2 (startup - 2)!"

do_cmd wait_for_state S_IDLE 30 $test_node_1 
cts_assert "S_IDLE not reached on $test_node_1 (startup - 2)!"

do_cmd is_running rsc1 $test_node_1
cts_assert "rsc1 NOT running"

do_cmd is_running rsc2 $test_node_1
cts_assert "rsc2 NOT running"

do_cmd is_running rsc1 $test_node_1 $test_node_1
cts_assert "rsc1 NOT running on $test_node_1"

do_cmd is_running rsc2 $test_node_1 $test_node_2
cts_assert "rsc2 NOT running on $test_node_2"

do_cmd remote_cmd $CRMD_USER $test_node_1 $HALIB_DIR/crmadmin -K $test_node_1 &

do_cmd echo "Looking for transition messages"
do_cmd ./testutils.pl --search -a -m 1500 -s "${test_node_2} crmd(.*) State transition (.*) -> \"S_ELECTION\"" -s "${test_node_1} crmd(.*) State transition (.*) -> \"S_NOT_DC\"" -s "${test_node_1} crmd(.*)State transition (.*) -> \"S_STOPPING\""
cts_assert "Shutdown of ${test_node_1} followed by stability on ${test_node_2} failed."

do_cmd wait_for_state S_IDLE 60 $test_node_2 
cts_assert "S_IDLE not reached on $test_node_2!"

do_cmd is_running rsc1 $test_node_2
cts_assert "rsc1 NOT running"

do_cmd is_running rsc2 $test_node_2
cts_assert "rsc2 NOT running"

do_cmd is_running rsc1 $test_node_2 $test_node_1
cts_assert_false "rsc1 IS running on $test_node_1"

do_cmd is_running rsc2 $test_node_2 $test_node_2
cts_assert "rsc2 NOT running on $test_node_2"

do_cmd remote_cmd $CRMD_USER $test_node_2 $HALIB_DIR/crmadmin -K $test_node_2

do_cmd wait_for_state S_PENDING 30 $test_node_2 
cts_assert "S_PENDING not reached on $test_node_2!"

# escalate the shutdown
do_cmd remote_cmd $CRMD_USER $test_node_2 $HALIB_DIR/crmadmin -K $test_node_2 &

do_cmd ./testutils.pl --search -a -m 1500 -s "${test_node_2} crmd(.*)State transition \"S_PENDING\" -> \"S_STOPPING\""
cts_assert "Shutdown of ${test_node_2} failed."

# just in case
do_cmd remote_cmd $CRMD_USER $test_node_2 killall -9 crmd

echo "test: PASSED"
