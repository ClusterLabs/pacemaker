#!/bin/bash
#
# Copyright (C) 2004 Andrew Beekhof  <andrew@beekhof.net>
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
#. @libdir@/heartbeat/crmtest/helper.sh

CRM_ERR_SHUTDOWN=1

# make *sure* theres nothing left over from last time
do_cmd remote_cmd $INIT_USER $test_node_1 $HALIB_DIR/heartbeat "-k" '2>&1 >/dev/null'
do_cmd remote_cmd $INIT_USER $test_node_1 "killall -q9 heartbeat crmd ccm lrmd"
do_cmd remote_cmd $INIT_USER $test_node_1 "rm -f $HAVAR_DIR/crm/cib*.xml"

# start HA anew
do_cmd remote_cmd $INIT_USER $test_node_1 $HALIB_DIR/heartbeat "-M" '2>&1 >/dev/null'
do_cmd echo "wait for HA to start"
sleep 20

do_cmd remote_cmd $CRMD_USER $test_node_1 $HALIB_DIR/crmd '2>&1 >/dev/null' &

do_cmd echo "wait for CRMd to start"
sleep 20

do_cmd wait_for_state S_IDLE 10 $test_node_1 
cts_assert "S_IDLE not reached on $test_node_1 (startup)"

# Erase the contents of the CIB and wait for things to settle down
do_cmd remote_cmd $CRMD_USER $test_node_1 $HALIB_DIR/cibadmin -E 
do_cmd wait_for_state S_IDLE 10 $test_node_1 
cts_assert "S_IDLE not reached on $test_node_1 after CIB erase"

# Create the CIB for this test and wait for all transitions to complete
do_cmd make_node $test_node_1 $test_node_1
args="<nvpair name=\"1\" value=\"${ip_rsc_1}\"/>"
do_cmd make_resource $test_node_1 rsc1 heartbeat IPaddr - - $args
args="<nvpair name=\"1\" value=\"${ip_rsc_2}\"/>"
do_cmd make_resource $test_node_1 rsc2 heartbeat IPaddr - - $args
do_cmd make_constraint $test_node_1 rsc1 can
do_cmd make_constraint $test_node_1 rsc2 can
do_cmd wait_for_state S_IDLE 10 $test_node_1 
cts_assert "S_IDLE not reached on $test_node_1 after CIB create"

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

# shutdown
do_cmd remote_cmd $CRMD_USER $test_node_1 $HALIB_DIR/crmadmin -K $test_node_1
do_cmd wait_for_state S_PENDING 30 $test_node_1 
cts_assert "S_PENDING not reached on $test_node_1!"

# escalate the shutdown
do_cmd remote_cmd $CRMD_USER $test_node_1 $HALIB_DIR/crmadmin -K $test_node_1

# just in case
do_cmd remote_cmd $CRMD_USER $test_node_1 killall -9q crmd

echo "test: PASSED"
