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

test_node_1=test1
test_node_2=test2
QUIET=$OUTPUT_NONE
CRM_ERR_SHUTDOWN=0

if [ "x$1" = "x-v" ]; then 
    QUIET=$OUTPUT_ALL
elif [ "x$1" = "x-e" ]; then 
    QUIET=$OUTPUT_NOOUT
elif [ "x$1" = "x-o" ]; then 
    QUIET=$OUTPUT_NOERR
elif [ "x$1" = "x-x" ]; then 
    set -x
fi

do_cmd $QUIET remote_cmd root $test_node_1 $HAINIT_DIR/heartbeat start
do_cmd $QUIET echo "wait for HA to start"
sleep 20

do_cmd $QUIET remote_cmd hacluster $test_node_1 $HALIB_DIR/crmd '2>&1 >/dev/null' &

do_cmd $QUIET echo "wait for CRMd to start"
sleep 20


do_cmd $QUIET wait_for_state S_IDLE 10 $test_node_1 
cts_assert "S_IDLE not reached on $test_node_1!"

do_cmd $QUIET is_running rsc1 $test_node_1
cts_assert "rsc1 NOT running"

do_cmd $QUIET is_running rsc2 $test_node_1
cts_assert "rsc2 NOT running"

do_cmd $QUIET is_dc $test_node_1
cts_assert "$test_node_1 is supposed to be the DC"

do_cmd $QUIET is_running rsc1 $test_node_1 x$test_node_1
cts_assert_false "rsc1 IS running on x$test_node_1"

do_cmd $QUIET is_running rsc1 $test_node_1 $test_node_1
cts_assert "rsc1 NOT running on $test_node_1"

do_cmd $QUIET is_running rsc2 $test_node_1 $test_node_1
cts_assert "rsc2 NOT running on $test_node_1"

do_cmd $QUIET remote_cmd root $test_node_2 $HAINIT_DIR/heartbeat start
do_cmd $QUIET echo "wait for HA to start on $test_node_2"
sleep 20

do_cmd $QUIET remote_cmd hacluster $test_node_2 $HALIB_DIR/crmd '2>&1 >/dev/null' &

do_cmd $QUIET wait_for_state S_INTEGRATION 30 $test_node_1 
cts_assert "S_INTEGRATION not reached on $test_node_1!"

do_cmd $QUIET wait_for_state S_NOT_DC 10 $test_node_2 
cts_assert "S_NOT_DC not reached on $test_node_2!"

do_cmd $QUIET wait_for_state S_IDLE 10 $test_node_1 
cts_assert "S_IDLE not reached on $test_node_1!"

do_cmd $QUIET is_running rsc1 $test_node_1
cts_assert "rsc1 NOT running"

do_cmd $QUIET is_running rsc2 $test_node_1
cts_assert "rsc2 NOT running"

do_cmd $QUIET is_running rsc1 $test_node_1 $test_node_1
cts_assert "rsc1 NOT running on $test_node_1"

do_cmd $QUIET is_running rsc2 $test_node_1 $test_node_2
cts_assert "rsc2 NOT running on $test_node_2"

do_cmd $QUIET remote_cmd root $test_node_1 $HALIB_DIR/crmadmin -K $test_node_1

do_cmd $QUIET wait_for_state S_ELECTION 30 $test_node_2 
cts_assert "S_ELECTION not reached on $test_node_2!"

do_cmd $QUIET wait_for_state S_NOT_DC 30 $test_node_1 
cts_assert "S_NOT_DC not reached on $test_node_1!"

do_cmd $QUIET wait_for_state S_IDLE 30 $test_node_2 
cts_assert "S_IDLE not reached on $test_node_2!"

do_cmd $QUIET is_running rsc1 $test_node_2
cts_assert "rsc1 NOT running"

do_cmd $QUIET is_running rsc2 $test_node_2
cts_assert "rsc2 NOT running"

do_cmd $QUIET is_running rsc1 $test_node_2 $test_node_1
cts_assert_false "rsc1 IS running on $test_node_1"

do_cmd $QUIET is_running rsc2 $test_node_2 $test_node_2
cts_assert "rsc2 NOT running on $test_node_2"

do_cmd $QUIET remote_cmd root $test_node_2 $HALIB_DIR/crmadmin -K $test_node_2

do_cmd $QUIET wait_for_state S_PENDING 30 $test_node_2 
cts_assert "S_PENDING not reached on $test_node_2!"

# escalate the shutdown
do_cmd $QUIET remote_cmd root $test_node_2 $HALIB_DIR/crmadmin -K $test_node_2

do_cmd $QUIET wait_for_state S_STOPPING 30 $test_node_2 
cts_assert "S_STOPPING not reached on $test_node_2!"

echo "test: PASSED"
