#!/bin/bash

. helper.sh
#. @libdir@/heartbeat/crmtest/helper.sh

HOST=hadev
QUIET=$OUTPUT_NONE
CRM_ERR_SHUTDOWN=1

if [ "x$1" = "x-v" ]; then 
    QUIET=$OUTPUT_ALL
elif [ "x$1" = "x-e" ]; then 
    QUIET=$OUTPUT_NOOUT
elif [ "x$1" = "x-o" ]; then 
    QUIET=$OUTPUT_NOERR
elif [ "x$1" = "x-x" ]; then 
    set -x
fi

#node1->CRM->install_cib(filename_or_text_or_whatever_is_easiest)
do_cmd $QUIET remote_cmd hacluster $HOST $HALIB_DIR/crmd '2>&1 >/dev/null' &

do_cmd $QUIET echo "wait for CRMd to start"
sleep 20

do_cmd $QUIET wait_for_state S_IDLE 10 $HOST 
cts_assert "S_IDLE not reached on $HOST!"

do_cmd $QUIET is_running rsc1 $HOST
cts_assert "rsc1 NOT running"

do_cmd $QUIET is_running rsc2 $HOST
cts_assert "rsc2 NOT running"

do_cmd $QUIET is_dc $HOST
cts_assert "$HOST is supposed to be the DC"

do_cmd $QUIET is_running rsc1 $HOST x$HOST
cts_assert_false "rsc1 IS running on x$HOST"

do_cmd $QUIET is_running rsc1 $HOST $HOST
cts_assert "rsc1 NOT running on $HOST"

do_cmd $QUIET is_running rsc2 $HOST $HOST
cts_assert "rsc2 NOT running on $HOST"

do_cmd $QUIET remote_cmd root $HOST $HALIB_DIR/crmadmin -K $HOST

echo "test: PASSED"
