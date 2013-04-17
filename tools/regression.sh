#!/bin/bash

: ${shadow=tools-regression}
test_home=`dirname $0`
num_errors=0
num_passed=0
GREP_OPTIONS=

function assert() {
    rc=$1; shift
    target=$1; shift
    app=$1; shift
    msg=$1; shift
    cib=$1; shift

    if [ x$cib = x0 ]; then
	: nothing
    else
	cibadmin -Q
    fi

    if [ $rc -ne $target ]; then
	num_errors=`expr $num_errors + 1`
	printf "* Failed (rc=%.3d): %-14s - %s\n" $rc $app "$msg"
	printf "* Failed (rc=%.3d): %-14s - %s\n" $rc $app "$msg" 1>&2
	return
	exit 1
    else
	printf "* Passed: %-14s - %s\n" $app "$msg"
	printf "* Passed: %-14s - %s\n" $app "$msg" 1>&2

	num_passed=`expr $num_passed + 1`
    fi
}

function usage() {
    echo "Usage: ./regression.sh [-s(ave)] [-x] [-v(erbose)]"
    exit $1
}

done=0
do_save=0
VALGRIND_CMD=
while test "$done" = "0"; do
    case "$1" in
	-V|--verbose) verbose=1; shift;;
	-v|--valgrind)
	    export G_SLICE=always-malloc
	    VALGRIND_CMD="valgrind -q --show-reachable=no --leak-check=full --trace-children=no --time-stamp=yes --num-callers=20 --suppressions=$test_home/cli.supp"
	    shift;;
	-x) set -x; shift;;
	-s) do_save=1; shift;;
	-p) PATH="$2:$PATH"; export PATH; shift 1;;
	-?) usage 0;;
	-*) echo "unknown option: $1"; usage 1;;
	*) done=1;;
    esac
done

if [ "x$VALGRIND_CMD" = "x" -a -x $test_home/crm_simulate ]; then
    echo "Using local binaries from: $test_home"
    PATH="$test_home:$PATH"
fi

function test_tools() {
    export CIB_shadow_dir=$test_home
    $VALGRIND_CMD crm_shadow --batch --force --create-empty $shadow  2>&1
    export CIB_shadow=$shadow
    $VALGRIND_CMD cibadmin -Q 2>&1

    $VALGRIND_CMD cibadmin -E 2>&1
    assert $? 22 cibadmin "Require --force for CIB erasure"

    $VALGRIND_CMD cibadmin -E --force
    assert $? 0 cibadmin "Allow CIB erasure with --force"

    $VALGRIND_CMD cibadmin -Q > /tmp/$$.existing.xml
    assert $? 0 cibadmin "Query CIB"

    $VALGRIND_CMD crm_attribute -n cluster-delay -v 60s
    assert $? 0 crm_attribute "Set cluster option"

    $VALGRIND_CMD cibadmin -Q -o crm_config | grep cib-bootstrap-options-cluster-delay
    assert $? 0 cibadmin "Query new cluster option"

    $VALGRIND_CMD cibadmin -Q -o crm_config > /tmp/$$.opt.xml
    assert $? 0 cibadmin "Query cluster options"

    $VALGRIND_CMD cibadmin -D -o crm_config --xml-text '<nvpair id="cib-bootstrap-options-cluster-delay"/>'
    assert $? 0 cibadmin "Delete nvpair"

    $VALGRIND_CMD cibadmin -C -o crm_config --xml-file /tmp/$$.opt.xml 2>&1
    assert $? 76 cibadmin "Create operaton should fail with: -76, The object already exists"

    $VALGRIND_CMD cibadmin -M -o crm_config --xml-file /tmp/$$.opt.xml
    assert $? 0 cibadmin "Modify cluster options section"

    $VALGRIND_CMD cibadmin -Q -o crm_config | grep cib-bootstrap-options-cluster-delay
    assert $? 0 cibadmin "Query updated cluster option"

    $VALGRIND_CMD crm_attribute -n cluster-delay -v 40s -s duplicate
    assert $? 0 crm_attribute "Set duplicate cluster option"

    $VALGRIND_CMD crm_attribute -n cluster-delay -v 30s
    assert $? 234 crm_attribute "Setting multiply defined cluster option should fail with -216, Could not set cluster option"

    $VALGRIND_CMD crm_attribute -n cluster-delay -v 30s -s duplicate
    assert $? 0 crm_attribute "Set cluster option with -s"

    $VALGRIND_CMD crm_attribute -n cluster-delay -D -i cib-bootstrap-options-cluster-delay
    assert $? 0 crm_attribute "Delete cluster option with -i"

    $VALGRIND_CMD cibadmin -C -o nodes --xml-text '<node id="clusterNode-UUID" uname="clusterNode-UNAME" type="member">'
    assert $? 0 cibadmin "Create node entry"

    $VALGRIND_CMD cibadmin -C -o status --xml-text '<node_state id="clusterNode-UUID" uname="clusterNode-UNAME"/>'
    assert $? 0 cibadmin "Create node status entry"

    $VALGRIND_CMD crm_attribute -n ram -v 1024M -U clusterNode-UNAME -t nodes
    assert $? 0 crm_attribute "Create node attribute"

    $VALGRIND_CMD cibadmin -Q -o nodes | grep clusterNode-UUID-ram
    assert $? 0 cibadmin "Query new node attribute"

    $VALGRIND_CMD cibadmin -Q | cibadmin -5 -p 2>&1 > /dev/null
    assert $? 0 cibadmin "Digest calculation"

    # This update will fail because it has version numbers
    $VALGRIND_CMD cibadmin -R --xml-file /tmp/$$.existing.xml 2>&1
    assert $? 205 cibadmin "Replace operation should fail with: 205, Update was older than existing configuration"

    crm_standby -N clusterNode-UNAME -G
    assert $? 0 crm_standby "Default standby value"

    crm_standby -N clusterNode-UNAME -v true
    assert $? 0 crm_standby "Set standby status"

    crm_standby -N clusterNode-UNAME -G
    assert $? 0 crm_standby "Query standby value"

    crm_standby -N clusterNode-UNAME -D 2>&1
    assert $? 0 crm_standby "Delete standby value"

    $VALGRIND_CMD cibadmin -C -o resources --xml-text '<primitive id="dummy" class="ocf" provider="pacemaker" type="Dummy"/>'
    assert $? 0 cibadmin "Create a resource"

    $VALGRIND_CMD crm_resource -r dummy --meta -p is-managed -v false
    assert $? 0 crm_resource "Create a resource meta attribute"

    $VALGRIND_CMD crm_resource -r dummy --meta -g is-managed
    assert $? 0 crm_resource "Query a resource meta attribute"

    $VALGRIND_CMD crm_resource -r dummy --meta -d is-managed
    assert $? 0 crm_resource "Remove a resource meta attribute"

    $VALGRIND_CMD crm_resource -r dummy -p delay -v 10s
    assert $? 0 crm_resource "Create a resource attribute"

    $VALGRIND_CMD crm_resource -L
    assert $? 0 crm_resource "List the configured resources"

    crm_failcount -r dummy -v 10 -N clusterNode-UNAME 2>&1
    assert $? 0 crm_resource "Set a resource's fail-count"

    $VALGRIND_CMD crm_resource -r dummy -M 2>&1
    assert $? 234 crm_resource "Require a destination when migrating a resource that is stopped"

    $VALGRIND_CMD crm_resource -r dummy -M -N i.dont.exist 2>&1
    assert $? 250 crm_resource "Don't support migration to non-existant locations"

    $VALGRIND_CMD crm_resource -r dummy -M -N clusterNode-UNAME
    assert $? 0 crm_resource "Migrate a resource"

    $VALGRIND_CMD crm_resource -r dummy -U
    assert $? 0 crm_resource "Un-migrate a resource"

    $VALGRIND_CMD crm_ticket -t ticketA -G granted -d false
    assert $? 0 crm_ticket "Default ticket granted state"

    $VALGRIND_CMD crm_ticket -t ticketA -r --force
    assert $? 0 crm_ticket "Set ticket granted state"

    $VALGRIND_CMD crm_ticket -t ticketA -G granted
    assert $? 0 crm_ticket "Query ticket granted state"

    $VALGRIND_CMD crm_ticket -t ticketA -D granted --force
    assert $? 0 crm_ticket "Delete ticket granted state"

    $VALGRIND_CMD crm_ticket -t ticketA -s
    assert $? 0 crm_ticket "Make a ticket standby"

    $VALGRIND_CMD crm_ticket -t ticketA -G standby
    assert $? 0 crm_ticket "Query ticket standby state"

    $VALGRIND_CMD crm_ticket -t ticketA -a
    assert $? 0 crm_ticket "Activate a ticket"

    $VALGRIND_CMD crm_ticket -t ticketA -D standby
    assert $? 0 crm_ticket "Delete ticket standby state"
 }

function test_date() {
#    $VALGRIND_CMD cibadmin -Q
    for y in 06 07 08 09 10 11 12 13 14 15 16 17 18; do
	$VALGRIND_CMD iso8601 -d "20$y-W01-7 00Z"
	$VALGRIND_CMD iso8601 -d "20$y-W01-7 00Z" -W -E "20$y-W01-7 00:00:00Z"
	assert $? 0 iso8601 "20$y-W01-7" 0
	$VALGRIND_CMD iso8601 -d "20$y-W01-1 00Z"
	$VALGRIND_CMD iso8601 -d "20$y-W01-1 00Z" -W -E "20$y-W01-1 00:00:00Z"
	assert $? 0 iso8601 "20$y-W01-1" 0
    done

    $VALGRIND_CMD iso8601 -d "2009-W53-7 00:00:00Z" -W -E "2009-W53-7 00:00:00Z"
    assert $? 0 iso8601 "2009-W53-07" 0

    $VALGRIND_CMD iso8601 -d "2009-01-31 00:00:00Z" -D "P1M" -E "2009-02-28 00:00:00Z"
    assert $? 0 iso8601 "2009-01-31 + 1 Month" 0

    $VALGRIND_CMD iso8601 -d "2009-01-31 00:00:00Z" -D "P2M" -E "2009-03-31 00:00:00Z"
    assert $? 0 iso8601 "2009-01-31 + 2 Months" 0

    $VALGRIND_CMD iso8601 -d "2009-01-31 00:00:00Z" -D "P3M" -E "2009-04-30 00:00:00Z"
    assert $? 0 iso8601 "2009-01-31 + 3 Months" 0

    $VALGRIND_CMD iso8601 -d "2009-03-31 00:00:00Z" -D "P-1M" -E "2009-02-28 00:00:00Z"
    assert $? 0 iso8601 "2009-03-31 - 1 Month" 0
 }

echo "Testing dates"
test_date > $test_home/regression.out
echo "Testing tools"
test_tools >> $test_home/regression.out
sed -i.sed 's/cib-last-written.*>/>/' $test_home/regression.out

if [ $do_save = 1 ]; then
    cp $test_home/regression.out $test_home/regression.exp
fi

grep -e "^*" $test_home/regression.out

if [ $num_errors != 0 ]; then
    echo $num_errors tests failed
    diff -wu $test_home/regression.exp $test_home/regression.out
    exit 1
fi

diff -wu $test_home/regression.exp $test_home/regression.out
if [ $? != 0 ]; then
    echo $num_passed tests passed but diff failed
    exit 2

else
    echo $num_passed tests passed
    exit 0
fi
