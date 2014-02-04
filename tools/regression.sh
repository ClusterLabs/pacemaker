#!/bin/bash

: ${shadow=tools-regression}
test_home=`dirname $0`
num_errors=0
num_passed=0
GREP_OPTIONS=

function test_assert() {
    target=$1; shift
    cib=$1; shift
    app=`echo "$cmd" | sed 's/\ .*//'`
    printf "* Running: $app - $desc\n" 1>&2

    printf "=#=#=#= Begin test: $desc =#=#=#=\n"
    eval $VALGRIND_CMD $cmd 2>&1
    rc=$?

    if [ x$cib != x0 ]; then
	cibadmin -Q
    fi

    printf "=#=#=#= End test: $desc - `crm_error $rc` ($rc) =#=#=#=\n"

    if [ $rc -ne $target ]; then
	num_errors=`expr $num_errors + 1`
	printf "* Failed (rc=%.3d): %-14s - %s\n" $rc $app "$desc"
	printf "* Failed (rc=%.3d): %-14s - %s\n" $rc $app "$desc (`which $app`)" 1>&2
	return
	exit 1
    else
	printf "* Passed: %-14s - %s\n" $app "$desc"

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
	    VALGRIND_CMD="valgrind -q --gen-suppressions=all --show-reachable=no --leak-check=full --trace-children=no --time-stamp=yes --num-callers=20 --suppressions=/usr/share/pacemaker/tests/valgrind-pcmk.suppressions"
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
    xml_home=`dirname ${test_home}`
    echo "Using local binaries from: $test_home, schemas from $xml_home"
    export PATH="$test_home:$PATH"
    export PCMK_schema_directory=${xml_home}/xml
fi

function test_tools() {
    export CIB_shadow_dir=$test_home
    $VALGRIND_CMD crm_shadow --batch --force --create-empty $shadow  2>&1
    export CIB_shadow=$shadow

    desc="Validate CIB"
    cmd="cibadmin -Q"
    test_assert 0

    desc="Require --force for CIB erasure"
    cmd="cibadmin -E"
    test_assert 22

    desc="Allow CIB erasure with --force"
    cmd="cibadmin -E --force"
    test_assert 0

    desc="Query CIB"
    cmd="cibadmin -Q > /tmp/$$.existing.xml"
    test_assert 0

    desc="Set cluster option"
    cmd="crm_attribute -n cluster-delay -v 60s"
    test_assert 0

    desc="Query new cluster option"
    cmd="cibadmin -Q -o crm_config | grep cib-bootstrap-options-cluster-delay"
    test_assert 0

    desc="Query cluster options"
    cmd="cibadmin -Q -o crm_config > /tmp/$$.opt.xml"
    test_assert 0

    desc="Set no-quorum policy"
    cmd="crm_attribute -n no-quorum-policy -v ignore"
    test_assert 0

    desc="Delete nvpair"
    cmd="cibadmin -D -o crm_config --xml-text '<nvpair id=\"cib-bootstrap-options-cluster-delay\"/>'"
    test_assert 0

    desc="Create operaton should fail"
    cmd="cibadmin -C -o crm_config --xml-file /tmp/$$.opt.xml"
    test_assert 76

    desc="Modify cluster options section"
    cmd="cibadmin -M -o crm_config --xml-file /tmp/$$.opt.xml"
    test_assert 0

    desc="Query updated cluster option"
    cmd="cibadmin -Q -o crm_config | grep cib-bootstrap-options-cluster-delay"
    test_assert 0

    desc="Set duplicate cluster option"
    cmd="crm_attribute -n cluster-delay -v 40s -s duplicate"
    test_assert 0

    desc="Setting multiply defined cluster option should fail"
    cmd="crm_attribute -n cluster-delay -v 30s"
    test_assert 76

    desc="Set cluster option with -s"
    cmd="crm_attribute -n cluster-delay -v 30s -s duplicate"
    test_assert 0

    desc="Delete cluster option with -i"
    cmd="crm_attribute -n cluster-delay -D -i cib-bootstrap-options-cluster-delay"
    test_assert 0

    desc="Create node1 and bring it online"
    cmd="crm_simulate --live-check --in-place --node-up=node1"
    test_assert 0

    desc="Create node attribute"
    cmd="crm_attribute -n ram -v 1024M -U node1 -t nodes"
    test_assert 0

    desc="Query new node attribute"
    cmd="cibadmin -Q -o nodes | grep node1-ram"
    test_assert 0

    desc="Digest calculation"
    cmd="cibadmin -Q | cibadmin -5 -p 2>&1 > /dev/null"
    test_assert 0

    # This update will fail because it has version numbers
    desc="Replace operation should fail"
    cmd="cibadmin -R --xml-file /tmp/$$.existing.xml"
    test_assert 205

    desc="Default standby value"
    cmd="crm_standby -N node1 -G"
    test_assert 0
 
    desc="Set standby status"
    cmd="crm_standby -N node1 -v true"
    test_assert 0
 
    desc="Query standby value"
    cmd="crm_standby -N node1 -G"
    test_assert 0
 
    desc="Delete standby value"
    cmd="crm_standby -N node1 -D"
    test_assert 0

    desc="Create a resource"
    cmd="cibadmin -C -o resources --xml-text '<primitive id=\"dummy\" class=\"ocf\" provider=\"pacemaker\" type=\"Dummy\"/>'"
    test_assert 0

    desc="Create a resource meta attribute"
    cmd="crm_resource -r dummy --meta -p is-managed -v false"
    test_assert 0

    desc="Query a resource meta attribute"
    cmd="crm_resource -r dummy --meta -g is-managed"
    test_assert 0

    desc="Remove a resource meta attribute"
    cmd="crm_resource -r dummy --meta -d is-managed"
    test_assert 0

    desc="Create a resource attribute"
    cmd="crm_resource -r dummy -p delay -v 10s"
    test_assert 0

    desc="List the configured resources"
    cmd="crm_resource -L"
    test_assert 0

    desc="Set a resource's fail-count"
    cmd="crm_failcount -r dummy -v 10 -N node1"
    test_assert 0

    desc="Require a destination when migrating a resource that is stopped"
    cmd="crm_resource -r dummy -M"
    test_assert 22

    desc="Don't support migration to non-existant locations"
    cmd="crm_resource -r dummy -M -N i.dont.exist"
    test_assert 6

    desc="Create a fencing resource"
    cmd="cibadmin -C -o resources --xml-text '<primitive id=\"Fence\" class=\"stonith\" type=\"fence_true\"/>'"
    test_assert 0

    desc="Bring resources online"
    cmd="crm_simulate --live-check --in-place -S"
    test_assert 0

    desc="Try to move a resource to its existing location"
    cmd="crm_resource -r dummy --move --host node1"
    test_assert 22

    desc="Move a resource from its existing location"
    cmd="crm_resource -r dummy --move"
    test_assert 0

    desc="Clear out constraints generated by --move"
    cmd="crm_resource -r dummy --clear"
    test_assert 0

    desc="Default ticket granted state"
    cmd="crm_ticket -t ticketA -G granted -d false"
    test_assert 0

    desc="Set ticket granted state"
    cmd="crm_ticket -t ticketA -r --force"
    test_assert 0

    desc="Query ticket granted state"
    cmd="crm_ticket -t ticketA -G granted"
    test_assert 0

    desc="Delete ticket granted state"
    cmd="crm_ticket -t ticketA -D granted --force"
    test_assert 0

    desc="Make a ticket standby"
    cmd="crm_ticket -t ticketA -s"
    test_assert 0

    desc="Query ticket standby state"
    cmd="crm_ticket -t ticketA -G standby"
    test_assert 0

    desc="Activate a ticket"
    cmd="crm_ticket -t ticketA -a"
    test_assert 0

    desc="Delete ticket standby state"
    cmd="crm_ticket -t ticketA -D standby"
    test_assert 0

    desc="Ban a resource on unknown node"
    cmd="crm_resource -r dummy -B -N host1"
    test_assert 6

    desc="Create two more nodes and bring them online"
    cmd="crm_simulate --live-check --in-place --node-up=node2 --node-up=node3"
    test_assert 0

    desc="Ban dummy from node1"
    cmd="crm_resource -r dummy -B -N node1"
    test_assert 0

    desc="Ban dummy from node2"
    cmd="crm_resource -r dummy -B -N node2"
    test_assert 0

    desc="Relocate resources due to ban"
    cmd="crm_simulate --live-check --in-place -S"
    test_assert 0

    desc="Move dummy to node1"
    cmd="crm_resource -r dummy -M -N node1"
    test_assert 0

    desc="Clear implicit constraints for dummy on node2"
    cmd="crm_resource -r dummy -U -N node2"
    test_assert 0
 }

function test_date() {
    for y in 06 07 08 09 10 11 12 13 14 15 16 17 18; do
	desc="20$y-W01-7"
	cmd="iso8601 -d '20$y-W01-7 00Z'"
	test_assert 0 0

	desc="20$y-W01-7 - round-trip"
	cmd="iso8601 -d '20$y-W01-7 00Z' -W -E '20$y-W01-7 00:00:00Z'"
	test_assert 0 0

	desc="20$y-W01-1"
	cmd="iso8601 -d '20$y-W01-1 00Z'"
	test_assert 0 0

	desc="20$y-W01-1 - round-trip"
	cmd="iso8601 -d '20$y-W01-1 00Z' -W -E '20$y-W01-1 00:00:00Z'"
	test_assert 0 0
    done

    desc="2009-W53-07"
    cmd="iso8601 -d '2009-W53-7 00:00:00Z' -W -E '2009-W53-7 00:00:00Z'"
    test_assert 0 0

    desc="2009-01-31 + 1 Month"
    cmd="iso8601 -d '2009-01-31 00:00:00Z' -D P1M -E '2009-02-28 00:00:00Z'"
    test_assert 0 0

    desc="2009-01-31 + 2 Months"
    cmd="iso8601 -d '2009-01-31 00:00:00Z' -D P2M -E '2009-03-31 00:00:00Z'"
    test_assert 0 0

    desc="2009-01-31 + 3 Months"
    cmd="iso8601 -d '2009-01-31 00:00:00Z' -D P3M -E '2009-04-30 00:00:00Z'"
    test_assert 0 0

    desc="2009-03-31 - 1 Month"
    cmd="iso8601 -d '2009-03-31 00:00:00Z' -D P-1M -E '2009-02-28 00:00:00Z'"
    test_assert 0 0
 }

echo "Testing dates"
test_date > $test_home/regression.out
echo "Testing tools"
test_tools >> $test_home/regression.out
sed -i -e 's/cib-last-written.*>/>/'	\
    -e 's/ last-run=\"[0-9]*\"//'	\
    -e 's/crm_feature_set="[^"]*"//'	\
    -e 's/ last-rc-change=\"[0-9]*\"//' $test_home/regression.out

sed -i -e 's/cib-last-written.*>/>/'	\
    -e 's/ last-run=\"[0-9]*\"//'	\
    -e 's/crm_feature_set="[^"]*"//'	\
    -e 's/ last-rc-change=\"[0-9]*\"//' $test_home/regression.exp

if [ $do_save = 1 ]; then
    cp $test_home/regression.out $test_home/regression.exp
fi

failed=0

echo -e "\n\nResults"
diff -wu $test_home/regression.exp $test_home/regression.out
if [ $? != 0 ]; then
    failed=1
fi

echo -e "\n\nSummary"
grep -e "^*" $test_home/regression.out

if [ $num_errors != 0 ]; then
    echo $num_errors tests failed
    exit 1
elif [ $failed = 1 ]; then
    echo $num_passed tests passed but diff failed
    exit 2
else
    echo $num_passed tests passed
    exit 0
fi
