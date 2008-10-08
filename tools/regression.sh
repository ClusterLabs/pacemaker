#!/bin/bash

: ${shadow=tools-regression}

WHO=`whoami`
if [ $WHO != root ]; then
    echo This regression test needs to be run as root
    exit 1
fi


num_errors=0
num_passed=0

function assert() {
    rc=$1; shift
    target=$1; shift
    app=$1; shift
    msg=$1; shift
    exit_code=$1; shift

    cibadmin -Q

    if [ $rc -ne $target ]; then
	num_errors=`expr $num_errors + 1`
	printf "* Failed (rc=%.3d): %-14s - %s\n" $rc $app "$msg"
	if [ ! -z $exit_code ]; then
	    echo "Aborting tests"
	    exit $exit_code
	fi
	exit 1
    else
	printf "* Passed: %-14s - %s\n" $app "$msg"
	num_passed=`expr $num_passed + 1`
    fi
}

function usage() {
    echo "Usage: ./regression.sh [-s(ave)] [-x] [-v(erbose)]"
    exit $1
}

done=0
do_save=0
while test "$done" = "0"; do
    case "$1" in
	-v) verbose=1; shift;;
	-x) set -x; shift;;
	-s) do_save=1; shift;;
	-?) usage 0;;
	-*) echo "unknown option: $1"; usage 1;;
	*) done=1;;
    esac
done

function test_tools() {
    crm_shadow --batch --force --create-empty $shadow
    CIB_shadow=$shadow ; export CIB_shadow
    cibadmin -Q
    
    cibadmin -E 
    assert $? 1 cibadmin "Require --force for CIB erasure"
    
    cibadmin -E --force
    assert $? 0 cibadmin "Allow CIB erasure with --force"
    
    cibadmin -Q > /tmp/$$.existing.xml
    assert $? 0 cibadmin "Query CIB"

    crm_attribute -n cluster-delay -v 60s
    assert $? 0 crm_attribute "Set cluster option"

    cibadmin -Q -o crm_config | grep cib-bootstrap-options-cluster-delay 
    assert $? 0 cibadmin "Query new cluster option"

    cibadmin -Q -o crm_config > /tmp/$$.opt.xml
    assert $? 0 cibadmin "Query cluster options"
    
    cibadmin -D -o crm_config --xml-text '<nvpair id="cib-bootstrap-options-cluster-delay"/>'
    assert $? 0 cibadmin "Delete nvpair"
    
    cibadmin -C -o crm_config --xml-file /tmp/$$.opt.xml 
    assert $? 21 cibadmin "Create operaton should fail with: -21, The object already exists"
    
    cibadmin -M -o crm_config --xml-file /tmp/$$.opt.xml
    assert $? 0 cibadmin "Modify cluster options section"
    
    cibadmin -Q -o crm_config | grep cib-bootstrap-options-cluster-delay 
    assert $? 0 cibadmin "Query updated cluster option"
    
    crm_attribute -n cluster-delay -v 40s -s duplicate 
    assert $? 0 crm_attribute "Set duplicate cluster option"
    
    crm_attribute -n cluster-delay -v 30s 
    assert $? 216 crm_attribute "Setting multiply defined cluster option should fail with -216, Could not set cluster option"
    
    crm_attribute -n cluster-delay -v 30s -s duplicate
    assert $? 0 crm_attribute "Set cluster option with -s"
    
    crm_attribute -n cluster-delay -D -i cib-bootstrap-options-cluster-delay
    assert $? 0 crm_attribute "Delete cluster option with -i"
    
    cibadmin -C -o nodes --xml-text '<node id="clusterNode-UUID" uname="clusterNode-UNAME" type="member">'
    assert $? 0 cibadmin "Create node entry"
    
    cibadmin -C -o status --xml-text '<node_state id="clusterNode-UUID" uname="clusterNode-UNAME"/>'
    assert $? 0 cibadmin "Create node status entry"
        
    crm_attribute -n ram -v 1024M -U clusterNode-UNAME -t nodes
    assert $? 0 crm_attribute "Create node attribute"
    
    cibadmin -Q -o nodes | grep clusterNode-UUID-ram 
    assert $? 0 cibadmin "Query new node attribute"
    
    cibadmin -Q | cibadmin -5 -p 2>&1 > /dev/null
    assert $? 0 cibadmin "Digest calculation"
    
    # This update will fail because it has version numbers
    cibadmin -R --xml-file /tmp/$$.existing.xml
    assert $? 45 cibadmin "Replace operation should fail with: -45, Update was older than existing configuration"

    crm_standby -N clusterNode-UNAME -G
    assert $? 0 crm_standby "Default standby value"

    crm_standby -N clusterNode-UNAME -v true
    assert $? 0 crm_standby "Set standby status"

    crm_standby -N clusterNode-UNAME -G
    assert $? 0 crm_standby "Query standby value"
    
    crm_standby -N clusterNode-UNAME -D
    assert $? 0 crm_standby "Delete standby value"
    
    cibadmin -C -o resources --xml-text '<primitive id="dummy" class="ocf" provider="pacemaker" type="Dummy"/>'
    assert $? 0 cibadmin "Create a resource"

    crm_resource -r dummy --meta -p is-managed -v false
    assert $? 0 crm_resource "Create a resource meta attribute"

    crm_resource -r dummy -p delay -v 10s
    assert $? 0 crm_resource "Create a resource attribute"

    crm_resource -L
    assert $? 0 crm_resource "List the configured resources"

    crm_failcount -r dummy -v 10 -N clusterNode-UNAME
    assert $? 0 crm_resource "Set a resource's fail-count"

    crm_resource -r dummy -M
    assert $? 244 crm_resource "Require a destination when migrating a resource that is stopped"

    crm_resource -r dummy -M -N i.dont.exist
    assert $? 234 crm_resource "Don't support migration to non-existant locations"

    crm_resource -r dummy -M -N clusterNode-UNAME
    assert $? 0 crm_resource "Migrate a resource"

    crm_resource -r dummy -U
    assert $? 0 crm_resource "Un-migrate a resource"
 }

test_tools 2>&1 | sed s/cib-last-written.*\>/\>/ > regression.out
rc=$?

if [ $do_save = 1 ]; then
    cp regression.out regression.exp
fi

diff -u regression.exp regression.out 
diff_rc=$?

if [ $rc != 0 ]; then
    echo Tests failed
elif [ $diff_rc != 0 ]; then
    echo Tests passed but diff failed
else
    echo Tests passed
fi
