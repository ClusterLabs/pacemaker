#!/bin/bash

num_errors=0
num_passed=0

assert() {
    rc=$1; shift
    target=$1; shift
    app=$1; shift
    msg=$1; shift
    exit_code=$1; shift
    if [ $rc -ne $target ]; then
	num_errors=`expr $num_errors + 1`
	printf "* Failed (rc=%.3d): %-14s - %s\n" $rc $app "$msg"
	cibadmin -Ql
	if [ ! -z $exit_code ]; then
	    echo "Aborting tests"
	    exit $exit_code
	fi
    else
	printf "* Passed: %-14s - %s\n" $app "$msg"
	num_passed=`expr $num_passed + 1`
    fi
}

done=0
cib_opts=""

while test "$done" = "0"; do
    case "$1" in
	-v) verbose=1; shift;;
	-l) cib_opts="$cib_opts -l"; shift;;
	-x) set -x; shift;;
	-?) usage 0;;
	-*) echo "unknown option: $1"; usage 1;;
	*) done=1;;
    esac
done

printf " %-9s %-16s %s\n" Result App Test

# Save backup
cibadmin $cib_opts -Q > /tmp/$$.existing.xml
assert $? 0 cibadmin "Query CIB"

# Create a combined backup

echo '<cib>' > /tmp/$$.combined.xml
echo '<configuration>' >> /tmp/$$.combined.xml

cibadmin $cib_opts -Q -o crm_config >> /tmp/$$.combined.xml
assert $? 0 cibadmin "Query CIB for config options"

cibadmin $cib_opts -Q -o nodes >> /tmp/$$.combined.xml
assert $? 0 cibadmin "Query CIB for nodes"

cibadmin $cib_opts -Q -o resources >> /tmp/$$.combined.xml
assert $? 0 cibadmin "Query CIB for resources"

cibadmin $cib_opts -Q -o constraints >> /tmp/$$.combined.xml
assert $? 0 cibadmin "Query CIB for constraints"

echo '</configuration>' >> /tmp/$$.combined.xml

cibadmin $cib_opts -Q -o status >> /tmp/$$.combined.xml
assert $? 0 cibadmin "Query CIB for status"

echo '</cib>' >> /tmp/$$.combined.xml

# Test various tools and options

cibadmin $cib_opts -E > /dev/null 2>&1
assert $? 1 cibadmin "Require --force for CIB erasure"

cibadmin $cib_opts -E --force
assert $? 0 cibadmin "Allow CIB erasure with --force"

crm_attribute -n cluster-delay -v 60s
assert $? 0 crm_attribute "Set cluster option"

cibadmin $cib_opts -Q -o crm_config | grep cib-bootstrap-options-cluster-delay > /dev/null 2>&1
assert $? 0 cibadmin "Query new cluster option"

cibadmin $cib_opts -Q -o crm_config > /tmp/$$.opt.xml
assert $? 0 cibadmin "Query cluster options"

cibadmin $cib_opts -D -o crm_config -X '<nvpair id="cib-bootstrap-options-cluster-delay"/>'
assert $? 0 cibadmin "Delete nvpair"

cibadmin $cib_opts -C -o crm_config -x /tmp/$$.opt.xml > /dev/null 2>&1
assert $? 21 cibadmin "Create operaton should fail with: -21, The object already exists"

cibadmin $cib_opts -M -o crm_config -x /tmp/$$.opt.xml
assert $? 0 cibadmin "Modify cluster options section"

cibadmin $cib_opts -Q -o crm_config | grep cib-bootstrap-options-cluster-delay > /dev/null 2>&1
assert $? 0 cibadmin "Query updated cluster option"

crm_attribute -n cluster-delay -v 40s -s duplicate > /dev/null 2>&1
assert $? 0 crm_attribute "Set duplicate cluster option"

crm_attribute -n cluster-delay -v 30s > /dev/null 2>&1
assert $? 216 crm_attribute "Setting multiply defined cluster option should fail with -216, Could not set cluster option"

crm_attribute -n cluster-delay -v 30s -s duplicate
assert $? 0 crm_attribute "Set cluster option with -s"

crm_attribute -n cluster-delay -D -i cib-bootstrap-options-cluster-delay
assert $? 0 crm_attribute "Delete cluster option with -i"

cibadmin -C -o nodes -X '<node id="i-dont-exist-UUID" uname="i-dont-exist-UNAME">'
assert $? 0 cibadmin "Create node entry"

crm_attribute -n ram -v 1024M -U i-dont-exist-UNAME -t nodes
assert $? 0 crm_attribute "Create node attribute"

cibadmin $cib_opts -Q -o nodes | grep i-dont-exist-UUID-ram > /dev/null 2>&1
assert $? 0 cibadmin "Query new node attribute"

cibadmin $cib_opts -Q | cibadmin -5 -p > /dev/null 2>&1
assert $? 0 cibadmin "Digest calculation"

# This update will fail because it has version numbers
cibadmin $cib_opts -R -x /tmp/$$.existing.xml > /dev/null 2>&1
assert $? 45 cibadmin "Replace operation should fail with: -45, Update was older than existing configuration"

# Restore the existing config
cibadmin $cib_opts -R -x /tmp/$$.combined.xml
assert $? 0 cibadmin "Version-less replace operation"

set +x

rm /tmp/$$.opt.xml
rm /tmp/$$.existing.xml

if [ $num_errors -gt 0 ]; then
    echo Tests failed: $agent failed $num_errors tests
    exit 1
else 
    echo All $num_passed tests completed successfully
    exit 0
fi
