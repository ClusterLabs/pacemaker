#!/bin/bash

: ${shadow=tools-regression}

WHO=`whoami`
if [ $WHO != root ]; then
    echo This regression test needs to be run as root
    exit 1
fi

function test_tools() {
    crm_shadow --batch --force --create-empty $shadow
    CIB_shadow=$shadow ; export CIB_shadow
    cibadmin -Q
    
    crm_attribute -n foo -v bar
    cibadmin -Q
    
    cibadmin -C -o nodes --xml-text '<node id="uuid-1" uname="aHost" type="member"/>'
    cibadmin -C -o status --xml-text '<node_state id="uuid-1" uname="aHost"/>'
    cibadmin -Q
    
    crm_standby -N aHost -G
    crm_standby -N aHost -v true
    crm_standby -N aHost -G
    cibadmin -Q
    
    crm_standby -N aHost -D
    cibadmin -Q
    
    cibadmin -C -o resources --xml-text '<primitive id="dummy" class="ocf" provider="pacemaker" type="Dummy"/>'
    crm_resource -r dummy --meta -p is-managed -v false
    crm_resource -r dummy -p delay -v 10s
    crm_resource -L
    cibadmin -Q
    
    crm_failcount -r dummy -v 10 -N aHost
    cibadmin -Q
    
    crm_resource -r dummy -M
    crm_resource -r dummy -M -N i.dont.exist
    crm_resource -r dummy -M -N aHost
    cibadmin -Q

    crm_resource -r dummy -U
    cibadmin -Q
 }

if [ x$1 = x-? ]; then
    echo Usage: regression.sh [save]
    exit 0

elif [ x$1 = xsave ]; then
    test_tools 2>&1 | sed s/cib-last-written.*\>/\>/ | tee regression.exp
    cp regression.exp regression.out
else
    test_tools 2>&1 | sed s/cib-last-written.*\>/\>/ > regression.out
fi

diff -u regression.exp regression.out 
if [ $? = 0 ]; then
    echo Tests passed
else
    echo Tests failed
fi
