#!/bin/bash

declare -A headers
headers[crmcommon]="include/crm/common include/crm/crm.h"
headers[crmcluster]="include/crm/cluster.h"
headers[transitioner]="include/crm/transition.h"
headers[cib]="include/crm/cib*"
headers[pe_rules]="include/crm/pengine/rules.h"
headers[pe_status]="include/crm/pengine"
headers[stonithd]="include/crm/stonith-ng.h"
headers[pengine]="include/crm/pengine pengine/*.h"

LAST_RELEASE=`test -e /Volumes || git tag -l | grep Pacemaker | sort -Vr | head -n 1`
for lib in crmcommon crmcluster transitioner cib pe_rules pe_status stonithd pengine; do
    git diff $LAST_RELEASE..HEAD ${headers[$lib]}
    echo ""

    am=`find . -name Makefile.am -exec grep -lr "lib${lib}_la.*version-info" \{\} \;`
    am_dir=`dirname $am`

    if
	grep "lib${lib}_la_SOURCES.*\\\\" $am
    then
	echo -e "\033[1;35m -- Sources list for lib$lib is probably truncated! --\033[0m"
	echo ""
    fi

    sources=`grep "lib${lib}_la_SOURCES" $am | sed s/.*=// | sed 's:$(top_builddir)/::' | sed 's:$(top_srcdir)/::' | sed 's:\\\::' | sed 's:$(libpe_rules_la_SOURCES):rules.c\ common.c:'`
    full_sources=""
    for f in $sources; do
	if 
	    echo $f | grep -q "/"
	then
	    full_sources="$full_sources $f"
	else
	    full_sources="$full_sources $am_dir/$f"
	fi
    done

    lines=`git diff $LAST_RELEASE..HEAD ${headers[$lib]} $full_sources | wc -l`

    if [ $lines -gt 0 ]; then
	echo "- Headers: ${headers[$lib]}"
	echo "- Sources: $full_sources"
	echo ""
	read -p "Are the changes to lib$lib: [A]dditions, [R]emovals or [F]ixes? [None]: " CHANGE

	git show $LAST_RELEASE:$am | grep version-info 
	VER=`git show $LAST_RELEASE:$am | grep "lib.*${lib}_la.*version-info" | sed s/.*version-info// | awk '{print $1}'`
	VER_NOW=`grep "lib.*${lib}_la.*version-info" $am | sed s/.*version-info// | awk '{print $1}'`
	VER_1=`echo $VER | awk -F: '{print $1}'`
	VER_2=`echo $VER | awk -F: '{print $2}'`
	VER_3=`echo $VER | awk -F: '{print $3}'`

	case $CHANGE in
	    A|a) 
		echo "x+1:0:z+1"
		VER_1=`expr $VER_1 + 1`
		VER_2=0
		VER_3=`expr $VER_3 + 1`
		;;
	    R|r)
		echo "x+1:0:0"
		VER_1=`expr $VER_1 + 1`
		VER_2=0
		VER_3=0
		;;
	    F|f) 
		echo "x:y+1:z"
		VER_2=`expr $VER_2 + 1`
		;;
	esac
	VER_NEW=$VER_1:$VER_2:$VER_3
	
	if [ $VER_NEW != $VER_NOW ]; then
	    read -p "Updating $lib library version: $VER -> $VER_NEW"
	    sed -i.sed  "s/version-info\ $VER_NOW/version-info\ $VER_NEW/" $am
	else
	    read -p "No further version changes needed"
	fi
	
    else
	read -p "No changes to $lib interface"
    fi
    echo ""
done

git diff
