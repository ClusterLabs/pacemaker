#!/bin/sh

 # Copyright (C) 2007 Dejan Muhamedagic <dejan@suse.de>
 # 
 # This program is free software; you can redistribute it and/or
 # modify it under the terms of the GNU General Public
 # License as published by the Free Software Foundation; either
 # version 2.1 of the License, or (at your option) any later version.
 # 
 # This software is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 # General Public License for more details.
 # 
 # You should have received a copy of the GNU General Public
 # License along with this library; if not, write to the Free Software
 # Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 #

: ${TESTDIR:=testcases}
: ${CRM:=/usr/sbin/crm}
CRM_NO_REG="$CRM"
CRM="$CRM -R"
export PYTHONUNBUFFERED=1

. ./defaults
. ./crm-interface
. ./descriptions

resetvars() {
	unset args
	unset extcheck
}

#
# special operations squad
#
specopt_setenv() {
	eval $rest
}
specopt_ext() {
	eval $rest
}
specopt_extcheck() {
	extcheck="$rest"
	set $extcheck
	which "$1" >/dev/null 2>&1 ||  # a program in the PATH
		extcheck="$TESTDIR/$extcheck"  # or our script
}
specopt_repeat() {
	repeat_limit=$rest
}
specopt() {
	cmd=`echo $cmd | sed 's/%//'`  # strip leading '%'
	echo ".`echo $cmd | tr '[a-z]' '[A-Z]'` $rest"  # show what we got
	specopt_$cmd  # do what they asked for
}

#
# substitute variables in the test line
#
substvars() {
	sed "
	s/%t/$test_cnt/g
	s/%l/$line/g
	s/%i/$repeat_cnt/g
	"
}

dotest_session() {
	echo -n "." >&3
	test_cnt=$(($test_cnt+1))
	describe_session $*  # show what we are about to do
	crm_$cmd |  # and execute the command
		{ [ "$extcheck" ] && $extcheck || cat;}
}
dotest_single() {
	echo -n "." >&3
	test_cnt=$(($test_cnt+1))
	describe_single $* # show what we are about to do
	crm_single $* |  # and execute the command
		{ [ "$extcheck" ] && $extcheck || cat;}
	if [ "$showobj" ]; then
		crm_showobj $showobj
	fi
}
runtest_session() {
	while read line; do
		if [ "$line" = . ]; then
			break
		fi
		echo "$line"
	done | dotest_session $*
}
runtest_single() {
	while [ $repeat_cnt -le $repeat_limit ]; do
		dotest_single $*
		resetvars  # unset all variables
		repeat_cnt=$(($repeat_cnt+1))
	done
	repeat_limit=1 repeat_cnt=1
}

#
# run the tests
#
repeat_limit=1 repeat_cnt=1
line=1
test_cnt=1

crm_setup
crm_mksample
while read cmd rest; do
	case "$cmd" in
		"") : empty ;;
		"#"*) : a comment ;;
		"%stop") break ;;
		"%"*) specopt ;;
		show|showxml|session) runtest_session $rest ;;
		*) runtest_single $cmd $rest ;;
	esac
	line=$(($line+1))
done
