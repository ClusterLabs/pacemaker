#!/bin/bash

# Copyright (C) 2009 Lars Marowsky-Bree <lmb@suse.de>
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

BASE=${1:-`pwd`}
AUTOCREATE=1

logt() {
	local msg="$1"
	echo $(date) "$msg" >>$LOGF
	echo "$msg"
}

run() {
	local cmd="$1"
	local erc="$2"
	local msg="$3"
	local rc
	local out

	echo $(date) "$1" >>$LOGF
	$1 >>$LOGF 2>&1 ; rc=$?
	echo $(date) "Returned: $rc (expected $erc)" >>$LOGF
	if [ $erc != "I" ]; then
		if [ $rc -ne $erc ]; then
			logt "$msg: FAILED ($erc != $rc)"
			logt "See $LOGF for details."
			exit 1
		fi
	fi
	echo "$msg: ok"
}

runt() {
	local T="$1"
	local CIBE="$BASE/$(basename $T .input).exp.xml"
	run "crm" 0 "Running testcase: $T" <$T
	local rc
	if [ ! -e $CIBE ]; then
		if [ "$AUTOCREATE" = "1" ]; then
			logt "Creating new expected output for $T."
			cp $CIB_file $CIBE
			return 0
		else
			logt "$T: No expected output."
			return 0
		fi
	fi

	if ! crm_diff -o $CIBE -n $CIB_file >/dev/null 2>&1 ; then
		logt "$T: XML: $CIBE does not match $CIB_file"
		exit 1
	fi
}

LOGF=$(mktemp)
export PATH=/usr/sbin:$PATH

export CIB_file=$BASE/shadow.test
cp $BASE/shadow.base $CIB_file

for T in $(ls $BASE/*.input) ; do
	runt $T
done

logt "All tests passed!"
rm $LOGF $CIB_file
exit 0

