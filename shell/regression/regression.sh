#!/bin/sh

 # Copyright (C) 2007 Dejan Muhamedagic <dmuhamedagic@suse.de>
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

rootdir=`dirname $0`
TESTDIR=${TESTDIR:-$rootdir/testcases}
DFLT_TESTSET=basicset
OUTDIR=${OUTDIR:-crmtestout}
CRM_OUTF="$OUTDIR/crm.out"
CRM_LOGF="$OUTDIR/crm.log"
CRM_DEBUGF="$OUTDIR/crm.debug"
OUTF="$OUTDIR/regression.out"
LRMD_OPTS=""
DIFF_OPTS="--ignore-all-space -U 1"
common_filter=$TESTDIR/common.filter
common_exclf=$TESTDIR/common.excl
export OUTDIR

logmsg() {
	echo "`date`: $*" | tee -a $CRM_DEBUGF | tee -a $CRM_LOGF
}
abspath() {
	echo $1 | grep -qs "^/" &&
		echo $1 ||
		echo `pwd`/$1
}

usage() {
	cat<<EOF

usage: $0 [-q] [testcase...|set:testset]

Test crm shell using supplied testcases. If none are given,
set:basicset is used. All testcases and sets are in testcases/.
See also README.regression for description.

-q: quiet operation (no progress shown)

EOF
exit 2
}

if [ ! -d "$TESTDIR" ]; then
	echo "$0: $TESTDIR does not exit"
	usage
fi

rm -f $CRM_LOGF $CRM_DEBUGF

# make tools/lrmd/stonithd log to our files only
HA_logfile=`abspath $CRM_LOGF`
HA_debugfile=`abspath $CRM_DEBUGF`
HA_use_logd=no
HA_logfacility=""
export HA_logfile HA_debugfile HA_use_logd HA_logfacility

mkdir -p $OUTDIR
. /etc/ha.d/shellfuncs

args=`getopt hqc:p:m: $*`
[ $? -ne 0 ] && usage
eval set -- "$args"

output_mode="normal"
while [ x"$1" != x ]; do
	case "$1" in
		-h) usage;;
	        -m) output_mode=$2; shift 1;;	    
		-q) output_mode="silent";;
	        -c) CRM=$2; export CRM; shift 1;;
	        -p) PATH="$2:$PATH"; export PATH; shift 1;;
		--) shift 1; break;;
		*) usage;;
	esac
	shift 1
done

exec >$OUTF 2>&1

# Where to send user output
# evaltest.sh also uses >&3 for printing progress dots
case $output_mode in 
    silent) exec 3>/dev/null;;
    buildbot) exec 3>$CRM_OUTF;;
    *) exec 3>/dev/tty;;
esac

setenvironment() {
	filterf=$TESTDIR/$testcase.filter
	exclf=$TESTDIR/$testcase.excl
	log_filter=$TESTDIR/$testcase.log_filter
	expf=$TESTDIR/$testcase.exp
	outf=$OUTDIR/$testcase.out
	difff=$OUTDIR/$testcase.diff
}

filter_output() {
	{ [ -x $common_filter ] && $common_filter || cat;} |
	{ [ -f $common_exclf ] && egrep -vf $common_exclf || cat;} |
	{ [ -x $filterf ] && $filterf || cat;} |
	{ [ -f $exclf ] && egrep -vf $exclf || cat;}
}

dumpcase() {
	cat<<EOF
----------
testcase $testcase failed
output is in $outf
diff (from $difff):
`cat $difff`
----------
EOF
}

runtestcase() {
	setenvironment
	echo -n "$testcase" >&3
	logmsg "BEGIN testcase $testcase"
	(
	cd $rootdir
	./evaltest.sh
	) < $TESTDIR/$testcase > $outf 2>&1

	filter_output < $outf |
	if [ "$prepare" ]; then
		echo " saving to expect file" >&3
		cat > $expf
	else
		echo -n " checking..." >&3
		if head -2 $expf | grep -qs '^<cib'; then
			crm_diff -o $expf -n -
		else
			diff $DIFF_OPTS $expf -
		fi > $difff
		if [ $? -ne 0 ]; then
			echo " FAIL" >&3
			dumpcase
			return 1
		else
			echo " PASS" >&3
			rm -f $outf $difff
		fi
	fi
	sed -n "/BEGIN testcase $testcase/,\$p" $CRM_LOGF |
		{ [ -x $log_filter ] && $log_filter || cat;} |
		egrep '(CRIT|ERROR):'
	logmsg "END testcase $testcase"
}

[ "$1" = prepare ] && { prepare=1; shift 1;}
[ $# -eq 0 ] && set "set:$DFLT_TESTSET"

for a; do
	if [ "$a" -a -f "$TESTDIR/$a" ]; then
		testcase=$a
		runtestcase
	else
		echo "$a" | grep -q "^set:" &&
			TESTSET=$TESTDIR/`echo $a | sed 's/set://'`
		while read testcase; do
			runtestcase
		done < $TESTSET
	fi
done

if egrep -wv '(BEGIN|END) testcase' $OUTF >/dev/null
then
	echo "seems like some tests failed or else something not expected"
	echo "check $OUTF and diff files in $OUTDIR"
	echo "in case you wonder what lrmd was doing, read $CRM_LOGF and $CRM_DEBUGF"
	exit 1
fi >&3
