#!/bin/bash

 # Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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

verbose=$1
io_dir=testcases
diff_opts="--ignore-all-space -1 -u"
failed=.regression.failed
# zero out the error log
> $failed

function do_test {

    base=$1;
    name=$2;
    input=$io_dir/${base}.xml
    output=$io_dir/${base}.out
    expected=$io_dir/${base}.exp

    if [ ! -f $input ]; then
	echo "Test $name	($base)...	Error ($input)";
	return;
    fi

    if [ "$create_mode" != "true" -a ! -f $expected ]; then
	echo "Test $name	($base)...	Error ($expected)";
#	return;
    fi

    ./ptest < $input 2>/dev/null 2>/dev/null > $output

    if [ ! -s $output ]; then
	echo "Test $name	($base)...	Error ($output)";
	rm $output
	return;
    fi

    ./fix_xml.pl $output

    if [ ! -s $output ]; then
	echo "Test $name	($base)...	Error (fixed $output)";
	rm $output
	return;
    fi

    if [ "$create_mode" = "true" ]; then
	cp "$output" "$expected"
    fi

    diff $diff_opts -q $expected $output >/dev/null
    rc=$?

    if [ "$create_mode" = "true" ]; then
	echo "Test $name	($base)...	Created expected output" 
    elif [ "$rc" = 0 ]; then
	echo "Test $name	($base)...	Passed";
    elif [ "$rc" = 1 ]; then
	echo "Test $name	($base)...	* Failed";
	diff $diff_opts $expected $output 2>/dev/null >> $failed
    else 
	echo "Test $name	($base)...	Error (diff: $rc)";
	echo "==== Raw results for test ($base) ====" >> $failed
	cat $output 2>/dev/null >> $failed
    fi
    
    rm $output
}

create_mode="false"
do_test simple1 "Offline	"
do_test simple2 "Start	"
do_test simple3 "Start 2	"
do_test simple4 "Start Failed"
do_test simple6 "Stop Start	"
do_test simple7 "Shutdown	"
#do_test simple8 "Stonith	"
do_test simple9 "Lower version"
do_test simple10 "Higher version"
do_test simple11 "Priority (ne)"
do_test simple12 "Priority (eq)"

echo ""

do_test rsc_rsc1 "Must not	"
do_test rsc_rsc2 "Should not	"
do_test rsc_rsc3 "Must	"
do_test rsc_rsc4 "Should	"
do_test rsc_rsc5 "Must not 3	"
do_test rsc_rsc6 "Should not 3"
do_test rsc_rsc7 "Must 3	"
do_test rsc_rsc8 "Should 3	"
do_test rsc_rsc10 "Must (cant)"
do_test rsc_rsc9 "2*MustNot 1*ShouldNot"

echo ""
do_test attrs1 "string: eq (and)	"
do_test attrs2 "string: lt / gt (and)"
do_test attrs3 "string: ne (or)	"
do_test attrs4 "string: exists	"
do_test attrs5 "string: notexists	"

echo ""
do_test stopfail1 "Stop Failed - STONITH	"
do_test stopfail2 "Stop Failed - Block	"
do_test stopfail3 "Stop Failed - Ignore (1 node)"
do_test stopfail4 "Stop Failed - Ignore (2 node)"

echo ""
do_test rsc_location1 "Score (not running)	"
do_test rsc_location2 "Score (running)		"
do_test rsc_location3 "Score (not running/no swap)"
do_test rsc_location4 "Score (running/swap)	"
do_test rsc_location5 "Score (running/swap 2)	"

echo ""
do_test complex1 "Complex	"

echo ""
do_test bad1 "Bad node	"
do_test bad2 "Bad rsc	"
do_test bad3 "No rsc class"
do_test bad4 "Bad data	"
do_test bad5 "Bad data	"
do_test bad6 "Bad lrm_rsc"
do_test bad7 "No lrm	"

echo ""
create_mode="true"
echo Generating test outputs for these tests...
#do_test bad7 "Bad data"

if [ -s $failed ]; then
    if [ "$verbose" = "-v" ]; then
	echo "Results of failed tests...."
	less $failed
    else
	echo "Results of failed tests are in $failed...."
	echo "Use $0 -v to display them automatically."
    fi
else
    rm $failed
fi


