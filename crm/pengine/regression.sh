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

io_dir=testcases
diff_opts="--ignore-all-space -1 -u"

# zero out the error log
> regression.failed

function do_test {

    base=$1;
    name=$2;
    input=$io_dir/${base}.xml
    output=$io_dir/${base}.out
    expected=$io_dir/${base}.exp

    if [ ! -f $input ]; then
	echo "Test $name	($base)...	Error (no input: $input)";
	return;
    fi

    if [ "$create_mode" != "true" -a ! -f $expected ]; then
	echo "Test $name	($base)...	Error (expected output: $expected)";
	return;
    fi

    ./ptest < $input 2>/dev/null 2>/dev/null > $output

    if [ ! -s $output ]; then
	echo "Test $name	($base)...	Error (pe output)";
	rm $output
	return;
    fi

    ./fix_xml.pl $output

    if [ ! -s $output ]; then
	echo "Test $name	($base)...	Error (fixed output)";
	rm $output
	return;
    fi

    if [ "$create_mode" = "true" ]; then
	cp "$output" "$expected"
    fi

    diff $diff_opts -q $expected $output >/dev/null
    rc=$?

    if [ "$rc" = 0 ]; then
	echo "Test $name	($base)...	Passed";
    elif [ "$rc" = 1 ]; then
	echo "Test $name	($base)...	* Failed";
	diff $diff_opts $expected $output 2>/dev/null >> regression.failed
    else
	echo "Test $name	($base)...	Error (diff: $rc)";
    fi
    
    rm $output
}

create_mode="false"
do_test simple1 "Offline	"
do_test simple2 "Start	"
do_test simple3 "Start 2	"
do_test simple4 "Start Failed"
do_test simple5 "Stop Failed"
do_test simple6 "Stop Start	"
do_test simple7 "Shutdown	"
do_test simple8 "Stonith	"


#create_mode="true"


if [ -s regression.failed ]; then
    echo "Results of failed tests...."
    cat regression.failed
else
    rm regression.failed
fi


