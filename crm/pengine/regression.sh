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
diff_opts="--ignore-all-space  --minimal"
> regression.failed

function do_test {

    base=$1;
    name=$2;
    input=$io_dir/${base}.in
    output=$io_dir/${base}.out
    expected=$io_dir/${base}.exp

    if [ ! -f $input ]; then
	echo "Test $name ($base)...	Error (no input: $input)";
	return;
    fi

    if [ ! -f $expected ]; then
	echo "Test $name ($base)...	Error (expected output: $expected)";
	return;
    fi

    ./ptest < $input 2>/dev/null 2>/dev/null > $output

    if [ ! -f $output ]; then
	echo "Test $name ($base)...	Error (pe output)";
	return;
    fi

    ./fix_xml.pl $output

    if [ ! -f $output ]; then
	echo "Test $name ($base)...	Error (fixed output)";
	return;
    fi

    diff $diff_opts -q $expected $output
    rc=$?

    if [ "$rc" = 0 ]; then
	echo "Test $name ($base)...	Passed";
    elif [ "$rc" = 1 ]; then
	echo "Test $name ($base)...	Failed";
	diff $diff_opts -C 1 $expected $output >> regression.failed
    else
	echo "Test $name ($base)...	Error (diff rc=$rc)";
    fi
    
    rm $output
}

do_test t1 "Simple"
do_test cib1 "Simple"
