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
io_dir=../pengine/testcases
diff_opts="--ignore-all-space -u -N"
failed=.regression.failed.diff
# zero out the error log
> $failed

num_failed=0
function do_test {

    base=$1; shift
    name=$1; shift
    input=$io_dir/${base}.xml
    output=$io_dir/${base}.upgrade.xml
    expected=$io_dir/${base}.expected.xml

    if [ ! -f $input ]; then
	echo "Test $name	($base)...	Error (PE : input)";
	num_failed=`expr $num_failed + 1`
	return;
    fi

    echo "Test $base	:	$name";
    if [ "$create_mode" != "true" -a ! -f $expected ]; then
	:
#	echo "	Error (PE : expected)";
#	return;
    fi

    xsltproc --novalid upgrade.xsl $input > $output
    if [ $? != 0 ]; then
	echo "	* Failed (xml : xsltproc)";
	num_failed=`expr $num_failed + 1`
    fi

     if [ ! -s $output ]; then
	echo "	Error (xml : no conversion)";
	num_failed=`expr $num_failed + 1`
	rm $output
	return;
    fi

    xmllint --relaxng pacemaker-1.0.rng $output > /dev/null

    if [ $? != 0 ]; then
	echo "	* Failed (xml : xmllint)";
	num_failed=`expr $num_failed + 1`
	cat -n $output
	exit
    fi

    rm -f $output
}

function test_results {
    if [ $num_failed != 0 ]; then
	if [ -s $failed ]; then
	    if [ "$verbose" = "-v" ]; then
		echo "Results of $num_failed failed tests...."
		less $failed
	    else
		echo "Results of $num_failed failed tests are in $failed...."
		echo "Use $0 -v to display them automatically."
	    fi
	else
	    echo "$num_failed tests failed (no diff results)"
	    rm $failed
	fi
    fi
}

