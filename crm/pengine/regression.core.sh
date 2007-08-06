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
diff_opts="--ignore-all-space -u -N"
failed=.regression.failed.diff
# zero out the error log
> $failed

num_failed=0
function ptest() {
    if [ "x$VALGRIND_CMD" != "x" ]; then
	ptest_cmd=`which ptest`

    elif [ -x ptest ]; then
	ptest_cmd=./ptest

    else
	echo No ptest executable in current directory using installed version
	ptest_cmd=`which ptest`
    fi
    #echo $VALGRIND_CMD $ptest_cmd $*
    $VALGRIND_CMD $ptest_cmd $*
}

function do_test {

    base=$1; shift
    name=$1; shift
    input=$io_dir/${base}.xml
    output=$io_dir/${base}.pe.out
    expected=$io_dir/${base}.exp
    te_output=$io_dir/${base}.te.out
    te_expected=$io_dir/${base}.te.exp
    dot_output=$io_dir/${base}.pe.dot
    dot_expected=$io_dir/${base}.dot
    dot_png=$io_dir/${base}.png

    if [ ! -f $input ]; then
	echo "Test $name	($base)...	Error (PE : input)";
	num_failed=`expr $num_failed + 1`
	return;
    fi

    echo "Test $base	:	$name";
    if [ "$create_mode" != "true" -a ! -f $expected ]; then
	echo "	Error (PE : expected)";
#	return;
    fi

#    ../admin/crm_verify -X $input
    ptest -V -X $input -D $dot_output -G $output -S $*
    if [ $? != 0 ]; then
	echo "	* Failed (PE : rc)";
	num_failed=`expr $num_failed + 1`
    fi

    if [ -s core ]; then
	echo "	Moved core to core.${base}";
	num_failed=`expr $num_failed + 1`
	rm -f core.$base
	mv core core.$base
    fi

    if [ ! -s $output ]; then
	echo "	Error (PE : no graph)";
	num_failed=`expr $num_failed + 1`
	rm $output
	return;
    fi

    if [ ! -s $dot_output ]; then
	echo "	Error (PE : no dot-file)";
	num_failed=`expr $num_failed + 1`
	rm $output
	return;
    else
	echo "digraph \"g\" {" > $dot_output.sort
	LC_ALL=POSIX sort -u $dot_output | grep -v -e ^}$ -e digraph >> $dot_output.sort
	echo "}" >> $dot_output.sort
	mv -f $dot_output.sort $dot_output
    fi

    if [ "$create_mode" = "true" ]; then
	cp "$output" "$expected"
	cp "$dot_output" "$dot_expected"
	echo "	Created expected output (PE)" 
    fi

    diff $diff_opts $dot_expected $dot_output >/dev/null
    rc=$?
    if [ $rc != 0 ]; then
	echo "	* Failed (PE : dot)";
	diff $diff_opts $dot_expected $dot_output 2>/dev/null >> $failed
	echo "" >> $failed
	num_failed=`expr $num_failed + 1`
    else 
	rm $dot_output
    fi

    diff $diff_opts $expected $output >/dev/null
    rc2=$?
    if [ $rc2 != 0 ]; then
	echo "	* Failed (PE : raw)";
	diff $diff_opts $expected $output 2>/dev/null >> $failed
	echo "" >> $failed
	num_failed=`expr $num_failed + 1`
    else 
	rm $output
    fi
    
    if [ "$test_te" = "true" ]; then
	../tengine/ttest -X $output 2> $te_output
	
#    if [ "$create_mode" = "true" ]; then
	if [ "$create_mode" = "true" -a ! -f $te_expected ]; then
	    cp "$te_output" "$te_expected"
	fi
	
	if [ -f $te_expected ]; then
	    diff $diff_opts -q $te_expected $te_output >/dev/null
	    rc=$?
	fi
	
	if [ "$create_mode" = "true" ]; then
	    echo "Test $name	($base)...	Created expected output (PE)" 
	elif [ ! -f $te_expected ]; then
	    echo "==== Raw results for TE test ($base) ====" >> $failed
	    cat $te_output 2>/dev/null >> $failed
	elif [ "$rc" = 0 ]; then
	    :
	elif [ "$rc" = 1 ]; then
	    echo "Test $name	($base)...	* Failed (TE)";
	    diff $diff_opts $te_expected $te_output 2>/dev/null >> $failed
	    diff $diff_opts $te_expected $te_output
	else 
	    echo "Test $name	($base)...	Error TE (diff: $rc)";
	    echo "==== Raw results for test ($base) TE ====" >> $failed
	    cat $te_output 2>/dev/null >> $failed
	fi
    fi
    rm -f $output $te_output
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

