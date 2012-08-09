#!/bin/bash

test_home=`dirname $0`
valgrind=""
verbose=""
tests=""

if [ "$test_home" = "." ]; then
    test_home="$PWD"
fi

function info() {
    printf "$*\n"
}

function error() {
    printf "      * ERROR:   $*\n"
}

info "Test home is:\t$test_home"

while true ; do
    case "$1" in
	all) tests="pengine lrmd fencing cli"; shift;;
	pengine|lrmd|fencing|cli) tests="$tests $1"; shift;;
	-V|--verbose) verbose="-V"; shift;;
	-v|--valgrind) valgrind="-v"; shift;;
	--) shift ; break ;;
	"") break;;
	*) echo "unknown option: $1"; exit 1;;
    esac
done

if [ -z "$tests" ]; then
    tests="pengine lrmd fencing cli"
fi

for t in $tests; do
    info "Executing the $t regression tests"
    info "============================================================"
    if [ -e $test_home/$t/regression.py ]; then
	# Fencing, lrmd
	chmod a+x $test_home/$t/regression.py
	sudo $test_home/$t/regression.py $verbose

    elif [ -e $test_home/$t ]; then
	# pengine, cli
	$test_home/$t/regression.sh $verbose $valgrind

    elif [ $t = cli -a -e $test_home/tools ]; then
	# Running cli tests from the source tree
	$test_home/tools/regression.sh $verbose $valgrind

    else
	error "Cannot find $t test in $test_home"
	exit 1
    fi
done

