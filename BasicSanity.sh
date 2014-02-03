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
        all) tests="pengine cli lrmd fencing"; shift;;
        pengine|lrmd|pacemaker_remote|fencing|cli) tests="$tests $1"; shift;;
        -V|--verbose) verbose="-V"; shift;;
        -v|--valgrind) valgrind="-v"; shift;;
        --) shift ; break ;;
        "") break;;
        *) echo "unknown option: $1"; exit 1;;
    esac
done

if [ -z "$tests" ]; then
    tests="pengine cli lrmd"
fi

failed=""
for t in $tests; do
    info "Executing the $t regression tests"
    info "============================================================"
    if [ -e $test_home/$t/regression.py ]; then
        # Fencing, lrmd need root access
        chmod a+x $test_home/$t/regression.py
        echo "Enter the root password..."
	# sudo doesn't work in builtbot, su doesn't work in travis
	if [ x$TRAVIS = x ]; then
            su root -c "$test_home/$t/regression.py $verbose"
	else
            sudo -- $test_home/$t/regression.py $verbose
	fi
        rc=$?

    elif [ $t == "pacemaker_remote" ] && [ -e $test_home/lrmd/regression.py ]; then
        # pacemaker_remote
        chmod a+x $test_home/lrmd/regression.py
        echo "Enter the root password..."
	# sudo doesn't work in builtbot, su doesn't work in travis
	if [ x$TRAVIS = x ]; then
            su root -c "$test_home/$t/regression.py -R $verbose"
	else
            sudo -- $test_home/$t/regression.py -R $verbose
	fi
        rc=$?

    elif [ -e $test_home/$t ]; then
        # pengine, cli
        $test_home/$t/regression.sh $verbose $valgrind
        rc=$?

    elif [ $t = cli -a -e $test_home/tools ]; then
        # Running cli tests from the source tree
        $test_home/tools/regression.sh $verbose $valgrind
        rc=$?

    else
        error "Cannot find $t test in $test_home"
        rc=1
    fi

    if [ $rc != 0 ]; then
        info "$t regression tests failed: $rc"
        failed="$failed $t"
    fi

    info "============================================================"
    info ""
    info ""
done

if [ -z "$failed" ]; then
    exit 0
fi

error "regression tests for $failed failed"
exit 1
