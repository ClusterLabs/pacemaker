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

function run_as_root() {
    CMD="$1"
    shift
    ARGS="$@"

    # Test might not be executable if run from source directory
    chmod a+x $CMD

    CMD="$CMD $ARGS $verbose"

    if [ $EUID -eq 0 ]; then
        $CMD

    elif [ -z $TRAVIS ]; then
        # sudo doesn't work in buildbot, su doesn't work in travis
        echo "Enter the root password..."
        su root -c "$CMD"

    else
        echo "Enter the root password if prompted..."
        sudo -- $CMD
    fi
}

info "Test home is:\t$test_home"

while true ; do
    case "$1" in
        all) tests="$tests pengine cli lrmd fencing"; shift;;
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
        # fencing, lrmd need root access
        run_as_root $test_home/$t/regression.py
        rc=$?

    elif [ $t == "pacemaker_remote" ] && [ -e $test_home/lrmd/regression.py ]; then
        # pacemaker_remote
        run_as_root $test_home/lrmd/regression.py -R
        rc=$?

    elif [ -e $test_home/$t/regression.sh ]; then
        # pengine, cli
	$test_home/$t/regression.sh $verbose $valgrind
        rc=$?

    elif [ $t = cli -a -e $test_home/tools ]; then
        # cli when run from the source tree
	t=tools
	$test_home/$t/regression.sh $verbose $valgrind
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
