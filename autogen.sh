#!/bin/sh
#
#	License: GNU General Public License (GPL)
#	Copyright 2001 horms <horms@vergenet.net>
#		(heavily mangled by alanr)
#
#	bootstrap: set up the project and get it ready to make
#
#	Basically, we run autoconf, automake and libtool in the
#	right way to get things set up for this environment.
#
#	We also look and see if those tools are installed, and
#	tell you where to get them if they're not.
#
#	Our goal is to not require dragging along anything
#	more than we need.  If this doesn't work on your system,
#	(i.e., your /bin/sh is broken) send us a patch.
#
#	This code loosely based on the corresponding named script in
#	enlightenment, and also on the sort-of-standard autoconf
#	bootstrap script.

# Run this to generate all the initial makefiles, etc.

# Unset GREP_OPTIONS as any coloring can mess up the AC_CONFIG_AUX_DIR matching patterns
GREP_OPTIONS= autoreconf -visf  -Wno-portability

if [ -f config.log ]; then
    echo Now re-running ./configure with the previous arguments
    last=`grep --color=never "$.*configure" config.log | tail -n 1 | sed s:.*configure:./configure: | sed s:--no-create::`
    echo "  $last"
    eval $last
else
    echo Now run ./configure
    echo "Now run configure with any arguments (eg. --prefix) specific to your system"
    if [ -e `which rpm` ]; then
	echo "Suggested invocation:"
	rpm --eval %{configure} | grep -v program-prefix
    fi
fi

trap '' 0
