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

testProgram()
{
  cmd=$1

  if [ -z "$cmd" ]; then
    return 1;
  fi

  arch=`uname -s`

  # Make sure the which is in an if-block... on some platforms it throws exceptions
  #
  # The ERR trap is not executed if the failed command is part
  #   of an until or while loop, part of an if statement, part of a &&
  #   or  ||  list.
  if
     which $cmd  </dev/null >/dev/null 2>&1
  then
      :
  else
      return 1
  fi

  # The GNU standard is --version
  if 
      $cmd --version </dev/null >/dev/null 2>&1
  then
      return 0 
  fi

  # Maybe it suppports -V instead
  if 
      $cmd -V </dev/null >/dev/null 2>&1
  then
      return 0 
  fi

  # Nope, the program seems broken
  return 1
}

case "$*" in
  --help)	IsHelp=yes;;
  -?)		IsHelp=yes; set -- --help;;
  *)		IsHelp=no;;
esac

arch=`uname -s`
# Disable the errors on FreeBSD until a fix can be found.
if [ ! "$arch" = "FreeBSD" ]; then
set -e
#
#	All errors are fatal from here on out...
#	The shell will complain and exit on any "uncaught" error code.
#
#
#	And the trap will ensure sure some kind of error message comes out.
#
trap 'echo ""; echo "$0 exiting due to error (sorry!)." >&2' 0
fi

RC=0

gnu="ftp://ftp.gnu.org/pub/gnu"

# Check for Autoconf
pkg="autoconf"
URL=$gnu/$pkg/
for command in autoconf autoconf213 autoconf253 autoconf259 
do
  if
      testProgram $command == 1
  then
    : OK $pkg is installed
    autoconf=$command
    autoheader=`echo  "$autoconf" | sed -e 's/autoconf/autoheader/'`
    autom4te=`echo  "$autoconf" | sed -e 's/autoconf/autmo4te/'`
    autoreconf=`echo  "$autoconf" | sed -e 's/autoconf/autoreconf/'`
    autoscan=`echo  "$autoconf" | sed -e 's/autoconf/autoscan/'`
    autoupdate=`echo  "$autoconf" | sed -e 's/autoconf/autoupdate/'`
    ifnames=`echo  "$autoconf" | sed -e 's/autoconf/ifnames/'`
  fi
done


# Check to see if we got a valid command.
if 
    $autoconf --version </dev/null >/dev/null 2>&1
then
    echo "Autoconf package $autoconf found."
else
    RC=$?
    cat <<-!EOF >&2

	You must have $pkg installed to compile the linux-ha package.
	Download the appropriate package for your system,
	or get the source tarball at: $URL
	!EOF
fi

# Create local copy so that the incremental updates will work.
rm -f           ./autoconf
ln -s `which $autoconf` ./autoconf

# Check for automake
pkg="automake"
URL=$gnu/$pkg/
for command in automake automake14 automake-1.4 automake15 automake-1.5 automake17 automake-1.7 automake19 automake-1.9 
do
  if 
      testProgram $command
  then
    : OK $pkg is installed
    automake=$command
    aclocal=`echo  "$automake" | sed -e 's/automake/aclocal/'`

  fi
done

# Check to see if we got a valid command.
if 
    $automake --version </dev/null >/dev/null 2>&1
then
    echo "Automake package $automake found."
else
    RC=$?
    cat <<-!EOF >&2

	You must have $pkg installed to compile the linux-ha package.
	Download the appropriate package for your system,
	or get the source tarball at: $URL
	!EOF
fi

# Create local copy so that the incremental updates will work.
rm -f           ./automake
ln -s `which $automake` ./automake

# Check for Libtool
pkg="libtool"
for command in libtool libtool14 libtool15 glibtool
do
  URL=$gnu/$pkg/
  if
    testProgram $command
  then
    : OK $pkg is installed
    libtool=$command
    libtoolize=`echo  "$libtool" | sed -e 's/libtool/libtoolize/'`
  fi
done

# Check to see if we got a valid command.
if 
    $libtool --version </dev/null >/dev/null 2>&1
then
    echo "Libtool package $libtool found."
else
    RC=$?
    cat <<-!EOF >&2

	You must have $pkg installed to compile the linux-ha package.
	Download the appropriate package for your system,
	or get the source tarball at: $URL
	!EOF
fi

# Create local copy so that the incremental updates will work.
rm -f          ./libtool
ln -s `which $libtool` ./libtool

case $RC in
  0)	;;
  *)	exit $RC;;
esac

case $IsHelp in
  yes)	$CONFIG "$@"; trap '' 0; exit 0;;
esac

oneline() {
  read x; echo "$x"
}

LT_version=`$libtool --version | oneline | sed -e 's%^[^0-9]*%%' -e s'% .*%%'`
LT_majvers=`echo "$LT_version" | sed -e 's%\..*%%'`
LT_minvers=`echo "$LT_version" | sed -e 's%^[^.]*\.%%' `
LT_minnum=`echo  "$LT_minvers" | sed -e 's%[^0-9].*%%'`

if
  [ $LT_majvers -lt 1 ] || [ $LT_majvers = 1 -a $LT_minnum -lt 4 ]
then
  echo "Minimum version of libtool is 1.4.  You have $LT_version installed."
  exit 1
fi

echo $aclocal $ACLOCAL_FLAGS
$aclocal $ACLOCAL_FLAGS

# Create local copy so that the incremental updates will work.
rm -f ./autoheader
ln -s `which $autoheader` ./autoheader

if
  echo $autoheader --version  < /dev/null > /dev/null 2>&1
  $autoheader --version  < /dev/null > /dev/null 2>&1
then
  echo $autoheader
  $autoheader
fi

rm -rf libltdl libltdl.tar
echo $libtoolize --ltdl --force --copy
# Unset GREP_OPTIONS as any coloring can mess up the AC_CONFIG_AUX_DIR matching patterns
GREP_OPTIONS= $libtoolize --ltdl --force --copy

echo $aclocal $ACLOCAL_FLAGS
$aclocal $ACLOCAL_FLAGS

# Emulate the old --ltdl-tar option...
#  If the libltdl directory is required we will unpack it later
tar -cf libltdl.tar libltdl
rm -rf libltdl

echo $automake --add-missing --include-deps --copy
$automake --add-missing --include-deps --copy

echo $autoconf
$autoconf

test -f libtool.m4 || touch libtool.m4 
test -f ltdl.m4 || touch ltdl.m4

echo Now run ./configure
trap '' 0
