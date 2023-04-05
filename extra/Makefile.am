#
# Copyright 2004-2023 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

MAINTAINERCLEANFILES    = Makefile.in

SUBDIRS		= resources

mibdir		= $(datadir)/snmp/mibs
dist_mib_DATA	= PCMK-MIB.txt

# "make check" will cause "make all" to be run, which means everything in this
# directory will get built as a part of running tests if it hasn't happened
# already.  That seems unnecessary, so override the default check-recursive
# rule with this one that just returns.  If we ever need to add tests to this
# directory, this rule will have to come out.
check-recursive:
	@true
