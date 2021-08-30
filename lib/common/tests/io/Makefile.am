#
# Copyright 2020-2021 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
LDADD = $(top_builddir)/lib/common/libcrmcommon.la -lcmocka

include $(top_srcdir)/mk/glib-tap.mk

# Add each test program here.  Each test should be written as a little standalone
# program using the glib unit testing functions.  See the documentation for more
# information.
#
# https://developer.gnome.org/glib/unstable/glib-Testing.html
#
# Add "_test" to the end of all test program names to simplify .gitignore.
test_programs =	\
	pcmk__full_path_test

# If any extra data needs to be added to the source distribution, add it to the
# following list.
dist_test_data =

# If any extra data needs to be used by tests but should not be added to the
# source distribution, add it to the following list.
test_data =
