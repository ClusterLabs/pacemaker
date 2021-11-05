#
# Copyright 2014-2021 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

#
# Some variables to help with silent rules
# https://www.gnu.org/software/automake/manual/html_node/Automake-silent_002drules-Option.html

V ?= $(AM_DEFAULT_VERBOSITY)

# When a make command is prefixed with one of the AM_V_* macros, it may also be
# desirable to suffix the command with this, to silence stdout.
PCMK_quiet = $(pcmk_quiet_$(V))
pcmk_quiet_0 = >/dev/null
pcmk_quiet_1 = 

# AM_V_GEN is intended to be used in custom pattern rules, and replaces echoing
# the command used with a more concise line with "GEN" and the name of the file
# being generated. Our AM_V_* macros are similar but more descriptive.
AM_V_MAN = $(am__v_MAN_$(V))
am__v_MAN_0 = @echo "  MAN      $@";
am__v_MAN_1 = 

AM_V_SCHEMA = $(am__v_SCHEMA_$(V))
am__v_SCHEMA_0 = @echo "  SCHEMA   $@";
am__v_SCHEMA_1 = 

AM_V_BOOK = $(am__v_BOOK_$(V))
am__v_BOOK_0 = @echo "  BOOK    $(@:%/_build=%): $(BOOK_FORMATS)";
am__v_BOOK_1 = 

MAINTAINERCLEANFILES	= Makefile.in

AM_CPPFLAGS		= -I$(top_builddir)/include -I$(top_srcdir)/include   \
			  -I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl
