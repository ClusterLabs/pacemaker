#
# Copyright 2021-2022 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

AM_TESTS_ENVIRONMENT= \
	G_DEBUG=gc-friendly 			\
	MALLOC_CHECK_=2 			\
	MALLOC_PERTURB_=$$(($${RANDOM:-256} % 256))
LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/tests/tap-driver.sh
LOG_COMPILER = $(top_srcdir)/tests/tap-test
CLEANFILES = *.log *.trs

WRAPPED = calloc		\
	  endgrent		\
	  fopen 		\
	  getenv		\
	  getpid		\
	  getgrent		\
	  getpwnam_r		\
	  readlink		\
	  setgrent		\
	  strdup 		\
	  uname
LDFLAGS_WRAP = $(foreach fn,$(WRAPPED),-Wl,--wrap=$(fn))
