#
# Copyright 2021-2026 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

AM_TESTS_ENVIRONMENT = G_DEBUG=gc-friendly
AM_TESTS_ENVIRONMENT += MALLOC_CHECK_=2
AM_TESTS_ENVIRONMENT += MALLOC_PERTURB_=$$(($${RANDOM:-256} % 256))
AM_TESTS_ENVIRONMENT += PCMK_CTS_CLI_DIR=$(top_srcdir)/cts/cli
AM_TESTS_ENVIRONMENT += PCMK_schema_directory=$(top_builddir)/xml

LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/tests/tap-driver.sh
LOG_COMPILER = $(top_srcdir)/tests/tap-test
CLEANFILES = *.log *.trs

WRAPPED = abort 		\
	  calloc		\
	  fopen 		\
	  getenv		\
	  getpid		\
	  getgrnam		\
	  getpwnam		\
	  readlink		\
	  realloc 		\
	  setenv		\
	  strdup 		\
	  unsetenv

if WRAPPABLE_FOPEN64
WRAPPED	+= fopen64
endif

LDFLAGS_WRAP = $(foreach fn,$(WRAPPED),-Wl,--wrap=$(fn))
