#
# Copyright 2019 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# SPDX-License-Identifier: FSFAP
#

# it's expected maintainers are interested in a build at full speed, unless
# -j argument already passed in during invocation (e.g. "-j1" to suppress this)
ifeq ($(host_os),linux-gnu)
AM_MAKEFLAGS += $(if $(findstring j,$(MAKEFLAGS)),,-j $(shell \
                                                        grep -c ^processor \
                                                        /proc/cpuinfo || echo 1))
endif
