#
# Copyright 2012-2024 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU Lesser General Public License
# version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/mk/common.mk

lib_LTLIBRARIES			= libcrmservice.la
noinst_HEADERS			= $(wildcard *.h)

libcrmservice_la_LDFLAGS	= -version-info 32:2:4
libcrmservice_la_CFLAGS		=

libcrmservice_la_CFLAGS		+= $(CFLAGS_HARDENED_LIB)
libcrmservice_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libcrmservice_la_LIBADD		= $(top_builddir)/lib/common/libcrmcommon.la \
				  $(DBUS_LIBS)

## Library sources (*must* use += format for bumplibs)
libcrmservice_la_SOURCES	= services.c
libcrmservice_la_SOURCES	+= services_linux.c
libcrmservice_la_SOURCES	+= services_ocf.c
if BUILD_LSB
libcrmservice_la_SOURCES	+= services_lsb.c
endif
if BUILD_SYSTEMD
libcrmservice_la_SOURCES	+= dbus.c
libcrmservice_la_SOURCES	+= systemd.c
endif
