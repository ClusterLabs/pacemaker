#
# Copyright 2012-2021 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU Lesser General Public License
# version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
#

MAINTAINERCLEANFILES = Makefile.in

AM_CPPFLAGS			= -I$(top_srcdir)/include

lib_LTLIBRARIES			= libcrmservice.la
noinst_HEADERS			= pcmk-dbus.h upstart.h systemd.h \
				  services_lsb.h services_nagios.h \
				  services_ocf.h \
				  services_private.h

libcrmservice_la_LDFLAGS	= -version-info 31:1:3
libcrmservice_la_CFLAGS		=

libcrmservice_la_CFLAGS		+= $(CFLAGS_HARDENED_LIB)
libcrmservice_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libcrmservice_la_LIBADD		= $(top_builddir)/lib/common/libcrmcommon.la $(DBUS_LIBS)

libcrmservice_la_SOURCES	= services.c
libcrmservice_la_SOURCES	+= services_linux.c
libcrmservice_la_SOURCES	+= services_lsb.c
libcrmservice_la_SOURCES	+= services_ocf.c
if BUILD_DBUS
libcrmservice_la_SOURCES	+= dbus.c
endif
if BUILD_UPSTART
libcrmservice_la_SOURCES	+= upstart.c
endif
if BUILD_SYSTEMD
libcrmservice_la_SOURCES	+= systemd.c
endif
if BUILD_NAGIOS
libcrmservice_la_SOURCES	+= services_nagios.c
endif
