# Copyright (c) 2012 David Vossel <davidvossel@gmail.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#
include $(top_srcdir)/Makefile.common

testdir			= $(datadir)/$(PACKAGE)/tests/lrmd
test_SCRIPTS		= regression.py

lrmdlibdir		= $(CRM_DAEMON_DIR)
lrmdlib_PROGRAMS	= lrmd lrmd_test lrmd_internal_ctl

initdir			= $(INITDIR)
init_SCRIPTS		= pacemaker_remote
sbin_PROGRAMS		= pacemaker_remoted

if BUILD_SYSTEMD
systemdunit_DATA	= pacemaker_remote.service
endif

lrmd_CFLAGS		= $(CFLAGS_HARDENED_EXE)
lrmd_LDFLAGS		= $(LDFLAGS_HARDENED_EXE)

lrmd_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la	\
			$(top_builddir)/lib/services/libcrmservice.la	\
			$(top_builddir)/lib/fencing/libstonithd.la ${COMPAT_LIBS}
lrmd_SOURCES		= main.c lrmd.c

pacemaker_remoted_CPPFLAGS	= -DSUPPORT_REMOTE $(AM_CPPFLAGS)

pacemaker_remoted_CFLAGS	= $(CFLAGS_HARDENED_EXE)
pacemaker_remoted_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)

pacemaker_remoted_LDADD		= $(lrmd_LDADD) \
			$(top_builddir)/lib/lrmd/liblrmd.la
pacemaker_remoted_SOURCES	= main.c lrmd.c tls_backend.c ipc_proxy.c

lrmd_internal_ctl_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la	\
				$(top_builddir)/lib/lrmd/liblrmd.la		\
				$(top_builddir)/lib/cib/libcib.la		\
				$(top_builddir)/lib/services/libcrmservice.la	\
				$(top_builddir)/lib/pengine/libpe_status.la	\
				$(top_builddir)/pengine/libpengine.la
lrmd_internal_ctl_SOURCES	= remote_ctl.c

lrmd_test_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la	\
			$(top_builddir)/lib/lrmd/liblrmd.la		\
			$(top_builddir)/lib/cib/libcib.la		\
			$(top_builddir)/lib/services/libcrmservice.la	\
			$(top_builddir)/lib/pengine/libpe_status.la	\
			$(top_builddir)/pengine/libpengine.la
lrmd_test_SOURCES	= test.c

noinst_HEADERS  = lrmd_private.h

CLEANFILES = $(man8_MANS)
