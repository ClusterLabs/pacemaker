#
# Copyright 2012-2018 David Vossel <davidvossel@gmail.com>
#
# This source code is licensed under the GNU Lesser General Public License
# version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/Makefile.common

halibdir		= $(CRM_DAEMON_DIR)
halib_PROGRAMS		= pacemaker-execd lrmd_test

initdir			= $(INITDIR)
init_SCRIPTS		= pacemaker_remote
sbin_PROGRAMS		= pacemaker_remoted

if BUILD_SYSTEMD
systemdunit_DATA	= pacemaker_remote.service
endif

pacemaker_execd_CFLAGS		= $(CFLAGS_HARDENED_EXE)
pacemaker_execd_LDFLAGS		= $(LDFLAGS_HARDENED_EXE)

pacemaker_execd_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la \
				  $(top_builddir)/lib/services/libcrmservice.la	\
				  $(top_builddir)/lib/fencing/libstonithd.la ${COMPAT_LIBS}
pacemaker_execd_SOURCES		= main.c lrmd.c lrmd_alert_api.c

pacemaker_remoted_CPPFLAGS	= -DSUPPORT_REMOTE $(AM_CPPFLAGS)

pacemaker_remoted_CFLAGS	= $(CFLAGS_HARDENED_EXE)
pacemaker_remoted_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)

pacemaker_remoted_LDADD		= $(pacemaker_execd_LDADD) \
				  $(top_builddir)/lib/lrmd/liblrmd.la
pacemaker_remoted_SOURCES	= $(pacemaker_execd_SOURCES) tls_backend.c ipc_proxy.c

lrmd_test_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la	\
			  $(top_builddir)/lib/lrmd/liblrmd.la		\
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/services/libcrmservice.la	\
			  $(top_builddir)/lib/pengine/libpe_status.la	\
			  $(top_builddir)/pengine/libpengine.la
lrmd_test_SOURCES	= cts-exec-helper.c

noinst_HEADERS  = lrmd_private.h

CLEANFILES = $(man8_MANS)
