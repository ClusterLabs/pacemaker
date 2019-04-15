#
# Copyright 2004-2019 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

MAINTAINERCLEANFILES = Makefile.in

headerdir=$(pkgincludedir)/crm/common

header_HEADERS = xml.h ipc.h util.h iso8601.h mainloop.h logging.h \
		 nvpair.h
noinst_HEADERS = ipcs.h internal.h remote_internal.h xml_internal.h \
		 ipc_internal.h
if BUILD_CIBSECRETS
noinst_HEADERS += cib_secrets.h
endif
