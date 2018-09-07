#
# Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

MAINTAINERCLEANFILES = Makefile.in

headerdir=$(pkgincludedir)/crm/common

header_HEADERS = xml.h ipc.h util.h iso8601.h mainloop.h logging.h
noinst_HEADERS = ipcs.h internal.h remote_internal.h xml_internal.h
if BUILD_CIBSECRETS
noinst_HEADERS += cib_secrets.h
endif
