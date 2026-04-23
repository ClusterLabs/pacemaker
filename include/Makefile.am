#
# Copyright 2003-2026 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk

MAINTAINERCLEANFILES += config.h.in

noinst_HEADERS = config.h
noinst_HEADERS += crm_internal.h
noinst_HEADERS += doxygen.h
noinst_HEADERS += pacemaker-internal.h
noinst_HEADERS += portability.h
noinst_HEADERS += gettext.h

pkginclude_HEADERS = crm_config.h
pkginclude_HEADERS += pacemaker.h

SUBDIRS                 =  crm pcmki

# gettext.h is supplied by the gettext project

GETTEXT_H		?= $(datadir)/gettext/gettext.h

.PHONY: update-gettext
update-gettext:
	@if [ ! -e "$(GETTEXT_H)" ]; then				\
		echo "$(GETTEXT_H) not found";				\
	else								\
		cp "$(GETTEXT_H)" gettext.h;				\
		"$(GIT)" diff --quiet gettext.h 2>/dev/null;		\
		if [ $$? -eq 0 ]; then					\
			echo "No update needed";			\
		else							\
			"$(GIT)" add gettext.h;				\
			echo 'Review changes then run:';		\
			echo 'git commit -m "Low: NLS: update gettext.h from upstream"'; \
		fi							\
	fi
