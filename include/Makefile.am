#
# Copyright 2003-2019 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

MAINTAINERCLEANFILES    = Makefile.in config.h.in

noinst_HEADERS	        = config.h 			\
			  crm_internal.h		\
			  doxygen.h			\
			  pacemaker.h \
			  pacemaker-internal.h		\
			  portability.h                 \
			  gettext.h
pkginclude_HEADERS	= crm_config.h

SUBDIRS                 =  crm pcmki

# gettext.h is supplied by the gettext project

GETTEXT_H		?= $(datadir)/gettext/gettext.h

update-gettext:
	@if [ ! -e "$(GETTEXT_H)" ]; then				\
		echo "$(GETTEXT_H) not found";				\
	else								\
		cp "$(GETTEXT_H)" gettext.h;				\
		git diff --quiet gettext.h 2>/dev/null;			\
		if [ $$? -eq 0 ]; then					\
			echo "No update needed";			\
		else							\
			git add gettext.h;				\
			echo 'Review changes then run:';		\
			echo 'git commit -m "Low: NLS: update gettext.h from upstream"'; \
		fi							\
	fi
