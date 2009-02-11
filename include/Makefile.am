#
# linux-ha: Linux-HA heartbeat code
#
# Copyright (C) 2001 Michael Moerz
#                    This instance created by Horms
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

MAINTAINERCLEANFILES    = Makefile.in ha_version.h config.h.in

EXTRA_DIST = ha_version.h crm_internal.h

headerdir=$(pkgincludedir)


noinst_HEADERS	        = portability.h config.h ha_version.h
header_HEADERS	        = crm_config.h
 

SUBDIRS                 =  crm fencing

## The backtick commands are not executed here,
## but rather as macro-expansions at use within the rules.
HG_LIVE_VERSION := `$(HG) -R "$(top_srcdir)" id -itb`
ARCHIVE_VERSION := "$(top_srcdir)/.hg_archival.txt"
HG_TAR_VERSION  := `cat "$(ARCHIVE_VERSION)" | awk '/node:/ { print $2 }'`

ha_version.h: $(ARCHIVE_VERSION)
	if [ -r ha_version.h -a ! -w ha_version.h ]; then	\
		hgv="";						\
		echo "Saved Version";	 			\
	elif [ -f $(ARCHIVE_VERSION) ]; then			\
		hgv="$(HG_TAR_VERSION)";			\
		echo "Hg Archived Version: $${hgv}";		\
	elif [ -x $(HG) -a -d $(top_srcdir)/.hg ]; then		\
		hgv="$(HG_LIVE_VERSION)";			\
		echo "Hg Live Version: $${hgv}";	 	\
	elif [ -r ha_version.h ]; then				\
		hgv="";						\
		echo "Hg Saved Live Version"; 			\
		cat ha_version.h; 				\
	else							\
		hgv="Unknown";					\
		echo "Unknown Hg Version";			\
	fi ;							\
	if [ X"$${hgv}" != "X" ]; then					\
	  echo "/* $${hgv} */" > ha_version.h; 				\
	  echo "#define HA_HG_VERSION \"$${hgv}\"" >> ha_version.h; 	\
	fi

.PHONY: $(ARCHIVE_VERSION)
