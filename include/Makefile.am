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

MAINTAINERCLEANFILES    = Makefile.in ha_version.h

EXTRA_DIST = ha_version.h

includedir=$(base_includedir)/heartbeat


noinst_HEADERS	        = hb_api_core.h ha_version.h
include_HEADERS	        = apphb.h apphb_notify.h HBauth.h HBcomm.h	\
			  ha_msg.h heartbeat.h hb_api.h			\
			  recoverymgr.h replace_uuid.h compress.h

SUBDIRS                 = clplumbing ocf pils saf 			\
			  stonith fencing lrm crm mgmt	

HG_LIVE_VERSION=`$(HG) -R "$(top_srcdir)" id`
ARCHIVE_VERSION="$(top_srcdir)/.hg_archival.txt"
HG_TAR_VERSION=`$(EGREP) node: "$(ARCHIVE_VERSION)"`

ha_version.h: $(ARCHIVE_VERSION)
	if [ -e ha_version.h -a ! -w ha_version.h ]; then				\
		echo "Saved Version";	 						\
	elif [ -f $(ARCHIVE_VERSION) ]; then						\
		echo "Hg Archived Version: $(HG_TAR_VERSION)";				\
		echo "/* $(HG_TAR_VERSION) */" > ha_version.h; 				\
		echo "#define HA_HG_VERSION \"$(HG_TAR_VERSION)\"" >> ha_version.h; 	\
	elif [ -x $(HG) -a -d $(top_srcdir)/.hg ]; then					\
		echo "Hg Live Version: $(HG_LIVE_VERSION)";			 	\
		echo "/* $(HG_LIVE_VERSION) */" > ha_version.h; 			\
		echo "#define HA_HG_VERSION \"$(HG_LIVE_VERSION)\"" >> ha_version.h; 	\
	elif [ -e ha_version.h ]; then							\
		echo "Hg Saved Live Version"; 						\
		cat ha_version.h; 							\
	else										\
		echo "Unknown Hg Version";			 			\
		echo "/* Unknown Version */" > ha_version.h;				\
		echo "#define HA_HG_VERSION \"Unknown\"" >> ha_version.h; 		\
	fi

.PHONY: $(ARCHIVE_VERSION)
