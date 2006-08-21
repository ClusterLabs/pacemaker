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
MAINTAINERCLEANFILES    = Makefile.in ha_config.h

EXTRA_DIST = ha_config.h.in

includedir=$(base_includedir)/heartbeat


noinst_HEADERS	        = hb_api_core.h
include_HEADERS	        = apphb.h apphb_notify.h HBauth.h HBcomm.h	\
			  ha_msg.h heartbeat.h hb_api.h ha_config.h	\
			  recoverymgr.h replace_uuid.h compress.h

SUBDIRS                 = clplumbing ocf pils saf 			\
			  stonith fencing lrm crm mgmt	
