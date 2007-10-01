/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifndef CRM_COMMON_CLUSTER__H
#define CRM_COMMON_CLUSTER__H

#include <clplumbing/ipc.h>
#include <clplumbing/GSource.h>

#include <crm/common/xml.h>
#include <crm/common/msg.h>
#include <crm/ais.h>

extern gboolean send_ha_message(ll_cluster_t *hb_conn, HA_Message *msg,
				const char *node, gboolean force_ordered);

#ifdef WITH_NATIVE_AIS
#  include <crm/ais.h> 
#  define send_cluster_message(node, service, data, ordered) send_ais_message( \
	data, FALSE, node, service)
#else
extern ll_cluster_t *hb_conn;
#  define send_cluster_message(node, service, data, ordered) send_ha_message( \
	hb_conn, data, node, ordered)
#endif

#endif
