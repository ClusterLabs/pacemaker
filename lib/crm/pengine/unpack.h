/* $Id: unpack.h,v 1.1 2006/06/09 06:24:57 andrew Exp $ */
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
#ifndef PENGINE_UNPACK__H
#define PENGINE_UNPACK__H

extern gboolean unpack_resources(
	crm_data_t *xml_resources, pe_working_set_t *data_set);

extern gboolean unpack_config(crm_data_t *config, pe_working_set_t *data_set);

extern gboolean unpack_nodes(crm_data_t *xml_nodes, pe_working_set_t *data_set);

extern gboolean unpack_status(crm_data_t *status, pe_working_set_t *data_set);

extern gint sort_op_by_callid(gconstpointer a, gconstpointer b);

extern gboolean unpack_lrm_resources(
	node_t *node, crm_data_t * lrm_state, pe_working_set_t *data_set);

extern gboolean add_node_attrs(
	crm_data_t * attrs, node_t *node, pe_working_set_t *data_set);

extern gboolean unpack_rsc_op(
	resource_t *rsc, node_t *node, crm_data_t *xml_op,
	int *max_call_id, enum action_fail_response *failed, pe_working_set_t *data_set);

extern gboolean determine_online_status(
	crm_data_t * node_state, node_t *this_node, pe_working_set_t *data_set);

extern const char *param_value(
	GHashTable *hash, crm_data_t * parent, const char *name);

#endif
