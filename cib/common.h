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

extern HA_Message *cib_msg_copy(HA_Message *msg, gboolean with_data);
extern HA_Message *cib_construct_reply(HA_Message *request, HA_Message *output, int rc);
extern enum cib_errors revision_check(crm_data_t *cib_update, crm_data_t *cib_copy, int flags);
extern enum cib_errors cib_get_operation_id(const char *op, int *operation);

extern enum cib_errors cib_perform_op(
    const char *op, int call_options, const char *section, crm_data_t *input,
    gboolean manage_counters, gboolean *config_changed,
    crm_data_t *current_cib, crm_data_t **result_cib, crm_data_t **output);

extern enum cib_errors cib_update_counter(
    crm_data_t *xml_obj, const char *field, gboolean reset);
