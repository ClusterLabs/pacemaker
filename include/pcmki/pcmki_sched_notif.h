/*
 * Copyright 2004-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef CRM_PE_NOTIF__H
#  define CRM_PE_NOTIF__H

#  include <crm/pengine/internal.h>

notify_data_t * create_notification_boundaries(pe_resource_t *rsc,
                                               const char *action,
                                               pe_action_t *start, pe_action_t *end,
                                               pe_working_set_t *data_set);

void collect_notification_data(pe_resource_t *rsc, gboolean state,
                               gboolean activity, notify_data_t *n_data);

gboolean expand_notification_data(pe_resource_t *rsc, notify_data_t *n_data,
                                  pe_working_set_t *data_set);

void create_notifications(pe_resource_t *rsc, notify_data_t *n_data,
                          pe_working_set_t *data_set);

void free_notification_data(notify_data_t *n_data);

void create_secondary_notification(pe_action_t *action, pe_resource_t *rsc,
                                   pe_action_t *stonith_op,
                                   pe_working_set_t *data_set);

#endif /* CRM_PE_NOTIF__H */
