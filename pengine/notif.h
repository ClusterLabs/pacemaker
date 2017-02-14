/*
 * Copyright (C) 2004-2016 Andrew Beekhof <andrew@beekhof.net>
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
#ifndef PCMK_PENGINE_NOTIF__H
#  define PCMK_PENGINE_NOTIF__H

#  include <crm/pengine/internal.h>

notify_data_t * create_notification_boundaries(resource_t *rsc,
                                               const char *action,
                                               action_t *start, action_t *end,
                                               pe_working_set_t *data_set);

void collect_notification_data(resource_t *rsc, gboolean state,
                               gboolean activity, notify_data_t *n_data);

gboolean expand_notification_data(notify_data_t *n_data,
                                  pe_working_set_t *data_set);

void create_notifications(resource_t *rsc, notify_data_t *n_data,
                          pe_working_set_t *data_set);

void free_notification_data(notify_data_t *n_data);

void create_secondary_notification(pe_action_t *action, resource_t *rsc,
                                   pe_action_t *stonith_op,
                                   pe_working_set_t *data_set);

#endif  /* PCMK_PENGINE_NOTIF__H */
