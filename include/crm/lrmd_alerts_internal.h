/*
 * Copyright (C) 2015 Andrew Beekhof <andrew@beekhof.net>
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

#ifndef LRMD_ALERT_INTERNAL_H
#define LRMD_ALERT_INTERNAL_H
lrmd_key_value_t * lrmd_set_alert_key_to_lrmd_params(lrmd_key_value_t *head, enum crm_alert_keys_e name, const char *value);
lrmd_key_value_t *lrmd_set_alert_envvar_to_lrmd_params(lrmd_key_value_t *head,
                                                       crm_alert_entry_t *entry);
#endif
