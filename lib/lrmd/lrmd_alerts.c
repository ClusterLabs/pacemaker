/*
 * Copyright (c) 2015 David Vossel <davidvossel@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <crm_internal.h>

#include <glib.h>
#include <unistd.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/services.h>
#include <crm/common/mainloop.h>
#include <crm/common/alerts_internal.h>
#include <crm/lrmd_alerts_internal.h>

#include <crm/pengine/status.h>
#include <crm/cib.h>
#include <crm/lrmd.h>

lrmd_key_value_t *
lrmd_set_alert_key_to_lrmd_params(lrmd_key_value_t *head, enum crm_alert_keys_e name, const char *value)
{
    const char **key;

    if (value == NULL) {
        value = "";
    }
    for (key = crm_alert_keys[name]; *key; key++) {
        crm_trace("Setting alert key %s = '%s'", *key, value);
        head = lrmd_key_value_add(head, *key, value);
    }
    return head;
}

static void
set_ev_kv(gpointer key, gpointer value, gpointer user_data)
{
    lrmd_key_value_t **head = (lrmd_key_value_t **) user_data;

    if (value) {
        crm_trace("Setting environment variable %s='%s'",
                  (char*)key, (char*)value);
        *head = lrmd_key_value_add(*head, key, value);
    }
}

lrmd_key_value_t *
lrmd_set_alert_envvar_to_lrmd_params(lrmd_key_value_t *head,
                                     crm_alert_entry_t *entry)
{
    if (entry->envvars) {
        g_hash_table_foreach(entry->envvars, set_ev_kv, &head);
    }
    return head;
}
