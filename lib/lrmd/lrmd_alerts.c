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

#if 0
lrmd_key_value_t * lrmd_set_alert_key_to_lrmd_params(lrmd_key_value_t *head, enum crm_alert_keys_e name, const char *value);
void lrmd_set_alert_envvar_to_lrmd_params(crm_alert_entry_t *entry, lrmd_key_value_t * params);
#endif

lrmd_key_value_t *
lrmd_set_alert_key_to_lrmd_params(lrmd_key_value_t *head, enum crm_alert_keys_e name, const char *value)
{
    const char **key;

    for (key = crm_alert_keys[name]; *key; key++) {
        crm_trace("Setting alert key %s = '%s'", *key, value);
        head = lrmd_key_value_add(head, *key, value);
    }
    return head;
}

void
lrmd_set_alert_envvar_to_lrmd_params(crm_alert_entry_t *entry, lrmd_key_value_t *head)
{
    GListPtr l;

    for (l = g_list_first(entry->envvars); l; l = g_list_next(l)) {
        crm_alert_envvar_t *ev = (crm_alert_envvar_t *)(l->data);

        crm_trace("Setting environment variable %s = '%s'", ev->name,
                  ev->value?ev->value:"");
        lrmd_key_value_add(head, ev->name, ev->value);
    }
    
}

