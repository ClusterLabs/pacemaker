/*
 * Copyright (C) 2015 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/alerts_internal.h>


char *notify_script = NULL;
char *notify_target = NULL;
GListPtr notify_list = NULL;
guint max_alert_timeout = CRMD_NOTIFY_DEFAULT_TIMEOUT_MS;

/*		
 * to allow script compatibility we can have more than one		
 * set of environment variables		
 */
const char *notify_keys[14][3] =		
{		
    [CRM_notify_recipient]     = {"CRM_notify_recipient",     "CRM_alert_recipient",     NULL},		
    [CRM_notify_node]          = {"CRM_notify_node",          "CRM_alert_node",          NULL},		
    [CRM_notify_nodeid]        = {"CRM_notify_nodeid",        "CRM_alert_nodeid",        NULL},		
    [CRM_notify_rsc]           = {"CRM_notify_rsc",           "CRM_alert_rsc",           NULL},		
    [CRM_notify_task]          = {"CRM_notify_task",          "CRM_alert_task",          NULL},		
    [CRM_notify_interval]      = {"CRM_notify_interval",      "CRM_alert_interval",      NULL},		
    [CRM_notify_desc]          = {"CRM_notify_desc",          "CRM_alert_desc",          NULL},		
    [CRM_notify_status]        = {"CRM_notify_status",        "CRM_alert_status",        NULL},		
    [CRM_notify_target_rc]     = {"CRM_notify_target_rc",     "CRM_alert_target_rc",     NULL},		
    [CRM_notify_rc]            = {"CRM_notify_rc",            "CRM_alert_rc",            NULL},		
    [CRM_notify_kind]          = {"CRM_notify_kind",          "CRM_alert_kind",          NULL},		
    [CRM_notify_version]       = {"CRM_notify_version",       "CRM_alert_version",       NULL},		
    [CRM_notify_node_sequence] = {"CRM_notify_node_sequence", "CRM_alert_node_sequence", NULL},		
    [CRM_notify_timestamp]     = {"CRM_notify_timestamp",     "CRM_alert_timestamp",     NULL}		
};

static void		
free_envvar_entry(envvar_t *entry)		
{		
    free(entry->name);		
    free(entry->value);		
    free(entry);		
}		

static void		
free_notify_list_entry(notify_entry_t *entry)		
{		
    free(entry->id);		
    free(entry->path);		
    free(entry->tstamp_format);		
    free(entry->recipient);		
    if (entry->envvars) {		
        g_list_free_full(entry->envvars,		
                         (GDestroyNotify) free_envvar_entry);		
    }		
    free(entry);		
}		

void		
free_notify_list()		
{		
    if (notify_list) {		
        g_list_free_full(notify_list, (GDestroyNotify) free_notify_list_entry);		
        notify_list = NULL;		
    }		
}		

static gpointer		
copy_envvar_entry(envvar_t * src,		
                  gpointer data)		
{		
    envvar_t *dst = calloc(1, sizeof(envvar_t));		

    CRM_ASSERT(dst);		
    dst->name = strdup(src->name);		
    dst->value = src->value?strdup(src->value):NULL;		
    return (gpointer) dst;		
}		

GListPtr		
add_dup_envvar(GListPtr envvar_list,		
               envvar_t *entry)		
{		
    return g_list_prepend(envvar_list, copy_envvar_entry(entry, NULL));		
}		

GListPtr		
drop_envvars(GListPtr envvar_list, int count)		
{		
    int i;		
		
    for (i = 0;		
         (envvar_list) && ((count < 0) || (i < count));		
         i++) {		
        free_envvar_entry((envvar_t *) g_list_first(envvar_list)->data);		
        envvar_list = g_list_delete_link(envvar_list,		
                                         g_list_first(envvar_list));		
    }		
    return envvar_list;		
}		

static GListPtr		
copy_envvar_list_remove_dupes(GListPtr src)		
{		
    GListPtr dst = NULL, ls, ld;		

    /* we are adding to the front so variable dupes coming via		
     * recipient-section have got precedence over those in the		
     * global section - we don't expect that many variables here		
     * that it pays off to go for a hash-table to make dupe elimination		
     * more efficient - maybe later when we might decide to do more		
     * with the variables than cycling through them		
     */		

    for (ls = g_list_first(src); ls; ls = g_list_next(ls)) {		
        for (ld = g_list_first(dst); ld; ld = g_list_next(ld)) {		
            if (!strcmp(((envvar_t *)(ls->data))->name,		
                        ((envvar_t *)(ld->data))->name)) {		
                break;		
            }		
        }		
        if (!ld) {		
            dst = g_list_prepend(dst,		
                    copy_envvar_entry((envvar_t *)(ls->data), NULL));		
        }		
    }		

    return dst;		
}		

void		
add_dup_notify_list_entry(notify_entry_t *entry)		
{		
    notify_entry_t *new_entry =		
        (notify_entry_t *) calloc(1, sizeof(notify_entry_t));		

    CRM_ASSERT(new_entry);		
    *new_entry = (notify_entry_t) {		
        .id = strdup(entry->id),		
        .path = strdup(entry->path),		
        .timeout = entry->timeout,		
        .tstamp_format = entry->tstamp_format?strdup(entry->tstamp_format):NULL,		
        .recipient = entry->recipient?strdup(entry->recipient):NULL,		
        .envvars = entry->envvars?		
            copy_envvar_list_remove_dupes(entry->envvars)		
            :NULL		
    };		
    notify_list = g_list_prepend(notify_list, new_entry);		
}		

GListPtr		
get_envvars_from_cib(xmlNode *basenode, GListPtr list, int *count)		
{		
    xmlNode *envvar;		
    xmlNode *pair;		

    if ((!basenode) ||		
        (!(envvar = first_named_child(basenode, XML_TAG_ATTR_SETS)))) {		
        return list;		
    }		

    for (pair = first_named_child(envvar, XML_CIB_TAG_NVPAIR);		
         pair; pair = __xml_next(pair)) {		

        envvar_t envvar_entry = (envvar_t) {		
            .name = (char *) crm_element_value(pair, XML_NVPAIR_ATTR_NAME),		
            .value = (char *) crm_element_value(pair, XML_NVPAIR_ATTR_VALUE)		
        };		
        crm_trace("Found environment variable %s = '%s'", envvar_entry.name,		
                  envvar_entry.value?envvar_entry.value:"");		
        (*count)++;		
        list = add_dup_envvar(list, &envvar_entry);		
    }		

    return list;		
}
