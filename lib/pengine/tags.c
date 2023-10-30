/*
 * Copyright 2020-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>
#include <stdbool.h>

#include <crm/common/util.h>
#include <crm/common/scheduler.h>
#include <crm/pengine/internal.h>

GList *
pe__rscs_with_tag(pcmk_scheduler_t *scheduler, const char *tag_name)
{
    gpointer value;
    GList *retval = NULL;

    if (scheduler->tags == NULL) {
        return retval;
    }

    value = g_hash_table_lookup(scheduler->tags, tag_name);

    if (value == NULL) {
        return retval;
    }

    for (GList *refs = ((pcmk_tag_t *) value)->refs; refs; refs = refs->next) {
        const char *id = (const char *) refs->data;
        const uint32_t flags = pcmk_rsc_match_history|pcmk_rsc_match_basename;
        pcmk_resource_t *rsc = pe_find_resource_with_flags(scheduler->resources,
                                                           id, flags);

        if (!rsc) {
            continue;
        }

        retval = g_list_append(retval, strdup(rsc_printable_id(rsc)));
    }

    return retval;
}

GList *
pe__unames_with_tag(pcmk_scheduler_t *scheduler, const char *tag_name)
{
    gpointer value;
    GList *retval = NULL;

    if (scheduler->tags == NULL) {
        return retval;
    }

    value = g_hash_table_lookup(scheduler->tags, tag_name);

    if (value == NULL) {
        return retval;
    }

    /* Iterate over the list of node IDs. */
    for (GList *refs = ((pcmk_tag_t *) value)->refs; refs; refs = refs->next) {
        /* Find the node that has this ID. */
        const char *id = (const char *) refs->data;
        pcmk_node_t *node = pe_find_node_id(scheduler->nodes, id);

        if (!node) {
            continue;
        }

        /* Get the uname for the node and add it to the return list. */
        retval = g_list_append(retval, strdup(node->details->uname));
    }

    return retval;
}

bool
pe__rsc_has_tag(pcmk_scheduler_t *scheduler, const char *rsc_name,
                const char *tag_name)
{
    GList *rscs = pe__rscs_with_tag(scheduler, tag_name);
    bool retval = false;

    if (rscs == NULL) {
        return retval;
    }

    retval = g_list_find_custom(rscs, rsc_name, (GCompareFunc) strcmp) != NULL;
    g_list_free_full(rscs, free);
    return retval;
}

bool
pe__uname_has_tag(pcmk_scheduler_t *scheduler, const char *node_name,
                  const char *tag_name)
{
    GList *unames = pe__unames_with_tag(scheduler, tag_name);
    bool retval = false;

    if (unames == NULL) {
        return retval;
    }

    retval = g_list_find_custom(unames, node_name, (GCompareFunc) strcmp) != NULL;
    g_list_free_full(unames, free);
    return retval;
}
