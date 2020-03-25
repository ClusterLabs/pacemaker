/*
 * Copyright 2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <glib.h>
#include <stdbool.h>

#include <crm/common/util.h>
#include <crm/pengine/internal.h>
#include <crm/pengine/pe_types.h>

gchar **
pe__unames_with_tag(pe_working_set_t *data_set, const char *tag_name)
{
    gpointer value;
    GPtrArray *arr = NULL;
    gchar **retval = NULL;

    if (data_set->tags == NULL) {
        return retval;
    }

    value = g_hash_table_lookup(data_set->tags, tag_name);

    if (value == NULL) {
        return retval;
    }

    /* Iterate over the list of node IDs. */
    for (GListPtr refs = ((pe_tag_t *) value)->refs; refs; refs = refs->next) {
        /* Find the node that has this ID. */
        const char *id = (const char *) refs->data;
        pe_node_t *node = pe_find_node_id(data_set->nodes, id);

        if (!node) {
            continue;
        }

        if (arr == NULL) {
            arr = g_ptr_array_new();
        }

        /* Get the uname for the node and add it to the return list. */
        g_ptr_array_add(arr, g_strdup((gchar *) node->details->uname));
    }

    if (arr == NULL) {
        return NULL;
    }

    /* Convert the GPtrArray into a gchar **. */
    retval = calloc(arr->len+1, sizeof(gchar *));
    for (int i = 0; i < arr->len; i++) {
        retval[i] = (gchar *) g_ptr_array_index(arr, i);
    }

    g_ptr_array_free(arr, FALSE);
    return retval;
}

bool
pe__uname_has_tag(pe_working_set_t *data_set, const char *node_name, const char *tag_name)
{
    gchar **unames = pe__unames_with_tag(data_set, tag_name);
    bool retval = false;

    if (unames == NULL) {
        return retval;
    }

    retval = g_strv_contains((const gchar * const *) unames, node_name);
    g_strfreev(unames);
    return retval;
}
