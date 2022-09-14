/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/common/lists_internal.h>

GList*
pcmk__subtract_lists(GList *from, const GList *items, GCompareFunc cmp)
{
    GList *result = g_list_copy(from);

    for (const GList *item = items; item != NULL; item = item->next) {
        GList *match = g_list_find_custom(result, item->data, cmp);

        if (match != NULL) {
            result = g_list_remove(result, match->data);
        }
    }

    return result;
}
