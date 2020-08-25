/*
 * Copyright 2004-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/common/lists_internal.h>

GList*
pcmk__subtract_lists(GList *from, GList *items, GCompareFunc cmp)
{
    GList *item = NULL;
    GList *result = g_list_copy(from);

    for (item = items; item != NULL; item = item->next) {
        GList *candidate = NULL;

        for (candidate = from; candidate != NULL; candidate = candidate->next) {
            if(cmp(candidate->data, item->data) == 0) {
                result = g_list_remove(result, candidate->data);
                break;
            }
        }
    }

    return result;
}
