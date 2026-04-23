/*
 * Copyright 2020-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <lists_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_LISTS_INTERNAL__H
#define PCMK__CRM_COMMON_LISTS_INTERNAL__H

#include <stdbool.h>        // bool

#include <glib.h>           // GCompareFunc, GList

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \internal
 * \brief Return the list that is \p from - \p items
 *
 * \param[in] from  Source list
 * \param[in] items List containing items to remove from \p from
 * \param[in] cmp   Function used to compare list elements
 *
 * \return Newly allocated list
 */
GList *pcmk__subtract_lists(GList *from, const GList *items, GCompareFunc cmp);

// More efficient than g_list_length(list) == 1
static inline bool
pcmk__list_of_1(GList *list)
{
    return list && (list->next == NULL);
}

// More efficient than g_list_length(list) > 1
static inline bool
pcmk__list_of_multiple(GList *list)
{
    return list && (list->next != NULL);
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_LISTS_INTERNAL__H
