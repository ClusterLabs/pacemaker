/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_HISTORY_INTERNAL__H
#define PCMK__CRM_COMMON_HISTORY_INTERNAL__H

#include <stdio.h>                  // NULL
#include <libxml/tree.h>            // xmlNode

#include <crm/common/internal.h>    // pcmk__str_empty()
#include <crm/common/xml_element_internal.h>    // pcmk__xe_id()
#include <crm/common/xml_names_internal.h>  // PCMK__XA_OPERATION_KEY

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \internal
 * \brief Get the operation key from an action history entry
 *
 * \param[in] xml  Action history entry
 *
 * \return Entry's operation key
 */
static inline const char *
pcmk__xe_history_key(const xmlNode *xml)
{
    if (xml == NULL) {
        return NULL;
    } else {
        /* @COMPAT Pacemaker <= 1.1.5 did not add the key, and used the ID
         * instead. Checking for that allows us to process old saved CIBs,
         * including some regression tests.
         */
        const char *key = pcmk__xe_get(xml, PCMK__XA_OPERATION_KEY);

        return pcmk__str_empty(key)? pcmk__xe_id(xml) : key;
    }
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_HISTORY_INTERNAL__H
