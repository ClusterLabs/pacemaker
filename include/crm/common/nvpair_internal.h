/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_NVPAIR_INTERNAL__H
#define PCMK__CRM_COMMON_NVPAIR_INTERNAL__H

#include <glib.h>                           // gboolean
#include <libxml/tree.h>                    // xmlNode

#include <crm/common/rules.h>               // pcmk_rule_input_t
#include <crm/common/iso8601.h>             // crm_time_t
#include <crm/common/strings_internal.h>    // pcmk__str_eq(), etc.

#ifdef __cplusplus
extern "C" {
#endif

// Data needed to sort XML blocks of name/value pairs
typedef struct unpack_data_s {
    GHashTable *values;             // Where to put name/value pairs
    const char *first_id;           // Block with this XML ID should sort first
    pcmk_rule_input_t rule_input;   // Data used to evaluate rules

    // Whether each block's values should overwrite any existing ones
    bool overwrite;

    // If not NULL, this will be set to when rule evaluations will change next
    crm_time_t *next_change;
} pcmk__nvpair_unpack_t;

/*!
 * \internal
 * \brief Insert a meta-attribute into a hash table
 *
 * \param[in] obj    Resource (pcmk__resource_private_t)
 *                   or action (pcmk_action_t) to add to
 * \param[in] name   Meta-attribute name
 * \param[in] value  Value to add
 */
#define pcmk__insert_meta(obj, name, value) do {                        \
        if (pcmk__str_eq((value), "#default", pcmk__str_casei)) {       \
            /* @COMPAT Deprecated since 2.1.8 */                        \
            pcmk__config_warn("Support for setting meta-attributes "    \
                              "(such as %s) to the explicit value "     \
                              "'#default' is deprecated and will be "   \
                              "removed in a future release", (name));   \
        } else if ((value) != NULL) {                                   \
            pcmk__insert_dup((obj)->meta, (name), (value));             \
        }                                                               \
    } while (0)

int pcmk__xe_get_datetime(const xmlNode *xml, const char *attr, crm_time_t **t);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_NVPAIR_INTERNAL__H
