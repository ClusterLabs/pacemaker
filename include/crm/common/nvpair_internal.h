/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <nvpair_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_NVPAIR_INTERNAL__H
#define PCMK__CRM_COMMON_NVPAIR_INTERNAL__H

#include <stdbool.h>                        // bool
#include <glib.h>                           // gboolean, gpointer, GHashTable
#include <libxml/tree.h>                    // xmlNode

#include <crm/common/rules.h>               // pcmk_rule_input_t
#include <crm/common/iso8601.h>             // crm_time_t
#include <crm/common/strings_internal.h>    // pcmk__str_eq(), etc.

#ifdef __cplusplus
extern "C" {
#endif

// Data needed to sort XML blocks of name/value pairs
typedef struct {
    GHashTable *values;             // Where to put name/value pairs
    const char *first_id;           // Block with this XML ID should sort first
    pcmk_rule_input_t rule_input;   // Data used to evaluate rules

    /* Whether each block's values should overwrite any existing ones
     *
     * @COMPAT Only external call paths set this to true. Drop it when we drop
     * pe_eval_nvpairs() and pe_unpack_nvpairs().
     */
    bool overwrite;

    // If not NULL, this will be set to when rule evaluations will change next
    crm_time_t *next_change;
} pcmk__nvpair_unpack_t;

gint pcmk__cmp_nvpair_blocks(gconstpointer a, gconstpointer b,
                             gpointer user_data);

void pcmk__unpack_nvpair_block(gpointer data, gpointer user_data);

int pcmk__scan_nvpair(const gchar *input, gchar **name, gchar **value);
char *pcmk__format_nvpair(const char *name, const char *value,
                          const char *units);

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

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_NVPAIR_INTERNAL__H
