/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_ACTIONS_INTERNAL__H
#define PCMK__CRM_COMMON_ACTIONS_INTERNAL__H

#include <stdbool.h>                        // bool
#include <glib.h>                           // guint
#include <libxml/tree.h>                    // xmlNode

#include <crm/common/actions.h>             // PCMK_ACTION_MONITOR
#include <crm/common/strings_internal.h>    // pcmk__str_eq()

#ifdef __cplusplus
extern "C" {
#endif

//! printf-style format to create operation key from resource, action, interval
#define PCMK__OP_FMT "%s_%s_%u"

char *pcmk__op_key(const char *rsc_id, const char *op_type, guint interval_ms);
char *pcmk__notify_key(const char *rsc_id, const char *notify_type,
                       const char *op_type);
char *pcmk__transition_key(int transition_id, int action_id, int target_rc,
                           const char *node);
void pcmk__filter_op_for_digest(xmlNode *param_set);
bool pcmk__is_fencing_action(const char *action);

/*!
 * \internal
 * \brief Get a human-friendly action name
 *
 * \param[in] action_name  Actual action name
 * \param[in] interval_ms  Action interval (in milliseconds)
 *
 * \return Action name suitable for display
 */
static inline const char *
pcmk__readable_action(const char *action_name, guint interval_ms) {
    if ((interval_ms == 0)
        && pcmk__str_eq(action_name, PCMK_ACTION_MONITOR, pcmk__str_none)) {
        return "probe";
    }
    return action_name;
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_ACTIONS_INTERNAL__H
