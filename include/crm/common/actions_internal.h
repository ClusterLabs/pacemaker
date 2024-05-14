/*
 * Copyright 2004-2024 the Pacemaker project contributors
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

// Action names as strings

// @COMPAT Deprecated since 2.0.0
#define PCMK__ACTION_POWEROFF               "poweroff"


//! printf-style format to create operation key from resource, action, interval
#define PCMK__OP_FMT "%s_%s_%u"

/*!
 * \internal
 * \brief Set action flags for an action
 *
 * \param[in,out] action        Action to set flags for
 * \param[in]     flags_to_set  Group of enum pe_action_flags to set
 */
#define pcmk__set_action_flags(action, flags_to_set) do {               \
        (action)->flags = pcmk__set_flags_as(__func__, __LINE__,        \
                                             LOG_TRACE,                 \
                                             "Action", (action)->uuid,  \
                                             (action)->flags,           \
                                             (flags_to_set),            \
                                             #flags_to_set);            \
    } while (0)

/*!
 * \internal
 * \brief Clear action flags for an action
 *
 * \param[in,out] action          Action to clear flags for
 * \param[in]     flags_to_clear  Group of enum pe_action_flags to clear
 */
#define pcmk__clear_action_flags(action, flags_to_clear) do {               \
        (action)->flags = pcmk__clear_flags_as(__func__, __LINE__,          \
                                               LOG_TRACE,                   \
                                               "Action", (action)->uuid,    \
                                               (action)->flags,             \
                                               (flags_to_clear),            \
                                               #flags_to_clear);            \
    } while (0)

/*!
 * \internal
 * \brief Set action flags for a flag group
 *
 * \param[in,out] action_flags  Flag group to set flags for
 * \param[in]     action_name   Name of action being modified (for logging)
 * \param[in]     to_set        Group of enum pe_action_flags to set
 */
#define pcmk__set_raw_action_flags(action_flags, action_name, to_set) do {  \
        action_flags = pcmk__set_flags_as(__func__, __LINE__,               \
                                          LOG_TRACE, "Action", action_name, \
                                          (action_flags),                   \
                                          (to_set), #to_set);               \
    } while (0)

/*!
 * \internal
 * \brief Clear action flags for a flag group
 *
 * \param[in,out] action_flags  Flag group to clear flags for
 * \param[in]     action_name   Name of action being modified (for logging)
 * \param[in]     to_clear      Group of enum pe_action_flags to clear
 */
#define pcmk__clear_raw_action_flags(action_flags, action_name, to_clear)   \
    do {                                                                    \
        action_flags = pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE,  \
                                            "Action", action_name,          \
                                            (action_flags),                 \
                                            (to_clear), #to_clear);         \
    } while (0)

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
