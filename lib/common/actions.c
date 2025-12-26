/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ctype.h>

#include <crm/crm.h>
#include <crm/lrmd.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/common/scheduler.h>

/*!
 * \internal
 * \brief Get string equivalent of an action type
 *
 * \param[in] action  Action type
 *
 * \return Static string describing \p action
 */
const char *
pcmk__action_text(enum pcmk__action_type action)
{
    switch (action) {
        case pcmk__action_stop:
            return PCMK_ACTION_STOP;

        case pcmk__action_stopped:
            return PCMK_ACTION_STOPPED;

        case pcmk__action_start:
            return PCMK_ACTION_START;

        case pcmk__action_started:
            return PCMK_ACTION_RUNNING;

        case pcmk__action_shutdown:
            return PCMK_ACTION_DO_SHUTDOWN;

        case pcmk__action_fence:
            return PCMK_ACTION_STONITH;

        case pcmk__action_monitor:
            return PCMK_ACTION_MONITOR;

        case pcmk__action_notify:
            return PCMK_ACTION_NOTIFY;

        case pcmk__action_notified:
            return PCMK_ACTION_NOTIFIED;

        case pcmk__action_promote:
            return PCMK_ACTION_PROMOTE;

        case pcmk__action_promoted:
            return PCMK_ACTION_PROMOTED;

        case pcmk__action_demote:
            return PCMK_ACTION_DEMOTE;

        case pcmk__action_demoted:
            return PCMK_ACTION_DEMOTED;

        default: // pcmk__action_unspecified or invalid
            return "no_action";
    }
}

/*!
 * \internal
 * \brief Parse an action type from an action name
 *
 * \param[in] action_name  Action name
 *
 * \return Action type corresponding to \p action_name
 */
enum pcmk__action_type
pcmk__parse_action(const char *action_name)
{
    if (pcmk__str_eq(action_name, PCMK_ACTION_STOP, pcmk__str_none)) {
        return pcmk__action_stop;

    } else if (pcmk__str_eq(action_name, PCMK_ACTION_STOPPED, pcmk__str_none)) {
        return pcmk__action_stopped;

    } else if (pcmk__str_eq(action_name, PCMK_ACTION_START, pcmk__str_none)) {
        return pcmk__action_start;

    } else if (pcmk__str_eq(action_name, PCMK_ACTION_RUNNING, pcmk__str_none)) {
        return pcmk__action_started;

    } else if (pcmk__str_eq(action_name, PCMK_ACTION_DO_SHUTDOWN,
                            pcmk__str_none)) {
        return pcmk__action_shutdown;

    } else if (pcmk__str_eq(action_name, PCMK_ACTION_STONITH, pcmk__str_none)) {
        return pcmk__action_fence;

    } else if (pcmk__str_eq(action_name, PCMK_ACTION_MONITOR, pcmk__str_none)) {
        return pcmk__action_monitor;

    } else if (pcmk__str_eq(action_name, PCMK_ACTION_NOTIFY, pcmk__str_none)) {
        return pcmk__action_notify;

    } else if (pcmk__str_eq(action_name, PCMK_ACTION_NOTIFIED,
                            pcmk__str_none)) {
        return pcmk__action_notified;

    } else if (pcmk__str_eq(action_name, PCMK_ACTION_PROMOTE, pcmk__str_none)) {
        return pcmk__action_promote;

    } else if (pcmk__str_eq(action_name, PCMK_ACTION_DEMOTE, pcmk__str_none)) {
        return pcmk__action_demote;

    } else if (pcmk__str_eq(action_name, PCMK_ACTION_PROMOTED,
                            pcmk__str_none)) {
        return pcmk__action_promoted;

    } else if (pcmk__str_eq(action_name, PCMK_ACTION_DEMOTED, pcmk__str_none)) {
        return pcmk__action_demoted;
    }
    return pcmk__action_unspecified;
}

/*!
 * \internal
 * \brief Get string equivalent of a failure handling type
 *
 * \param[in] on_fail  Failure handling type
 *
 * \return Static string describing \p on_fail
 */
const char *
pcmk__on_fail_text(enum pcmk__on_fail on_fail)
{
    switch (on_fail) {
        case pcmk__on_fail_ignore:
            return "ignore";

        case pcmk__on_fail_demote:
            return "demote";

        case pcmk__on_fail_block:
            return "block";

        case pcmk__on_fail_restart:
            return "recover";

        case pcmk__on_fail_ban:
            return "migrate";

        case pcmk__on_fail_stop:
            return "stop";

        case pcmk__on_fail_fence_node:
            return "fence";

        case pcmk__on_fail_standby_node:
            return "standby";

        case pcmk__on_fail_restart_container:
            return "restart-container";

        case pcmk__on_fail_reset_remote:
            return "reset-remote";
    }
    return "<unknown>";
}

/*!
 * \internal
 * \brief Free an action object
 *
 * \param[in,out] user_data  Action object to free
 */
void
pcmk__free_action(gpointer user_data)
{
    pcmk_action_t *action = user_data;

    if (action == NULL) {
        return;
    }
    g_list_free_full(action->actions_before, free);
    g_list_free_full(action->actions_after, free);
    if (action->extra != NULL) {
        g_hash_table_destroy(action->extra);
    }
    if (action->meta != NULL) {
        g_hash_table_destroy(action->meta);
    }
    pcmk__free_node_copy(action->node);
    free(action->cancel_task);
    free(action->reason);
    free(action->task);
    free(action->uuid);
    free(action);
}

/*!
 * \brief Generate an operation key (RESOURCE_ACTION_INTERVAL)
 *
 * \param[in] rsc_id       ID of resource being operated on
 * \param[in] op_type      Operation name
 * \param[in] interval_ms  Operation interval
 *
 * \return Newly allocated memory containing operation key as string
 *
 * \note This function asserts on errors, so it will never return NULL.
 *       The caller is responsible for freeing the result with free().
 */
char *
pcmk__op_key(const char *rsc_id, const char *op_type, guint interval_ms)
{
    pcmk__assert((rsc_id != NULL) && (op_type != NULL));
    return pcmk__assert_asprintf(PCMK__OP_FMT, rsc_id, op_type, interval_ms);
}

static inline gboolean
convert_interval(const char *s, guint *interval_ms)
{
    unsigned long l;

    errno = 0;
    l = strtoul(s, NULL, 10);

    if (errno != 0) {
        return FALSE;
    }

    *interval_ms = (guint) l;
    return TRUE;
}

/*!
 * \internal
 * \brief Check for underbar-separated substring match
 *
 * \param[in] key       Overall string being checked
 * \param[in] position  Match before underbar at this \p key index
 * \param[in] matches   Substrings to match (may contain underbars)
 *
 * \return \p key index of underbar before any matching substring,
 *         or 0 if none
 */
static size_t
match_before(const char *key, size_t position, const char **matches)
{
    for (int i = 0; matches[i] != NULL; ++i) {
        const size_t match_len = strlen(matches[i]);

        // Must have at least X_MATCH before position
        if (position > (match_len + 1)) {
            const size_t possible = position - match_len - 1;

            if ((key[possible] == '_')
                && g_str_has_prefix(key + possible + 1, matches[i])) {

                return possible;
            }
        }
    }
    return 0;
}

gboolean
parse_op_key(const char *key, char **rsc_id, char **op_type, guint *interval_ms)
{
    guint local_interval_ms = 0;
    const size_t key_len = (key == NULL)? 0 : strlen(key);

    // Operation keys must be formatted as RSC_ACTION_INTERVAL
    size_t action_underbar = 0;   // Index in key of underbar before ACTION
    size_t interval_underbar = 0; // Index in key of underbar before INTERVAL
    size_t possible = 0;

    /* Underbar was a poor choice of separator since both RSC and ACTION can
     * contain underbars. Here, list action names and name prefixes that can.
     */
    const char *actions_with_underbars[] = {
        PCMK_ACTION_MIGRATE_FROM,
        PCMK_ACTION_MIGRATE_TO,
        NULL
    };
    const char *action_prefixes_with_underbars[] = {
        "pre_" PCMK_ACTION_NOTIFY,
        "post_" PCMK_ACTION_NOTIFY,
        "confirmed-pre_" PCMK_ACTION_NOTIFY,
        "confirmed-post_" PCMK_ACTION_NOTIFY,
        NULL,
    };

    // Initialize output variables in case of early return
    if (rsc_id) {
        *rsc_id = NULL;
    }
    if (op_type) {
        *op_type = NULL;
    }
    if (interval_ms) {
        *interval_ms = 0;
    }

    // RSC_ACTION_INTERVAL implies a minimum of 5 characters
    if (key_len < 5) {
        return FALSE;
    }

    // Find, parse, and validate interval
    interval_underbar = key_len - 2;
    while ((interval_underbar > 2) && (key[interval_underbar] != '_')) {
        --interval_underbar;
    }
    if ((interval_underbar == 2)
        || !convert_interval(key + interval_underbar + 1, &local_interval_ms)) {
        return FALSE;
    }

    // Find the base (OCF) action name, disregarding prefixes
    action_underbar = match_before(key, interval_underbar,
                                   actions_with_underbars);
    if (action_underbar == 0) {
        action_underbar = interval_underbar - 2;
        while ((action_underbar > 0) && (key[action_underbar] != '_')) {
            --action_underbar;
        }
        if (action_underbar == 0) {
            return FALSE;
        }
    }
    possible = match_before(key, action_underbar,
                            action_prefixes_with_underbars);
    if (possible != 0) {
        action_underbar = possible;
    }

    // Set output variables
    if (rsc_id != NULL) {
        *rsc_id = strndup(key, action_underbar);
        pcmk__mem_assert(*rsc_id);
    }
    if (op_type != NULL) {
        *op_type = strndup(key + action_underbar + 1,
                           interval_underbar - action_underbar - 1);
        pcmk__mem_assert(*op_type);
    }
    if (interval_ms != NULL) {
        *interval_ms = local_interval_ms;
    }
    return TRUE;
}

char *
pcmk__notify_key(const char *rsc_id, const char *notify_type,
                 const char *op_type)
{
    CRM_CHECK(rsc_id != NULL, return NULL);
    CRM_CHECK(op_type != NULL, return NULL);
    CRM_CHECK(notify_type != NULL, return NULL);
    return pcmk__assert_asprintf("%s_%s_notify_%s_0",
                                 rsc_id, notify_type, op_type);
}

/*!
 * \brief Parse a transition magic string into its constituent parts
 *
 * \param[in]  magic          Magic string to parse (must be non-NULL)
 * \param[out] uuid           If non-NULL, where to store copy of parsed UUID
 * \param[out] transition_id  If non-NULL, where to store parsed transition ID
 * \param[out] action_id      If non-NULL, where to store parsed action ID
 * \param[out] op_status      If non-NULL, where to store parsed result status
 * \param[out] op_rc          If non-NULL, where to store parsed actual rc
 * \param[out] target_rc      If non-NULL, where to stored parsed target rc
 *
 * \return TRUE if key was valid, FALSE otherwise
 * \note If uuid is supplied and this returns TRUE, the caller is responsible
 *       for freeing the memory for *uuid using free().
 */
gboolean
decode_transition_magic(const char *magic, char **uuid, int *transition_id, int *action_id,
                        int *op_status, int *op_rc, int *target_rc)
{
    int res = 0;
    char *key = NULL;
    gboolean result = TRUE;
    int local_op_status = -1;
    int local_op_rc = -1;

    CRM_CHECK(magic != NULL, return FALSE);

#ifdef HAVE_SSCANF_M
    res = sscanf(magic, "%d:%d;%ms", &local_op_status, &local_op_rc, &key);
#else
    // magic must have >=4 other characters
    key = pcmk__assert_alloc(strlen(magic) - 3, sizeof(char));
    res = sscanf(magic, "%d:%d;%s", &local_op_status, &local_op_rc, key);
#endif
    if (res == EOF) {
        pcmk__err("Could not decode transition information '%s': %s", magic,
                  pcmk_rc_str(errno));
        result = FALSE;
    } else if (res < 3) {
        pcmk__warn("Transition information '%s' incomplete (%d of 3 expected "
                   "items)",
                   magic, res);
        result = FALSE;
    } else {
        if (op_status) {
            *op_status = local_op_status;
        }
        if (op_rc) {
            *op_rc = local_op_rc;
        }
        result = decode_transition_key(key, uuid, transition_id, action_id,
                                       target_rc);
    }
    free(key);
    return result;
}

char *
pcmk__transition_key(int transition_id, int action_id, int target_rc,
                     const char *node)
{
    CRM_CHECK(node != NULL, return NULL);
    return pcmk__assert_asprintf("%d:%d:%d:%-*s",
                                 action_id, transition_id, target_rc, 36, node);
}

/*!
 * \brief Parse a transition key into its constituent parts
 *
 * \param[in]  key            Transition key to parse (must be non-NULL)
 * \param[out] uuid           If non-NULL, where to store copy of parsed UUID
 * \param[out] transition_id  If non-NULL, where to store parsed transition ID
 * \param[out] action_id      If non-NULL, where to store parsed action ID
 * \param[out] target_rc      If non-NULL, where to stored parsed target rc
 *
 * \return TRUE if key was valid, FALSE otherwise
 * \note If uuid is supplied and this returns TRUE, the caller is responsible
 *       for freeing the memory for *uuid using free().
 */
gboolean
decode_transition_key(const char *key, char **uuid, int *transition_id, int *action_id,
                      int *target_rc)
{
    int local_transition_id = -1;
    int local_action_id = -1;
    int local_target_rc = -1;
    char local_uuid[37] = { '\0' };

    // Initialize any supplied output arguments
    if (uuid) {
        *uuid = NULL;
    }
    if (transition_id) {
        *transition_id = -1;
    }
    if (action_id) {
        *action_id = -1;
    }
    if (target_rc) {
        *target_rc = -1;
    }

    CRM_CHECK(key != NULL, return FALSE);
    if (sscanf(key, "%d:%d:%d:%36s", &local_action_id, &local_transition_id,
               &local_target_rc, local_uuid) != 4) {
        pcmk__err("Invalid transition key '%s'", key);
        return FALSE;
    }
    if (strlen(local_uuid) != 36) {
        pcmk__warn("Invalid UUID '%s' in transition key '%s'", local_uuid, key);
    }
    if (uuid) {
        *uuid = pcmk__str_copy(local_uuid);
    }
    if (transition_id) {
        *transition_id = local_transition_id;
    }
    if (action_id) {
        *action_id = local_action_id;
    }
    if (target_rc) {
        *target_rc = local_target_rc;
    }
    return TRUE;
}

int
rsc_op_expected_rc(const lrmd_event_data_t *op)
{
    int rc = 0;

    if (op && op->user_data) {
        decode_transition_key(op->user_data, NULL, NULL, NULL, &rc);
    }
    return rc;
}

gboolean
did_rsc_op_fail(lrmd_event_data_t * op, int target_rc)
{
    switch (op->op_status) {
        case PCMK_EXEC_CANCELLED:
        case PCMK_EXEC_PENDING:
            return FALSE;

        case PCMK_EXEC_NOT_SUPPORTED:
        case PCMK_EXEC_TIMEOUT:
        case PCMK_EXEC_ERROR:
        case PCMK_EXEC_NOT_CONNECTED:
        case PCMK_EXEC_NO_FENCE_DEVICE:
        case PCMK_EXEC_NO_SECRETS:
        case PCMK_EXEC_INVALID:
            return TRUE;

        default:
            if (target_rc != op->rc) {
                return TRUE;
            }
    }

    return FALSE;
}

/*!
 * \brief Create a CIB XML element for an operation
 *
 * \param[in,out] parent         If not NULL, make new XML node a child of this
 * \param[in]     prefix         Generate an ID using this prefix
 * \param[in]     task           Operation task to set
 * \param[in]     interval_spec  Operation interval to set
 * \param[in]     timeout        If not NULL, operation timeout to set
 *
 * \return New XML object on success, NULL otherwise
 */
xmlNode *
crm_create_op_xml(xmlNode *parent, const char *prefix, const char *task,
                  const char *interval_spec, const char *timeout)
{
    xmlNode *xml_op;

    CRM_CHECK(prefix && task && interval_spec, return NULL);

    xml_op = pcmk__xe_create(parent, PCMK_XE_OP);
    pcmk__xe_set_id(xml_op, "%s-%s-%s", prefix, task, interval_spec);
    pcmk__xe_set(xml_op, PCMK_META_INTERVAL, interval_spec);
    pcmk__xe_set(xml_op, PCMK_XA_NAME, task);
    if (timeout) {
        pcmk__xe_set(xml_op, PCMK_META_TIMEOUT, timeout);
    }
    return xml_op;
}

/*!
 * \brief Check whether an operation requires resource agent meta-data
 *
 * \param[in] rsc_class  Resource agent class (or NULL to skip class check)
 * \param[in] op         Operation action (or NULL to skip op check)
 *
 * \return true if operation needs meta-data, false otherwise
 * \note At least one of rsc_class and op must be specified.
 */
bool
crm_op_needs_metadata(const char *rsc_class, const char *op)
{
    /* Agent metadata is used to determine whether an agent reload is possible,
     * so if this op is not relevant to that feature, we don't need metadata.
     */

    CRM_CHECK((rsc_class != NULL) || (op != NULL), return false);

    if ((rsc_class != NULL)
        && !pcmk__is_set(pcmk_get_ra_caps(rsc_class), pcmk_ra_cap_params)) {
        // Metadata is needed only for resource classes that use parameters
        return false;
    }
    if (op == NULL) {
        return true;
    }

    // Metadata is needed only for these actions
    return pcmk__str_any_of(op, PCMK_ACTION_START, PCMK_ACTION_MONITOR,
                            PCMK_ACTION_PROMOTE, PCMK_ACTION_DEMOTE,
                            PCMK_ACTION_RELOAD, PCMK_ACTION_RELOAD_AGENT,
                            PCMK_ACTION_MIGRATE_TO, PCMK_ACTION_MIGRATE_FROM,
                            PCMK_ACTION_NOTIFY, NULL);
}

/*!
 * \internal
 * \brief Check whether an action name is for a fencing action
 *
 * \param[in] action  Action name to check
 *
 * \return \c true if \p action is \c PCMK_ACTION_OFF or \c PCMK_ACTION_REBOOT,
 *         or \c false otherwise
 */
bool
pcmk__is_fencing_action(const char *action)
{
    return pcmk__str_any_of(action, PCMK_ACTION_OFF, PCMK_ACTION_REBOOT, NULL);
}
