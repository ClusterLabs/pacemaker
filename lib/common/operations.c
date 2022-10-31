/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ctype.h>

#include <crm/crm.h>
#include <crm/lrmd.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>
#include <crm/common/util.h>

static regex_t *notify_migrate_re = NULL;

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
    CRM_ASSERT(rsc_id != NULL);
    CRM_ASSERT(op_type != NULL);
    return crm_strdup_printf(PCMK__OP_FMT, rsc_id, op_type, interval_ms);
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

static gboolean
try_fast_match(const char *key, const char *underbar1, const char *underbar2,
               char **rsc_id, char **op_type, guint *interval_ms)
{
    if (interval_ms) {
        if (!convert_interval(underbar2+1, interval_ms)) {
            return FALSE;
        }
    }

    if (rsc_id) {
        *rsc_id = strndup(key, underbar1-key);
    }

    if (op_type) {
        *op_type = strndup(underbar1+1, underbar2-underbar1-1);
    }

    return TRUE;
}

static gboolean
try_basic_match(const char *key, char **rsc_id, char **op_type, guint *interval_ms)
{
    char *interval_sep = NULL;
    char *type_sep = NULL;

    // Parse interval at end of string
    interval_sep = strrchr(key, '_');
    if (interval_sep == NULL) {
        return FALSE;
    }

    if (interval_ms) {
        if (!convert_interval(interval_sep+1, interval_ms)) {
            return FALSE;
        }
    }

    type_sep = interval_sep-1;

    while (1) {
        if (*type_sep == '_') {
            break;
        } else if (type_sep == key) {
            if (interval_ms) {
                *interval_ms = 0;
            }

            return FALSE;
        }

        type_sep--;
    }

    if (op_type) {
        // Add one here to skip the leading underscore we landed on in the
        // while loop.
        *op_type = strndup(type_sep+1, interval_sep-type_sep-1);
    }

    // Everything else is the name of the resource.
    if (rsc_id) {
        *rsc_id = strndup(key, type_sep-key);
    }

    return TRUE;
}

static gboolean
try_migrate_notify_match(const char *key, char **rsc_id, char **op_type, guint *interval_ms)
{
    int rc = 0;
    size_t nmatch = 8;
    regmatch_t pmatch[nmatch];

    if (notify_migrate_re == NULL) {
        // cppcheck-suppress memleak
        notify_migrate_re = calloc(1, sizeof(regex_t));
        rc = regcomp(notify_migrate_re, "^(.*)_(migrate_(from|to)|(pre|post)_notify_([a-z]+|migrate_(from|to)))_([0-9]+)$",
                     REG_EXTENDED);
        CRM_ASSERT(rc == 0);
    }

    rc = regexec(notify_migrate_re, key, nmatch, pmatch, 0);
    if (rc == REG_NOMATCH) {
        return FALSE;
    }

    if (rsc_id) {
        *rsc_id = strndup(key+pmatch[1].rm_so, pmatch[1].rm_eo-pmatch[1].rm_so);
    }

    if (op_type) {
        *op_type = strndup(key+pmatch[2].rm_so, pmatch[2].rm_eo-pmatch[2].rm_so);
    }

    if (interval_ms) {
        if (!convert_interval(key+pmatch[7].rm_so, interval_ms)) {
            if (rsc_id) {
                free(*rsc_id);
                *rsc_id = NULL;
            }

            if (op_type) {
                free(*op_type);
                *op_type = NULL;
            }

            return FALSE;
        }
    }

    return TRUE;
}

gboolean
parse_op_key(const char *key, char **rsc_id, char **op_type, guint *interval_ms)
{
    char *underbar1 = NULL;
    char *underbar2 = NULL;
    char *underbar3 = NULL;

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

    CRM_CHECK(key && *key, return FALSE);

    underbar1 = strchr(key, '_');
    if (!underbar1) {
        return FALSE;
    }

    underbar2 = strchr(underbar1+1, '_');
    if (!underbar2) {
        return FALSE;
    }

    underbar3 = strchr(underbar2+1, '_');

    if (!underbar3) {
        return try_fast_match(key, underbar1, underbar2,
                              rsc_id, op_type, interval_ms);
    } else if (try_migrate_notify_match(key, rsc_id, op_type, interval_ms)) {
        return TRUE;
    } else {
        return try_basic_match(key, rsc_id, op_type, interval_ms);
    }
}

char *
pcmk__notify_key(const char *rsc_id, const char *notify_type,
                 const char *op_type)
{
    CRM_CHECK(rsc_id != NULL, return NULL);
    CRM_CHECK(op_type != NULL, return NULL);
    CRM_CHECK(notify_type != NULL, return NULL);
    return crm_strdup_printf("%s_%s_notify_%s_0",
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
    key = calloc(1, strlen(magic) - 3); // magic must have >=4 other characters
    CRM_ASSERT(key);
    res = sscanf(magic, "%d:%d;%s", &local_op_status, &local_op_rc, key);
#endif
    if (res == EOF) {
        crm_err("Could not decode transition information '%s': %s",
                magic, pcmk_rc_str(errno));
        result = FALSE;
    } else if (res < 3) {
        crm_warn("Transition information '%s' incomplete (%d of 3 expected items)",
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
    return crm_strdup_printf("%d:%d:%d:%-*s",
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
        crm_err("Invalid transition key '%s'", key);
        return FALSE;
    }
    if (strlen(local_uuid) != 36) {
        crm_warn("Invalid UUID '%s' in transition key '%s'", local_uuid, key);
    }
    if (uuid) {
        *uuid = strdup(local_uuid);
        CRM_ASSERT(*uuid);
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

// Return true if a is an attribute that should be filtered
static bool
should_filter_for_digest(xmlAttrPtr a, void *user_data)
{
    if (strncmp((const char *) a->name, CRM_META "_",
                sizeof(CRM_META " ") - 1) == 0) {
        return true;
    }
    return pcmk__str_any_of((const char *) a->name,
                            XML_ATTR_ID,
                            XML_ATTR_CRM_VERSION,
                            XML_LRM_ATTR_OP_DIGEST,
                            XML_LRM_ATTR_TARGET,
                            XML_LRM_ATTR_TARGET_UUID,
                            "pcmk_external_ip",
                            NULL);
}

/*!
 * \internal
 * \brief Remove XML attributes not needed for operation digest
 *
 * \param[in,out] param_set  XML with operation parameters
 */
void
pcmk__filter_op_for_digest(xmlNode *param_set)
{
    char *key = NULL;
    char *timeout = NULL;
    guint interval_ms = 0;

    if (param_set == NULL) {
        return;
    }

    /* Timeout is useful for recurring operation digests, so grab it before
     * removing meta-attributes
     */
    key = crm_meta_name(XML_LRM_ATTR_INTERVAL_MS);
    if (crm_element_value_ms(param_set, key, &interval_ms) != pcmk_ok) {
        interval_ms = 0;
    }
    free(key);
    key = NULL;
    if (interval_ms != 0) {
        key = crm_meta_name(XML_ATTR_TIMEOUT);
        timeout = crm_element_value_copy(param_set, key);
    }

    // Remove all CRM_meta_* attributes and certain other attributes
    pcmk__xe_remove_matching_attrs(param_set, should_filter_for_digest, NULL);

    // Add timeout back for recurring operation digests
    if (timeout != NULL) {
        crm_xml_add(param_set, key, timeout);
    }
    free(timeout);
    free(key);
}

int
rsc_op_expected_rc(lrmd_event_data_t * op)
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

    xml_op = create_xml_node(parent, XML_ATTR_OP);
    crm_xml_set_id(xml_op, "%s-%s-%s", prefix, task, interval_spec);
    crm_xml_add(xml_op, XML_LRM_ATTR_INTERVAL, interval_spec);
    crm_xml_add(xml_op, "name", task);
    if (timeout) {
        crm_xml_add(xml_op, XML_ATTR_TIMEOUT, timeout);
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
        && !pcmk_is_set(pcmk_get_ra_caps(rsc_class), pcmk_ra_cap_params)) {
        // Metadata is needed only for resource classes that use parameters
        return false;
    }
    if (op == NULL) {
        return true;
    }

    // Metadata is needed only for these actions
    return pcmk__str_any_of(op, CRMD_ACTION_START, CRMD_ACTION_STATUS,
                            CRMD_ACTION_PROMOTE, CRMD_ACTION_DEMOTE,
                            CRMD_ACTION_RELOAD, CRMD_ACTION_RELOAD_AGENT,
                            CRMD_ACTION_MIGRATE, CRMD_ACTION_MIGRATED,
                            CRMD_ACTION_NOTIFY, NULL);
}

/*!
 * \internal
 * \brief Check whether an action name is for a fencing action
 *
 * \param[in] action  Action name to check
 *
 * \return true if \p action is "off", "reboot", or "poweroff", otherwise false
 */
bool
pcmk__is_fencing_action(const char *action)
{
    return pcmk__str_any_of(action, "off", "reboot", "poweroff", NULL);
}

bool
pcmk_is_probe(const char *task, guint interval)
{
    if (task == NULL) {
        return false;
    }

    return (interval == 0) && pcmk__str_eq(task, CRMD_ACTION_STATUS, pcmk__str_none);
}

bool
pcmk_xe_is_probe(xmlNode *xml_op)
{
    const char *task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
    const char *interval_ms_s = crm_element_value(xml_op, XML_LRM_ATTR_INTERVAL_MS);
    int interval_ms;

    pcmk__scan_min_int(interval_ms_s, &interval_ms, 0);
    return pcmk_is_probe(task, interval_ms);
}

bool
pcmk_xe_mask_probe_failure(xmlNode *xml_op)
{
    int status = PCMK_EXEC_UNKNOWN;
    int rc = PCMK_OCF_OK;

    if (!pcmk_xe_is_probe(xml_op)) {
        return false;
    }

    crm_element_value_int(xml_op, XML_LRM_ATTR_OPSTATUS, &status);
    crm_element_value_int(xml_op, XML_LRM_ATTR_RC, &rc);

    return rc == PCMK_OCF_NOT_INSTALLED || rc == PCMK_OCF_INVALID_PARAM ||
           status == PCMK_EXEC_NOT_INSTALLED;
}
