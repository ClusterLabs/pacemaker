/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <crm/crm.h>
#include <crm/lrmd.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>

/*!
 * \brief Generate an operation key
 *
 * \param[in] rsc_id    ID of resource being operated on
 * \param[in] op_type   Operation name
 * \param[in] interval  Operation interval
 *
 * \return Newly allocated memory containing operation key as string
 *
 * \note It is the caller's responsibility to free() the result.
 */
char *
generate_op_key(const char *rsc_id, const char *op_type, int interval)
{
    CRM_ASSERT(rsc_id != NULL);
    CRM_ASSERT(op_type != NULL);
    CRM_ASSERT(interval >= 0);
    return crm_strdup_printf("%s_%s_%d", rsc_id, op_type, interval);
}

gboolean
parse_op_key(const char *key, char **rsc_id, char **op_type, int *interval)
{
    char *notify = NULL;
    char *mutable_key = NULL;
    char *mutable_key_ptr = NULL;
    int len = 0, offset = 0, ch = 0;
    int local_interval_ms = 0;

    // Initialize output variables in case of early return
    if (rsc_id) {
        *rsc_id = NULL;
    }
    if (op_type) {
        *op_type = NULL;
    }
    if (interval) {
        *interval = 0;
    }

    CRM_CHECK(key && *key, return FALSE);

    // Parse interval at end of string
    len = strlen(key);
    offset = len - 1;

    crm_trace("Source: %s", key);

    while (offset > 0 && isdigit(key[offset])) {
        int digits = len - offset;

        ch = key[offset] - '0';
        CRM_CHECK(ch < 10, return FALSE);
        CRM_CHECK(ch >= 0, return FALSE);
        while (digits > 1) {
            digits--;
            ch = ch * 10;
        }
        local_interval_ms += ch;
        offset--;
    }
    crm_trace("Operation key '%s' has interval %ums", key, local_interval_ms);
    if (interval) {
        *interval = local_interval_ms;
    }
 
    CRM_CHECK((offset != (len - 1)) && (key[offset] == '_'), return FALSE);

    mutable_key = strndup(key, offset);
    offset--;

    while (offset > 0 && key[offset] != '_') {
        offset--;
    }

    CRM_CHECK(key[offset] == '_',
              free(mutable_key); return FALSE);

    mutable_key_ptr = mutable_key + offset + 1;

    crm_trace("  Action: %s", mutable_key_ptr);
    if (op_type) {
        *op_type = strdup(mutable_key_ptr);
    }

    mutable_key[offset] = 0;
    offset--;

    notify = strstr(mutable_key, "_post_notify");
    if (notify && safe_str_eq(notify, "_post_notify")) {
        notify[0] = 0;
    }

    notify = strstr(mutable_key, "_pre_notify");
    if (notify && safe_str_eq(notify, "_pre_notify")) {
        notify[0] = 0;
    }

    crm_trace("  Resource: %s", mutable_key);
    if (rsc_id) {
        *rsc_id = mutable_key;
    } else {
        free(mutable_key);
    }

    return TRUE;
}

char *
generate_notify_key(const char *rsc_id, const char *notify_type, const char *op_type)
{
    int len = 12;
    char *op_id = NULL;

    CRM_CHECK(rsc_id != NULL, return NULL);
    CRM_CHECK(op_type != NULL, return NULL);
    CRM_CHECK(notify_type != NULL, return NULL);

    len += strlen(op_type);
    len += strlen(rsc_id);
    len += strlen(notify_type);
    if(len > 0) {
        op_id = malloc(len);
    }
    if (op_id != NULL) {
        sprintf(op_id, "%s_%s_notify_%s_0", rsc_id, notify_type, op_type);
    }
    return op_id;
}

char *
generate_transition_magic_v202(const char *transition_key, int op_status)
{
    int len = 80;
    char *fail_state = NULL;

    CRM_CHECK(transition_key != NULL, return NULL);

    len += strlen(transition_key);

    fail_state = malloc(len);
    if (fail_state != NULL) {
        snprintf(fail_state, len, "%d:%s", op_status, transition_key);
    }
    return fail_state;
}

char *
generate_transition_magic(const char *transition_key, int op_status, int op_rc)
{
    int len = 80;
    char *fail_state = NULL;

    CRM_CHECK(transition_key != NULL, return NULL);

    len += strlen(transition_key);

    fail_state = malloc(len);
    if (fail_state != NULL) {
        snprintf(fail_state, len, "%d:%d;%s", op_status, op_rc, transition_key);
    }
    return fail_state;
}

gboolean
decode_transition_magic(const char *magic, char **uuid, int *transition_id, int *action_id,
                        int *op_status, int *op_rc, int *target_rc)
{
    int res = 0;
    char *key = NULL;
    gboolean result = TRUE;

    CRM_CHECK(magic != NULL, return FALSE);
    CRM_CHECK(op_rc != NULL, return FALSE);
    CRM_CHECK(op_status != NULL, return FALSE);

    key = calloc(1, strlen(magic) + 1);
    res = sscanf(magic, "%d:%d;%s", op_status, op_rc, key);
    if (res != 3) {
        crm_warn("Only found %d items in: '%s'", res, magic);
        free(key);
        return FALSE;
    }

    CRM_CHECK(decode_transition_key(key, uuid, transition_id, action_id, target_rc), result = FALSE);

    free(key);
    return result;
}

char *
generate_transition_key(int transition_id, int action_id, int target_rc, const char *node)
{
    int len = 40;
    char *fail_state = NULL;

    CRM_CHECK(node != NULL, return NULL);

    len += strlen(node);

    fail_state = malloc(len);
    if (fail_state != NULL) {
        snprintf(fail_state, len, "%d:%d:%d:%-*s", action_id, transition_id, target_rc, 36, node);
    }
    return fail_state;
}

gboolean
decode_transition_key(const char *key, char **uuid, int *transition_id, int *action_id,
                      int *target_rc)
{
    int res = 0;
    gboolean done = FALSE;

    CRM_CHECK(uuid != NULL, return FALSE);
    CRM_CHECK(target_rc != NULL, return FALSE);
    CRM_CHECK(action_id != NULL, return FALSE);
    CRM_CHECK(transition_id != NULL, return FALSE);

    *uuid = calloc(1, 37);
    res = sscanf(key, "%d:%d:%d:%36s", action_id, transition_id, target_rc, *uuid);
    switch (res) {
        case 4:
            /* Post Pacemaker 0.6 */
            done = TRUE;
            break;
        case 3:
        case 2:
            /* this can be tricky - the UUID might start with an integer */

            /* Until Pacemaker 0.6 */
            done = TRUE;
            *target_rc = -1;
            res = sscanf(key, "%d:%d:%36s", action_id, transition_id, *uuid);
            if (res == 2) {
                *action_id = -1;
                res = sscanf(key, "%d:%36s", transition_id, *uuid);
                CRM_CHECK(res == 2, done = FALSE);

            } else if (res != 3) {
                CRM_CHECK(res == 3, done = FALSE);
            }
            break;

        case 1:
            /* Prior to Heartbeat 2.0.8 */
            done = TRUE;
            *action_id = -1;
            *target_rc = -1;
            res = sscanf(key, "%d:%36s", transition_id, *uuid);
            CRM_CHECK(res == 2, done = FALSE);
            break;
        default:
            crm_crit("Unhandled sscanf result (%d) for %s", res, key);
    }

    if (strlen(*uuid) != 36) {
        crm_warn("Bad UUID (%s) in sscanf result (%d) for %s", *uuid, res, key);
    }

    if (done == FALSE) {
        crm_err("Cannot decode '%s' rc=%d", key, res);

        free(*uuid);
        *uuid = NULL;
        *target_rc = -1;
        *action_id = -1;
        *transition_id = -1;
    }

    return done;
}

void
filter_action_parameters(xmlNode * param_set, const char *version)
{
    char *key = NULL;
    char *timeout = NULL;
    char *interval = NULL;

    const char *attr_filter[] = {
        XML_ATTR_ID,
        XML_ATTR_CRM_VERSION,
        XML_LRM_ATTR_OP_DIGEST,
        XML_LRM_ATTR_TARGET,
        XML_LRM_ATTR_TARGET_UUID,
        "pcmk_external_ip"
    };

    gboolean do_delete = FALSE;
    int lpc = 0;
    static int meta_len = 0;

    if (meta_len == 0) {
        meta_len = strlen(CRM_META);
    }

    if (param_set == NULL) {
        return;
    }

    for (lpc = 0; lpc < DIMOF(attr_filter); lpc++) {
        xml_remove_prop(param_set, attr_filter[lpc]);
    }

    key = crm_meta_name(XML_LRM_ATTR_INTERVAL);
    interval = crm_element_value_copy(param_set, key);
    free(key);

    key = crm_meta_name(XML_ATTR_TIMEOUT);
    timeout = crm_element_value_copy(param_set, key);

    if (param_set) {
        xmlAttrPtr xIter = param_set->properties;

        while (xIter) {
            const char *prop_name = (const char *)xIter->name;

            xIter = xIter->next;
            do_delete = FALSE;
            if (strncasecmp(prop_name, CRM_META, meta_len) == 0) {
                do_delete = TRUE;
            }

            if (do_delete) {
                xml_remove_prop(param_set, prop_name);
            }
        }
    }

    if (crm_get_msec(interval) > 0 && compare_version(version, "1.0.8") > 0) {
        /* Re-instate the operation's timeout value */
        if (timeout != NULL) {
            crm_xml_add(param_set, key, timeout);
        }
    }

    free(interval);
    free(timeout);
    free(key);
}

#define FAKE_TE_ID	"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
static void
append_digest(lrmd_event_data_t * op, xmlNode * update, const char *version, const char *magic,
              int level)
{
    /* this will enable us to later determine that the
     *   resource's parameters have changed and we should force
     *   a restart
     */
    char *digest = NULL;
    xmlNode *args_xml = NULL;

    if (op->params == NULL) {
        return;
    }

    args_xml = create_xml_node(NULL, XML_TAG_PARAMS);
    g_hash_table_foreach(op->params, hash2field, args_xml);
    filter_action_parameters(args_xml, version);
    digest = calculate_operation_digest(args_xml, version);

#if 0
    if (level < get_crm_log_level()
        && op->interval == 0 && crm_str_eq(op->op_type, CRMD_ACTION_START, TRUE)) {
        char *digest_source = dump_xml_unformatted(args_xml);

        do_crm_log(level, "Calculated digest %s for %s (%s). Source: %s\n",
                   digest, ID(update), magic, digest_source);
        free(digest_source);
    }
#endif
    crm_xml_add(update, XML_LRM_ATTR_OP_DIGEST, digest);

    free_xml(args_xml);
    free(digest);
}

int
rsc_op_expected_rc(lrmd_event_data_t * op)
{
    int rc = 0;

    if (op && op->user_data) {
        int dummy = 0;
        char *uuid = NULL;

        decode_transition_key(op->user_data, &uuid, &dummy, &dummy, &rc);
        free(uuid);
    }
    return rc;
}

gboolean
did_rsc_op_fail(lrmd_event_data_t * op, int target_rc)
{
    switch (op->op_status) {
        case PCMK_LRM_OP_CANCELLED:
        case PCMK_LRM_OP_PENDING:
            return FALSE;
            break;

        case PCMK_LRM_OP_NOTSUPPORTED:
        case PCMK_LRM_OP_TIMEOUT:
        case PCMK_LRM_OP_ERROR:
            return TRUE;
            break;

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
 * \param[in] parent    If not NULL, make new XML node a child of this one
 * \param[in] prefix    Generate an ID using this prefix
 * \param[in] task      Operation task to set
 * \param[in] interval  Operation interval to set
 * \param[in] timeout   If not NULL, operation timeout to set
 *
 * \return New XML object on success, NULL otherwise
 */
xmlNode *
crm_create_op_xml(xmlNode *parent, const char *prefix, const char *task,
                  const char *interval, const char *timeout)
{
    xmlNode *xml_op;

    CRM_CHECK(prefix && task && interval, return NULL);

    xml_op = create_xml_node(parent, XML_ATTR_OP);
    crm_xml_set_id(xml_op, "%s-%s-%s", prefix, task, interval);
    crm_xml_add(xml_op, XML_LRM_ATTR_INTERVAL, interval);
    crm_xml_add(xml_op, "name", task);
    if (timeout) {
        crm_xml_add(xml_op, XML_ATTR_TIMEOUT, timeout);
    }
    return xml_op;
}

xmlNode *
create_operation_update(xmlNode * parent, lrmd_event_data_t * op, const char * caller_version,
                        int target_rc, const char * node, const char * origin, int level)
{
    char *key = NULL;
    char *magic = NULL;
    char *op_id = NULL;
    char *op_id_additional = NULL;
    char *local_user_data = NULL;
    const char *exit_reason = NULL;

    xmlNode *xml_op = NULL;
    const char *task = NULL;
    gboolean dc_munges_migrate_ops = (compare_version(caller_version, "3.0.3") < 0);
    gboolean dc_needs_unique_ops = (compare_version(caller_version, "3.0.6") < 0);

    CRM_CHECK(op != NULL, return NULL);
    do_crm_log(level, "%s: Updating resource %s after %s op %s (interval=%d)",
               origin, op->rsc_id, op->op_type, services_lrm_status_str(op->op_status),
               op->interval);

    crm_trace("DC version: %s", caller_version);

    task = op->op_type;
    /* remap the task name under various scenarios
     * this makes life easier for the PE when trying determine the current state
     */
    if (crm_str_eq(task, "reload", TRUE)) {
        if (op->op_status == PCMK_LRM_OP_DONE) {
            task = CRMD_ACTION_START;
        } else {
            task = CRMD_ACTION_STATUS;
        }

    } else if (dc_munges_migrate_ops && crm_str_eq(task, CRMD_ACTION_MIGRATE, TRUE)) {
        /* if the migrate_from fails it will have enough info to do the right thing */
        if (op->op_status == PCMK_LRM_OP_DONE) {
            task = CRMD_ACTION_STOP;
        } else {
            task = CRMD_ACTION_STATUS;
        }

    } else if (dc_munges_migrate_ops
               && op->op_status == PCMK_LRM_OP_DONE
               && crm_str_eq(task, CRMD_ACTION_MIGRATED, TRUE)) {
        task = CRMD_ACTION_START;
    }

    key = generate_op_key(op->rsc_id, task, op->interval);
    if (dc_needs_unique_ops && op->interval > 0) {
        op_id = strdup(key);

    } else if (crm_str_eq(task, CRMD_ACTION_NOTIFY, TRUE)) {
        const char *n_type = crm_meta_value(op->params, "notify_type");
        const char *n_task = crm_meta_value(op->params, "notify_operation");

        CRM_LOG_ASSERT(n_type != NULL);
        CRM_LOG_ASSERT(n_task != NULL);
        op_id = generate_notify_key(op->rsc_id, n_type, n_task);

        if (op->op_status != PCMK_LRM_OP_PENDING) {
            /* Ignore notify errors.
             *
             * @TODO It might be better to keep the correct result here, and
             * ignore it in process_graph_event().
             */
            op->op_status = PCMK_LRM_OP_DONE;
            op->rc = 0;
        }

    } else if (did_rsc_op_fail(op, target_rc)) {
        op_id = generate_op_key(op->rsc_id, "last_failure", 0);
        if (op->interval == 0) {
            /* Ensure 'last' gets updated too in case recording-pending="true" */
            op_id_additional = generate_op_key(op->rsc_id, "last", 0);
        }
        exit_reason = op->exit_reason;

    } else if (op->interval > 0) {
        op_id = strdup(key);

    } else {
        op_id = generate_op_key(op->rsc_id, "last", 0);
    }

  again:
    xml_op = find_entity(parent, XML_LRM_TAG_RSC_OP, op_id);
    if (xml_op == NULL) {
        xml_op = create_xml_node(parent, XML_LRM_TAG_RSC_OP);
    }

    if (op->user_data == NULL) {
        crm_debug("Generating fake transition key for:"
                  " %s_%s_%d %d from %s",
                  op->rsc_id, op->op_type, op->interval, op->call_id, origin);
        local_user_data = generate_transition_key(-1, op->call_id, target_rc, FAKE_TE_ID);
        op->user_data = local_user_data;
    }

    if(magic == NULL) {
        magic = generate_transition_magic(op->user_data, op->op_status, op->rc);
    }

    crm_xml_add(xml_op, XML_ATTR_ID, op_id);
    crm_xml_add(xml_op, XML_LRM_ATTR_TASK_KEY, key);
    crm_xml_add(xml_op, XML_LRM_ATTR_TASK, task);
    crm_xml_add(xml_op, XML_ATTR_ORIGIN, origin);
    crm_xml_add(xml_op, XML_ATTR_CRM_VERSION, caller_version);
    crm_xml_add(xml_op, XML_ATTR_TRANSITION_KEY, op->user_data);
    crm_xml_add(xml_op, XML_ATTR_TRANSITION_MAGIC, magic);
    crm_xml_add(xml_op, XML_LRM_ATTR_EXIT_REASON, exit_reason == NULL ? "" : exit_reason);
    crm_xml_add(xml_op, XML_LRM_ATTR_TARGET, node); /* For context during triage */

    crm_xml_add_int(xml_op, XML_LRM_ATTR_CALLID, op->call_id);
    crm_xml_add_int(xml_op, XML_LRM_ATTR_RC, op->rc);
    crm_xml_add_int(xml_op, XML_LRM_ATTR_OPSTATUS, op->op_status);
    crm_xml_add_int(xml_op, XML_LRM_ATTR_INTERVAL, op->interval);

    if (compare_version("2.1", caller_version) <= 0) {
        if (op->t_run || op->t_rcchange || op->exec_time || op->queue_time) {
            crm_trace("Timing data (%s_%s_%d): last=%u change=%u exec=%u queue=%u",
                      op->rsc_id, op->op_type, op->interval,
                      op->t_run, op->t_rcchange, op->exec_time, op->queue_time);

            if (op->interval == 0) {
                /* The values are the same for non-recurring ops */
                crm_xml_add_int(xml_op, XML_RSC_OP_LAST_RUN, op->t_run);
                crm_xml_add_int(xml_op, XML_RSC_OP_LAST_CHANGE, op->t_run);

            } else if(op->t_rcchange) {
                /* last-run is not accurate for recurring ops */
                crm_xml_add_int(xml_op, XML_RSC_OP_LAST_CHANGE, op->t_rcchange);

            } else {
                /* ...but is better than nothing otherwise */
                crm_xml_add_int(xml_op, XML_RSC_OP_LAST_CHANGE, op->t_run);
            }

            crm_xml_add_int(xml_op, XML_RSC_OP_T_EXEC, op->exec_time);
            crm_xml_add_int(xml_op, XML_RSC_OP_T_QUEUE, op->queue_time);
        }
    }

    if (crm_str_eq(op->op_type, CRMD_ACTION_MIGRATE, TRUE)
        || crm_str_eq(op->op_type, CRMD_ACTION_MIGRATED, TRUE)) {
        /*
         * Record migrate_source and migrate_target always for migrate ops.
         */
        const char *name = XML_LRM_ATTR_MIGRATE_SOURCE;

        crm_xml_add(xml_op, name, crm_meta_value(op->params, name));

        name = XML_LRM_ATTR_MIGRATE_TARGET;
        crm_xml_add(xml_op, name, crm_meta_value(op->params, name));
    }

    append_digest(op, xml_op, caller_version, magic, LOG_DEBUG);

    if (op_id_additional) {
        free(op_id);
        op_id = op_id_additional;
        op_id_additional = NULL;
        goto again;
    }

    if (local_user_data) {
        free(local_user_data);
        op->user_data = NULL;
    }
    free(magic);
    free(op_id);
    free(key);
    return xml_op;
}

/*!
 * \brief Check whether an operation requires resource agent meta-data
 *
 * \param[in] rsc_class  Resource agent class (or NULL to skip class check)
 * \param[in] op         Operation action (or NULL to skip op check)
 *
 * \return TRUE if operation needs meta-data, FALSE otherwise
 * \note At least one of rsc_class and op must be specified.
 */
bool
crm_op_needs_metadata(const char *rsc_class, const char *op)
{
    /* Agent meta-data is used to determine whether a reload is possible, and to
     * evaluate versioned parameters -- so if this op is not relevant to those
     * features, we don't need the meta-data.
     */

    CRM_CHECK(rsc_class || op, return FALSE);

    if (rsc_class
        && is_not_set(pcmk_get_ra_caps(rsc_class), pcmk_ra_cap_params)) {
        /* Meta-data is only needed for resource classes that use parameters */
        return FALSE;
    }

    /* Meta-data is only needed for these actions */
    if (op
        && strcmp(op, CRMD_ACTION_START)
        && strcmp(op, CRMD_ACTION_STATUS)
        && strcmp(op, CRMD_ACTION_PROMOTE)
        && strcmp(op, CRMD_ACTION_DEMOTE)
        && strcmp(op, CRMD_ACTION_RELOAD)
        && strcmp(op, CRMD_ACTION_MIGRATE)
        && strcmp(op, CRMD_ACTION_MIGRATED)
        && strcmp(op, CRMD_ACTION_NOTIFY)) {
        return FALSE;
    }

    return TRUE;
}
