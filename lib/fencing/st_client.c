/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/types.h>

#include <glib.h>
#include <libxml/tree.h>            // xmlNode
#include <libxml/xpath.h>           // xmlXPathObject, etc.

#include <crm/crm.h>
#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/common/xml.h>

#include <crm/common/mainloop.h>

#include "fencing_private.h"

// Used as stonith_t:st_private
typedef struct {
    char *token;
    crm_ipc_t *ipc;
    mainloop_io_t *source;
    GHashTable *stonith_op_callback_table;
    GList *notify_list;
    int notify_refcnt;
    bool notify_deletes;

    void (*op_callback) (stonith_t * st, stonith_callback_data_t * data);

} stonith_private_t;

// Used as stonith_event_t:opaque
struct event_private {
    pcmk__action_result_t result;
};

typedef struct {
    const char *event;
    const char *obj_id;         /* implement one day */
    const char *obj_type;       /* implement one day */
    void (*notify) (stonith_t * st, stonith_event_t * e);
    bool delete;

} stonith_notify_client_t;

typedef struct {
    void (*callback) (stonith_t * st, stonith_callback_data_t * data);
    const char *id;
    void *user_data;
    gboolean only_success;
    gboolean allow_timeout_updates;
    struct timer_rec_s *timer;

} stonith_callback_client_t;

struct notify_blob_s {
    stonith_t *stonith;
    xmlNode *xml;
};

struct timer_rec_s {
    int call_id;
    int timeout;
    guint ref;
    stonith_t *stonith;
};

typedef int (*stonith_op_t) (const char *, int, const char *, xmlNode *,
                             xmlNode *, xmlNode *, xmlNode **, xmlNode **);

xmlNode *stonith_create_op(int call_id, const char *token, const char *op, xmlNode * data,
                           int call_options);
static int stonith_send_command(stonith_t *stonith, const char *op,
                                xmlNode *data, xmlNode **output_data,
                                int call_options, int timeout);

static void stonith_connection_destroy(gpointer user_data);
static void stonith_send_notification(gpointer data, gpointer user_data);
static int stonith_api_del_notification(stonith_t *stonith,
                                        const char *event);

/*!
 * \internal
 * \brief Parse fence agent namespace from a string
 *
 * \param[in] namespace_s  Name of namespace as string
 *
 * \return enum value parsed from \p namespace_s
 */
static enum stonith_namespace
parse_namespace(const char *namespace_s)
{
    if (pcmk__str_eq(namespace_s, "any", pcmk__str_null_matches)) {
        return st_namespace_any;
    }
    /* @TODO Is "redhat" still necessary except for stonith_text2namespace()
     * backward compatibility?
     */
    if (pcmk__str_any_of(namespace_s, "redhat", "stonith-ng", NULL)) {
        return st_namespace_rhcs;
    }
    if (pcmk__str_eq(namespace_s, "internal", pcmk__str_none)) {
        return st_namespace_internal;
    }
    if (pcmk__str_eq(namespace_s, "heartbeat", pcmk__str_none)) {
        return st_namespace_lha;
    }
    return st_namespace_invalid;
}

/*!
 * \internal
 * \brief Get name of a fence agent namespace as a string
 *
 * \param[in] st_namespace  Namespace as enum value
 *
 * \return Name of \p st_namespace as a string
 */
static const char *
namespace_text(enum stonith_namespace st_namespace)
{
    switch (st_namespace) {
        case st_namespace_any:
            return "any";
        case st_namespace_rhcs:
            return "stonith-ng";
        case st_namespace_internal:
            return "internal";
        case st_namespace_lha:
            return "heartbeat";
        default:
            return "unsupported";
    }
}

/*!
 * \internal
 * \brief Determine fence agent namespace from agent name
 *
 * This involves external checks (for example, checking the existence of a file
 * or calling an external library function).
 *
 * \param[in] agent  Fence agent name
 *
 * \return Namespace to which \p agent belongs, or \c st_namespace_invalid if
 *         not found
 */
static enum stonith_namespace
get_namespace_from_agent(const char *agent)
{
    if (stonith__agent_is_rhcs(agent)) {
        return st_namespace_rhcs;
    }

#if HAVE_STONITH_STONITH_H
    if (stonith__agent_is_lha(agent)) {
        return st_namespace_lha;
    }
#endif  // HAVE_STONITH_STONITH_H

    return st_namespace_invalid;
}

gboolean
stonith__watchdog_fencing_enabled_for_node_api(stonith_t *st, const char *node)
{
    gboolean rv = FALSE;
    stonith_t *stonith_api = (st != NULL)? st : stonith__api_new();
    char *list = NULL;

    if(stonith_api) {
        if (stonith_api->state == stonith_disconnected) {
            int rc = stonith_api->cmds->connect(stonith_api, "stonith-api", NULL);

            if (rc != pcmk_ok) {
                pcmk__err("Failed connecting to Stonith-API for "
                          "watchdog-fencing-query");
            }
        }

        if (stonith_api->state != stonith_disconnected) {
            /* caveat!!!
             * this might fail when the fencer is just updating the device-list
             * probably something we should fix as well for other api-calls */
            int rc = stonith_api->cmds->list(stonith_api, st_opt_sync_call, STONITH_WATCHDOG_ID, &list, 0);
            if ((rc != pcmk_ok) || (list == NULL)) {
                /* due to the race described above it can happen that
                 * we drop in here - so as not to make remote nodes
                 * panic on that answer
                 */
                if (rc == -ENODEV) {
                    pcmk__notice("Cluster does not have watchdog fencing "
                                 "device");
                } else {
                    pcmk__warn("Could not check for watchdog fencing device: %s",
                               pcmk_strerror(rc));
                }
            } else if (list[0] == '\0') {
                rv = TRUE;
            } else {
                GList *targets = stonith__parse_targets(list);
                rv = pcmk__str_in_list(node, targets, pcmk__str_casei);
                g_list_free_full(targets, free);
            }
            free(list);
            if (!st) {
                /* if we're provided the api we still might have done the
                 * connection - but let's assume the caller won't bother
                 */
                stonith_api->cmds->disconnect(stonith_api);
            }
        }

        if (!st) {
            stonith__api_free(stonith_api);
        }
    } else {
        pcmk__err("Stonith-API for watchdog-fencing-query couldn't be created");
    }
    pcmk__trace("Pacemaker assumes node %s %sto do watchdog-fencing", node,
                (rv? "" : "not "));
    return rv;
}

gboolean
stonith__watchdog_fencing_enabled_for_node(const char *node)
{
    return stonith__watchdog_fencing_enabled_for_node_api(NULL, node);
}

/* when cycling through the list we don't want to delete items
   so just mark them and when we know nobody is using the list
   loop over it to remove the marked items
 */
static void
foreach_notify_entry (stonith_private_t *private,
                GFunc func,
                gpointer user_data)
{
    private->notify_refcnt++;
    g_list_foreach(private->notify_list, func, user_data);
    private->notify_refcnt--;
    if ((private->notify_refcnt == 0) &&
        private->notify_deletes) {
        GList *list_item = private->notify_list;

        private->notify_deletes = FALSE;
        while (list_item != NULL)
        {
            stonith_notify_client_t *list_client = list_item->data;
            GList *next = g_list_next(list_item);

            if (list_client->delete) {
                free(list_client);
                private->notify_list =
                    g_list_delete_link(private->notify_list, list_item);
            }
            list_item = next;
        }
    }
}

static void
stonith_connection_destroy(gpointer user_data)
{
    stonith_t *stonith = user_data;
    stonith_private_t *native = NULL;
    struct notify_blob_s blob;

    pcmk__trace("Sending destroyed notification");
    blob.stonith = stonith;
    blob.xml = pcmk__xe_create(NULL, PCMK__XE_NOTIFY);

    native = stonith->st_private;
    native->ipc = NULL;
    native->source = NULL;

    free(native->token); native->token = NULL;
    stonith->state = stonith_disconnected;
    pcmk__xe_set(blob.xml, PCMK__XA_T, PCMK__VALUE_ST_NOTIFY);
    pcmk__xe_set(blob.xml, PCMK__XA_SUBT, PCMK__VALUE_ST_NOTIFY_DISCONNECT);

    foreach_notify_entry(native, stonith_send_notification, &blob);
    pcmk__xml_free(blob.xml);
}

xmlNode *
create_device_registration_xml(const char *id, enum stonith_namespace standard,
                               const char *agent,
                               const stonith_key_value_t *params,
                               const char *rsc_provides)
{
    xmlNode *data = pcmk__xe_create(NULL, PCMK__XE_ST_DEVICE_ID);
    xmlNode *args = pcmk__xe_create(data, PCMK__XE_ATTRIBUTES);

#if HAVE_STONITH_STONITH_H
    if (standard == st_namespace_any) {
        standard = get_namespace_from_agent(agent);
    }
    if (standard == st_namespace_lha) {
        hash2field((gpointer) "plugin", (gpointer) agent, args);
        agent = "fence_legacy";
    }
#endif

    pcmk__xe_set(data, PCMK_XA_ID, id);
    pcmk__xe_set(data, PCMK__XA_ST_ORIGIN, __func__);
    pcmk__xe_set(data, PCMK_XA_AGENT, agent);
    if ((standard != st_namespace_any) && (standard != st_namespace_invalid)) {
        pcmk__xe_set(data, PCMK__XA_NAMESPACE, namespace_text(standard));
    }
    if (rsc_provides) {
        pcmk__xe_set(data, PCMK__XA_RSC_PROVIDES, rsc_provides);
    }

    for (; params; params = params->next) {
        hash2field((gpointer) params->key, (gpointer) params->value, args);
    }

    return data;
}

static int
stonith_api_register_device(stonith_t *st, int call_options,
                            const char *id, const char *namespace_s,
                            const char *agent,
                            const stonith_key_value_t *params)
{
    int rc = 0;
    xmlNode *data = NULL;

    data = create_device_registration_xml(id, parse_namespace(namespace_s),
                                          agent, params, NULL);

    rc = stonith_send_command(st, STONITH_OP_DEVICE_ADD, data, NULL, call_options, 0);
    pcmk__xml_free(data);

    return rc;
}

static int
stonith_api_remove_device(stonith_t * st, int call_options, const char *name)
{
    int rc = 0;
    xmlNode *data = NULL;

    data = pcmk__xe_create(NULL, PCMK__XE_ST_DEVICE_ID);
    pcmk__xe_set(data, PCMK__XA_ST_ORIGIN, __func__);
    pcmk__xe_set(data, PCMK_XA_ID, name);
    rc = stonith_send_command(st, STONITH_OP_DEVICE_DEL, data, NULL, call_options, 0);
    pcmk__xml_free(data);

    return rc;
}

static int
stonith_api_remove_level_full(stonith_t *st, int options,
                              const char *node, const char *pattern,
                              const char *attr, const char *value, int level)
{
    int rc = 0;
    xmlNode *data = NULL;

    CRM_CHECK(node || pattern || (attr && value), return -EINVAL);

    data = pcmk__xe_create(NULL, PCMK_XE_FENCING_LEVEL);
    pcmk__xe_set(data, PCMK__XA_ST_ORIGIN, __func__);

    if (node) {
        pcmk__xe_set(data, PCMK_XA_TARGET, node);

    } else if (pattern) {
        pcmk__xe_set(data, PCMK_XA_TARGET_PATTERN, pattern);

    } else {
        pcmk__xe_set(data, PCMK_XA_TARGET_ATTRIBUTE, attr);
        pcmk__xe_set(data, PCMK_XA_TARGET_VALUE, value);
    }

    pcmk__xe_set_int(data, PCMK_XA_INDEX, level);
    rc = stonith_send_command(st, STONITH_OP_LEVEL_DEL, data, NULL, options, 0);
    pcmk__xml_free(data);

    return rc;
}

static int
stonith_api_remove_level(stonith_t * st, int options, const char *node, int level)
{
    return stonith_api_remove_level_full(st, options, node,
                                         NULL, NULL, NULL, level);
}

/*!
 * \internal
 * \brief Create XML for fence topology level registration request
 *
 * \param[in] node        If not NULL, target level by this node name
 * \param[in] pattern     If not NULL, target by node name using this regex
 * \param[in] attr        If not NULL, target by this node attribute
 * \param[in] value       If not NULL, target by this node attribute value
 * \param[in] level       Index number of level to register
 * \param[in] device_list List of devices in level
 *
 * \return Newly allocated XML tree on success, NULL otherwise
 *
 * \note The caller should set only one of node, pattern or attr/value.
 */
xmlNode *
create_level_registration_xml(const char *node, const char *pattern,
                              const char *attr, const char *value,
                              int level, const stonith_key_value_t *device_list)
{
    GString *list = NULL;
    xmlNode *data;

    CRM_CHECK(node || pattern || (attr && value), return NULL);

    data = pcmk__xe_create(NULL, PCMK_XE_FENCING_LEVEL);

    pcmk__xe_set(data, PCMK__XA_ST_ORIGIN, __func__);
    pcmk__xe_set_int(data, PCMK_XA_ID, level);
    pcmk__xe_set_int(data, PCMK_XA_INDEX, level);

    if (node) {
        pcmk__xe_set(data, PCMK_XA_TARGET, node);

    } else if (pattern) {
        pcmk__xe_set(data, PCMK_XA_TARGET_PATTERN, pattern);

    } else {
        pcmk__xe_set(data, PCMK_XA_TARGET_ATTRIBUTE, attr);
        pcmk__xe_set(data, PCMK_XA_TARGET_VALUE, value);
    }

    for (; device_list; device_list = device_list->next) {
        pcmk__add_separated_word(&list, 1024, device_list->value, ",");
    }

    if (list != NULL) {
        pcmk__xe_set(data, PCMK_XA_DEVICES, (const char *) list->str);
        g_string_free(list, TRUE);
    }
    return data;
}

static int
stonith_api_register_level_full(stonith_t *st, int options, const char *node,
                                const char *pattern, const char *attr,
                                const char *value, int level,
                                const stonith_key_value_t *device_list)
{
    int rc = 0;
    xmlNode *data = create_level_registration_xml(node, pattern, attr, value,
                                                  level, device_list);
    CRM_CHECK(data != NULL, return -EINVAL);

    rc = stonith_send_command(st, STONITH_OP_LEVEL_ADD, data, NULL, options, 0);
    pcmk__xml_free(data);

    return rc;
}

static int
stonith_api_register_level(stonith_t * st, int options, const char *node, int level,
                           const stonith_key_value_t * device_list)
{
    return stonith_api_register_level_full(st, options, node, NULL, NULL, NULL,
                                           level, device_list);
}

static int
stonith_api_device_list(stonith_t *stonith, int call_options,
                        const char *namespace_s, stonith_key_value_t **devices,
                        int timeout)
{
    int count = 0;
    enum stonith_namespace ns = parse_namespace(namespace_s);

    if (devices == NULL) {
        pcmk__err("Parameter error: stonith_api_device_list");
        return -EFAULT;
    }

#if HAVE_STONITH_STONITH_H
    // Include Linux-HA agents if requested
    if ((ns == st_namespace_any) || (ns == st_namespace_lha)) {
        count += stonith__list_lha_agents(devices);
    }
#endif

    // Include Red Hat agents if requested
    if ((ns == st_namespace_any) || (ns == st_namespace_rhcs)) {
        count += stonith__list_rhcs_agents(devices);
    }

    return count;
}

// See stonith_api_operations_t:metadata() documentation
static int
stonith_api_device_metadata(stonith_t *stonith, int call_options,
                            const char *agent, const char *namespace_s,
                            char **output, int timeout_sec)
{
    /* By executing meta-data directly, we can get it from stonith_admin when
     * the cluster is not running, which is important for higher-level tools.
     */

    enum stonith_namespace ns = get_namespace_from_agent(agent);

    if (timeout_sec <= 0) {
        timeout_sec = PCMK_DEFAULT_ACTION_TIMEOUT_MS;
    }

    pcmk__trace("Looking up metadata for %s agent %s", namespace_text(ns),
                agent);

    switch (ns) {
        case st_namespace_rhcs:
            return stonith__rhcs_metadata(agent, timeout_sec, output);

#if HAVE_STONITH_STONITH_H
        case st_namespace_lha:
            return stonith__lha_metadata(agent, timeout_sec, output);
#endif

        default:
            pcmk__err("Can't get fence agent '%s' meta-data: No such agent",
                      agent);
            break;
    }
    return -ENODEV;
}

static int
stonith_api_query(stonith_t * stonith, int call_options, const char *target,
                  stonith_key_value_t ** devices, int timeout)
{
    int rc = 0, lpc = 0, max = 0;

    xmlNode *data = NULL;
    xmlNode *output = NULL;
    xmlXPathObject *xpathObj = NULL;

    CRM_CHECK(devices != NULL, return -EINVAL);

    data = pcmk__xe_create(NULL, PCMK__XE_ST_DEVICE_ID);
    pcmk__xe_set(data, PCMK__XA_ST_ORIGIN, __func__);
    pcmk__xe_set(data, PCMK__XA_ST_TARGET, target);
    pcmk__xe_set(data, PCMK__XA_ST_DEVICE_ACTION, PCMK_ACTION_OFF);
    rc = stonith_send_command(stonith, STONITH_OP_QUERY, data, &output, call_options, timeout);

    if (rc < 0) {
        return rc;
    }

    xpathObj = pcmk__xpath_search(output->doc, "//*[@" PCMK_XA_AGENT "]");
    if (xpathObj) {
        max = pcmk__xpath_num_results(xpathObj);

        for (lpc = 0; lpc < max; lpc++) {
            xmlNode *match = pcmk__xpath_result(xpathObj, lpc);

            CRM_LOG_ASSERT(match != NULL);
            if(match != NULL) {
                const char *match_id = pcmk__xe_get(match, PCMK_XA_ID);
                xmlChar *match_path = xmlGetNodePath(match);

                pcmk__info("//*[@" PCMK_XA_AGENT "][%d] = %s", lpc, match_path);
                free(match_path);
                *devices = stonith__key_value_add(*devices, NULL, match_id);
            }
        }

        xmlXPathFreeObject(xpathObj);
    }

    pcmk__xml_free(output);
    pcmk__xml_free(data);
    return max;
}

/*!
 * \internal
 * \brief Make a STONITH_OP_EXEC request
 *
 * \param[in,out] stonith       Fencer connection
 * \param[in]     call_options  Bitmask of \c stonith_call_options
 * \param[in]     id            Fence device ID that request is for
 * \param[in]     action        Agent action to request (list, status, monitor)
 * \param[in]     target        Name of target node for requested action
 * \param[in]     timeout_sec   Error if not completed within this many seconds
 * \param[out]    output        Where to set agent output
 */
static int
stonith_api_call(stonith_t *stonith, int call_options, const char *id,
                 const char *action, const char *target, int timeout_sec,
                 xmlNode **output)
{
    int rc = 0;
    xmlNode *data = NULL;

    data = pcmk__xe_create(NULL, PCMK__XE_ST_DEVICE_ID);
    pcmk__xe_set(data, PCMK__XA_ST_ORIGIN, __func__);
    pcmk__xe_set(data, PCMK__XA_ST_DEVICE_ID, id);
    pcmk__xe_set(data, PCMK__XA_ST_DEVICE_ACTION, action);
    pcmk__xe_set(data, PCMK__XA_ST_TARGET, target);

    rc = stonith_send_command(stonith, STONITH_OP_EXEC, data, output,
                              call_options, timeout_sec);
    pcmk__xml_free(data);

    return rc;
}

static int
stonith_api_list(stonith_t * stonith, int call_options, const char *id, char **list_info,
                 int timeout)
{
    int rc;
    xmlNode *output = NULL;

    rc = stonith_api_call(stonith, call_options, id, PCMK_ACTION_LIST, NULL,
                          timeout, &output);

    if (output && list_info) {
        const char *list_str;

        list_str = pcmk__xe_get(output, PCMK__XA_ST_OUTPUT);

        if (list_str) {
            *list_info = strdup(list_str);
        }
    }

    if (output) {
        pcmk__xml_free(output);
    }

    return rc;
}

static int
stonith_api_monitor(stonith_t * stonith, int call_options, const char *id, int timeout)
{
    return stonith_api_call(stonith, call_options, id, PCMK_ACTION_MONITOR,
                            NULL, timeout, NULL);
}

static int
stonith_api_status(stonith_t * stonith, int call_options, const char *id, const char *port,
                   int timeout)
{
    return stonith_api_call(stonith, call_options, id, PCMK_ACTION_STATUS, port,
                            timeout, NULL);
}

static int
stonith_api_fence_with_delay(stonith_t * stonith, int call_options, const char *node,
                             const char *action, int timeout, int tolerance, int delay)
{
    int rc = 0;
    xmlNode *data = NULL;

    data = pcmk__xe_create(NULL, __func__);
    pcmk__xe_set(data, PCMK__XA_ST_TARGET, node);
    pcmk__xe_set(data, PCMK__XA_ST_DEVICE_ACTION, action);
    pcmk__xe_set_int(data, PCMK__XA_ST_TIMEOUT, timeout);
    pcmk__xe_set_int(data, PCMK__XA_ST_TOLERANCE, tolerance);
    pcmk__xe_set_int(data, PCMK__XA_ST_DELAY, delay);

    rc = stonith_send_command(stonith, STONITH_OP_FENCE, data, NULL, call_options, timeout);
    pcmk__xml_free(data);

    return rc;
}

static int
stonith_api_fence(stonith_t * stonith, int call_options, const char *node, const char *action,
                  int timeout, int tolerance)
{
    return stonith_api_fence_with_delay(stonith, call_options, node, action,
                                        timeout, tolerance, 0);
}

static int
stonith_api_confirm(stonith_t * stonith, int call_options, const char *target)
{
    stonith__set_call_options(call_options, target, st_opt_manual_ack);
    return stonith_api_fence(stonith, call_options, target, PCMK_ACTION_OFF, 0,
                             0);
}

static int
stonith_api_history(stonith_t * stonith, int call_options, const char *node,
                    stonith_history_t ** history, int timeout)
{
    int rc = 0;
    xmlNode *data = NULL;
    xmlNode *output = NULL;
    stonith_history_t *last = NULL;

    *history = NULL;

    if (node) {
        data = pcmk__xe_create(NULL, __func__);
        pcmk__xe_set(data, PCMK__XA_ST_TARGET, node);
    }

    stonith__set_call_options(call_options, node, st_opt_sync_call);
    rc = stonith_send_command(stonith, STONITH_OP_FENCE_HISTORY, data, &output,
                              call_options, timeout);
    pcmk__xml_free(data);

    if (rc == 0) {
        xmlNode *op = NULL;
        xmlNode *reply = pcmk__xpath_find_one(output->doc,
                                              "//" PCMK__XE_ST_HISTORY,
                                              PCMK__LOG_NEVER);

        for (op = pcmk__xe_first_child(reply, NULL, NULL, NULL); op != NULL;
             op = pcmk__xe_next(op, NULL)) {
            stonith_history_t *kvp =
                pcmk__assert_alloc(1, sizeof(stonith_history_t));
            long long completed_nsec = 0LL;

            kvp->target = pcmk__xe_get_copy(op, PCMK__XA_ST_TARGET);
            kvp->action = pcmk__xe_get_copy(op, PCMK__XA_ST_DEVICE_ACTION);
            kvp->origin = pcmk__xe_get_copy(op, PCMK__XA_ST_ORIGIN);
            kvp->delegate = pcmk__xe_get_copy(op, PCMK__XA_ST_DELEGATE);
            kvp->client = pcmk__xe_get_copy(op, PCMK__XA_ST_CLIENTNAME);
            pcmk__xe_get_time(op, PCMK__XA_ST_DATE, &kvp->completed);

            pcmk__xe_get_ll(op, PCMK__XA_ST_DATE_NSEC, &completed_nsec);

            // Coverity complains here if long is the same size as long long
            // coverity[result_independent_of_operands:FALSE]
            if ((completed_nsec >= LONG_MIN) && (completed_nsec <= LONG_MAX)) {
                kvp->completed_nsec = (long) completed_nsec;
            }

            pcmk__xe_get_int(op, PCMK__XA_ST_STATE, &kvp->state);
            kvp->exit_reason = pcmk__xe_get_copy(op, PCMK_XA_EXIT_REASON);

            if (last) {
                last->next = kvp;
            } else {
                *history = kvp;
            }
            last = kvp;
        }
    }

    pcmk__xml_free(output);

    return rc;
}

/*!
 * \internal
 * \brief Free a list of fencing history objects and all members of each object
 *
 * \param[in,out] head  Head of fencing history object list
 */
void
stonith__history_free(stonith_history_t *head)
{
    /* @COMPAT Drop "next" member of stonith_history_t, use a GList or GSList,
     * and use the appropriate free function (while ensuring the members get
     * freed)
     */
    while (head != NULL) {
        stonith_history_t *next = head->next;

        free(head->target);
        free(head->action);
        free(head->origin);
        free(head->delegate);
        free(head->client);
        free(head->exit_reason);
        free(head);
        head = next;
    }
}

static gint
stonithlib_GCompareFunc(gconstpointer a, gconstpointer b)
{
    int rc = 0;
    const stonith_notify_client_t *a_client = a;
    const stonith_notify_client_t *b_client = b;

    if (a_client->delete || b_client->delete) {
        /* make entries marked for deletion not findable */
        return -1;
    }
    CRM_CHECK(a_client->event != NULL && b_client->event != NULL, return 0);
    rc = strcmp(a_client->event, b_client->event);
    if (rc == 0) {
        if (a_client->notify == NULL || b_client->notify == NULL) {
            return 0;

        } else if (a_client->notify == b_client->notify) {
            return 0;

        } else if (((long)a_client->notify) < ((long)b_client->notify)) {
            pcmk__err("callbacks for %s are not equal: %p vs. %p",
                      a_client->event, a_client->notify, b_client->notify);
            return -1;
        }
        pcmk__err("callbacks for %s are not equal: %p vs. %p",
                  a_client->event, a_client->notify, b_client->notify);
        return 1;
    }
    return rc;
}

xmlNode *
stonith_create_op(int call_id, const char *token, const char *op, xmlNode * data, int call_options)
{
    xmlNode *op_msg = NULL;

    CRM_CHECK(token != NULL, return NULL);

    op_msg = pcmk__xe_create(NULL, PCMK__XE_STONITH_COMMAND);
    pcmk__xe_set(op_msg, PCMK__XA_T, PCMK__VALUE_STONITH_NG);
    pcmk__xe_set(op_msg, PCMK__XA_ST_OP, op);
    pcmk__xe_set_int(op_msg, PCMK__XA_ST_CALLID, call_id);
    pcmk__trace("Sending call options: %.8lx, %d", (long) call_options,
                call_options);
    pcmk__xe_set_int(op_msg, PCMK__XA_ST_CALLOPT, call_options);

    if (data != NULL) {
        xmlNode *wrapper = pcmk__xe_create(op_msg, PCMK__XE_ST_CALLDATA);

        pcmk__xml_copy(wrapper, data);
    }

    return op_msg;
}

static void
stonith_destroy_op_callback(gpointer data)
{
    stonith_callback_client_t *blob = data;

    if (blob->timer && blob->timer->ref > 0) {
        g_source_remove(blob->timer->ref);
    }
    free(blob->timer);
    free(blob);
}

static int
stonith_api_signoff(stonith_t * stonith)
{
    stonith_private_t *native = stonith->st_private;

    pcmk__debug("Disconnecting from the fencer");

    if (native->source != NULL) {
        /* Attached to mainloop */
        mainloop_del_ipc_client(native->source);
        native->source = NULL;
        native->ipc = NULL;

    } else if (native->ipc) {
        /* Not attached to mainloop */
        crm_ipc_t *ipc = native->ipc;

        native->ipc = NULL;
        crm_ipc_close(ipc);
        crm_ipc_destroy(ipc);
    }

    free(native->token); native->token = NULL;
    stonith->state = stonith_disconnected;
    return pcmk_ok;
}

static int
stonith_api_del_callback(stonith_t * stonith, int call_id, bool all_callbacks)
{
    stonith_private_t *private = stonith->st_private;

    if (all_callbacks) {
        private->op_callback = NULL;
        g_hash_table_destroy(private->stonith_op_callback_table);
        private->stonith_op_callback_table = pcmk__intkey_table(stonith_destroy_op_callback);

    } else if (call_id == 0) {
        private->op_callback = NULL;

    } else {
        pcmk__intkey_table_remove(private->stonith_op_callback_table, call_id);
    }
    return pcmk_ok;
}

/*!
 * \internal
 * \brief Invoke a (single) specified fence action callback
 *
 * \param[in,out] st        Fencer API connection
 * \param[in]     call_id   If positive, call ID of completed fence action,
 *                          otherwise legacy return code for early failure
 * \param[in,out] result    Full result for action
 * \param[in,out] userdata  User data to pass to callback
 * \param[in]     callback  Fence action callback to invoke
 */
static void
invoke_fence_action_callback(stonith_t *st, int call_id,
                             pcmk__action_result_t *result,
                             void *userdata,
                             void (*callback) (stonith_t *st,
                                               stonith_callback_data_t *data))
{
    stonith_callback_data_t data = { 0, };

    data.call_id = call_id;
    data.rc = pcmk_rc2legacy(stonith__result2rc(result));
    data.userdata = userdata;
    data.opaque = (void *) result;

    callback(st, &data);
}

/*!
 * \internal
 * \brief Invoke any callbacks registered for a specified fence action result
 *
 * Given a fence action result from the fencer, invoke any callback registered
 * for that action, as well as any global callback registered.
 *
 * \param[in,out] stonith   Fencer API connection
 * \param[in]     msg       If non-NULL, fencer reply
 * \param[in]     call_id   If \p msg is NULL, call ID of action that timed out
 */
static void
invoke_registered_callbacks(stonith_t *stonith, const xmlNode *msg, int call_id)
{
    stonith_private_t *private = NULL;
    stonith_callback_client_t *cb_info = NULL;
    pcmk__action_result_t result = PCMK__UNKNOWN_RESULT;

    CRM_CHECK(stonith != NULL, return);
    CRM_CHECK(stonith->st_private != NULL, return);

    private = stonith->st_private;

    if (msg == NULL) {
        // Fencer didn't reply in time
        pcmk__set_result(&result, CRM_EX_ERROR, PCMK_EXEC_TIMEOUT,
                         "Fencer accepted request but did not reply in time");
        CRM_LOG_ASSERT(call_id > 0);

    } else {
        // We have the fencer reply
        if ((pcmk__xe_get_int(msg, PCMK__XA_ST_CALLID, &call_id) != pcmk_rc_ok)
            || (call_id <= 0)) {
            pcmk__log_xml_warn(msg, "Bad fencer reply");
        }
        stonith__xe_get_result(msg, &result);
    }

    if (call_id > 0) {
        cb_info = pcmk__intkey_table_lookup(private->stonith_op_callback_table,
                                            call_id);
    }

    if ((cb_info != NULL) && (cb_info->callback != NULL)
        && (pcmk__result_ok(&result) || !(cb_info->only_success))) {
        pcmk__trace("Invoking callback %s for call %d",
                    pcmk__s(cb_info->id, "without ID"), call_id);
        invoke_fence_action_callback(stonith, call_id, &result,
                                     cb_info->user_data, cb_info->callback);

    } else if ((private->op_callback == NULL) && !pcmk__result_ok(&result)) {
        pcmk__warn("Fencing action without registered callback failed: %d "
                   "(%s%s%s)",
                   result.exit_status,
                   pcmk_exec_status_str(result.execution_status),
                   ((result.exit_reason != NULL)? ": " : ""),
                   pcmk__s(result.exit_reason, ""));
        pcmk__log_xml_debug(msg, "Failed fence update");
    }

    if (private->op_callback != NULL) {
        pcmk__trace("Invoking global callback for call %d", call_id);
        invoke_fence_action_callback(stonith, call_id, &result, NULL,
                                     private->op_callback);
    }

    if (cb_info != NULL) {
        stonith_api_del_callback(stonith, call_id, FALSE);
    }
    pcmk__reset_result(&result);
}

static gboolean
stonith_async_timeout_handler(gpointer data)
{
    struct timer_rec_s *timer = data;

    pcmk__err("Async call %d timed out after %dms", timer->call_id,
              timer->timeout);
    invoke_registered_callbacks(timer->stonith, NULL, timer->call_id);

    /* Always return TRUE, never remove the handler
     * We do that in stonith_del_callback()
     */
    return TRUE;
}

static void
set_callback_timeout(stonith_callback_client_t * callback, stonith_t * stonith, int call_id,
                     int timeout)
{
    struct timer_rec_s *async_timer = callback->timer;

    if (timeout <= 0) {
        return;
    }

    if (!async_timer) {
        async_timer = pcmk__assert_alloc(1, sizeof(struct timer_rec_s));
        callback->timer = async_timer;
    }

    async_timer->stonith = stonith;
    async_timer->call_id = call_id;
    /* Allow a fair bit of grace to allow the server to tell us of a timeout
     * This is only a fallback
     */
    async_timer->timeout = (timeout + 60) * 1000;
    if (async_timer->ref) {
        g_source_remove(async_timer->ref);
    }
    async_timer->ref =
        pcmk__create_timer(async_timer->timeout, stonith_async_timeout_handler,
                           async_timer);
}

static void
update_callback_timeout(int call_id, int timeout, stonith_t * st)
{
    stonith_callback_client_t *callback = NULL;
    stonith_private_t *private = st->st_private;

    callback = pcmk__intkey_table_lookup(private->stonith_op_callback_table,
                                         call_id);
    if (!callback || !callback->allow_timeout_updates) {
        return;
    }

    set_callback_timeout(callback, st, call_id, timeout);
}

static int
stonith_dispatch_internal(const char *buffer, ssize_t length, gpointer userdata)
{
    const char *type = NULL;
    struct notify_blob_s blob;

    stonith_t *st = userdata;
    stonith_private_t *private = NULL;

    pcmk__assert(st != NULL);
    private = st->st_private;

    blob.stonith = st;
    blob.xml = pcmk__xml_parse(buffer);
    if (blob.xml == NULL) {
        pcmk__warn("Received malformed message from fencer: %s", buffer);
        return 0;
    }

    /* do callbacks */
    type = pcmk__xe_get(blob.xml, PCMK__XA_T);
    pcmk__trace("Activating %s callbacks...", type);

    if (pcmk__str_eq(type, PCMK__VALUE_STONITH_NG, pcmk__str_none)) {
        invoke_registered_callbacks(st, blob.xml, 0);

    } else if (pcmk__str_eq(type, PCMK__VALUE_ST_NOTIFY, pcmk__str_none)) {
        foreach_notify_entry(private, stonith_send_notification, &blob);

    } else if (pcmk__str_eq(type, PCMK__VALUE_ST_ASYNC_TIMEOUT_VALUE,
                            pcmk__str_none)) {
        int call_id = 0;
        int timeout = 0;

        pcmk__xe_get_int(blob.xml, PCMK__XA_ST_TIMEOUT, &timeout);
        pcmk__xe_get_int(blob.xml, PCMK__XA_ST_CALLID, &call_id);

        update_callback_timeout(call_id, timeout, st);
    } else {
        pcmk__err("Unknown message type: %s", type);
        pcmk__log_xml_warn(blob.xml, "BadReply");
    }

    pcmk__xml_free(blob.xml);
    return 1;
}

static int
stonith_api_signon(stonith_t * stonith, const char *name, int *stonith_fd)
{
    int rc = pcmk_ok;
    stonith_private_t *native = NULL;
    const char *display_name = name? name : "client";

    xmlNode *reply = NULL;
    xmlNode *hello = NULL;
    const char *msg_type = NULL;

    struct ipc_client_callbacks st_callbacks = {
        .dispatch = stonith_dispatch_internal,
        .destroy = stonith_connection_destroy
    };

    CRM_CHECK(stonith != NULL, return -EINVAL);

    native = stonith->st_private;
    pcmk__assert(native != NULL);

    pcmk__debug("Attempting fencer connection by %s with%s mainloop",
                display_name, ((stonith_fd != 0)? "out" : ""));

    stonith->state = stonith_connected_command;
    if (stonith_fd) {
        /* No mainloop */
        native->ipc = crm_ipc_new("stonith-ng", 0);
        if (native->ipc != NULL) {
            rc = pcmk__connect_generic_ipc(native->ipc);
            if (rc == pcmk_rc_ok) {
                rc = pcmk__ipc_fd(native->ipc, stonith_fd);
                if (rc != pcmk_rc_ok) {
                    pcmk__debug("Couldn't get file descriptor for IPC: %s",
                                pcmk_rc_str(rc));
                }
            }
            if (rc != pcmk_rc_ok) {
                crm_ipc_close(native->ipc);
                crm_ipc_destroy(native->ipc);
                native->ipc = NULL;
            }
        }

    } else {
        /* With mainloop */
        native->source =
            mainloop_add_ipc_client("stonith-ng", G_PRIORITY_MEDIUM, 0, stonith, &st_callbacks);
        native->ipc = mainloop_get_ipc_client(native->source);
    }

    if (native->ipc == NULL) {
        rc = -ENOTCONN;
        goto done;
    }

    hello = pcmk__xe_create(NULL, PCMK__XE_STONITH_COMMAND);

    pcmk__xe_set(hello, PCMK__XA_T, PCMK__VALUE_STONITH_NG);
    pcmk__xe_set(hello, PCMK__XA_ST_OP, CRM_OP_REGISTER);
    pcmk__xe_set(hello, PCMK__XA_ST_CLIENTNAME, name);
    rc = crm_ipc_send(native->ipc, hello, crm_ipc_client_response, -1, &reply);

    if (rc < 0) {
        pcmk__debug("Couldn't register with the fencer: %s " QB_XS " rc=%d",
                    pcmk_strerror(rc), rc);
        rc = -ECOMM;
        goto done;
    }

    if (reply == NULL) {
        pcmk__debug("Couldn't register with the fencer: no reply");
        rc = -EPROTO;
        goto done;
    }

    /* If we received an ACK with an error status in response, fenced
     * thinks we originally sent an invalid message.
     *
     * NOTE: At the moment, all ACK messages sent in the signon process
     * will have an error status.  However, this may change in the future so
     * we'll let those fall through to the rest of the message handling below
     * so we get some log messages should we change that in the future.
     */
    if (pcmk__xe_is(reply, PCMK__XE_ACK)) {
        int status = 0;

        rc = pcmk__xe_get_int(reply, PCMK_XA_STATUS, &status);

        if ((rc == pcmk_rc_ok) && (status != 0)) {
            pcmk__err("Received error response from CIB manager: %s",
                      crm_exit_str(status));
            return -EPROTO;
        }
    }

    msg_type = pcmk__xe_get(reply, PCMK__XA_ST_OP);

    native->token = pcmk__xe_get_copy(reply, PCMK__XA_ST_CLIENTID);
    if (!pcmk__str_eq(msg_type, CRM_OP_REGISTER, pcmk__str_none)) {
        pcmk__debug("Couldn't register with the fencer: invalid reply "
                    "type '%s'",
                    pcmk__s(msg_type, "(missing)"));
        pcmk__log_xml_debug(reply, "Invalid fencer reply");
        rc = -EPROTO;

    } else if (native->token == NULL) {
        pcmk__debug("Couldn't register with the fencer: no token in "
                    "reply");
        pcmk__log_xml_debug(reply, "Invalid fencer reply");
        rc = -EPROTO;

    } else {
        pcmk__debug("Connection to fencer by %s succeeded "
                    "(registration token: %s)",
                    display_name, native->token);
        rc = pcmk_ok;
    }

done:
    pcmk__xml_free(reply);
    pcmk__xml_free(hello);

    if (rc != pcmk_ok) {
        pcmk__debug("Connection attempt to fencer by %s failed: %s "
                    QB_XS " rc=%d",
                    display_name, pcmk_strerror(rc), rc);
        stonith->cmds->disconnect(stonith);
    }
    return rc;
}

static int
stonith_set_notification(stonith_t * stonith, const char *callback, int enabled)
{
    int rc = pcmk_ok;
    xmlNode *notify_msg = pcmk__xe_create(NULL, __func__);
    stonith_private_t *native = stonith->st_private;

    if (stonith->state != stonith_disconnected) {

        pcmk__xe_set(notify_msg, PCMK__XA_ST_OP, STONITH_OP_NOTIFY);
        if (enabled) {
            pcmk__xe_set(notify_msg, PCMK__XA_ST_NOTIFY_ACTIVATE, callback);
        } else {
            pcmk__xe_set(notify_msg, PCMK__XA_ST_NOTIFY_DEACTIVATE, callback);
        }

        rc = crm_ipc_send(native->ipc, notify_msg, crm_ipc_client_response, -1, NULL);
        if (rc < 0) {
            pcmk__debug("Couldn't register for fencing notifications: %s",
                        pcmk_strerror(rc));
            rc = -ECOMM;
        } else {
            rc = pcmk_ok;
        }
    }

    pcmk__xml_free(notify_msg);
    return rc;
}

static int
stonith_api_add_notification(stonith_t * stonith, const char *event,
                             void (*callback) (stonith_t * stonith, stonith_event_t * e))
{
    GList *list_item = NULL;
    stonith_notify_client_t *new_client = NULL;
    stonith_private_t *private = NULL;

    private = stonith->st_private;
    pcmk__trace("Adding callback for %s events (%u)", event,
                g_list_length(private->notify_list));

    new_client = pcmk__assert_alloc(1, sizeof(stonith_notify_client_t));
    new_client->event = event;
    new_client->notify = callback;

    list_item = g_list_find_custom(private->notify_list, new_client, stonithlib_GCompareFunc);

    if (list_item != NULL) {
        pcmk__warn("Callback already present");
        free(new_client);
        return -ENOTUNIQ;

    } else {
        private->notify_list = g_list_append(private->notify_list, new_client);

        stonith_set_notification(stonith, event, 1);

        pcmk__trace("Callback added (%u)", g_list_length(private->notify_list));
    }
    return pcmk_ok;
}

static void
del_notify_entry(gpointer data, gpointer user_data)
{
    stonith_notify_client_t *entry = data;
    stonith_t * stonith = user_data;

    if (!entry->delete) {
        pcmk__debug("Removing callback for %s events", entry->event);
        stonith_api_del_notification(stonith, entry->event);
    }
}

static int
stonith_api_del_notification(stonith_t * stonith, const char *event)
{
    GList *list_item = NULL;
    stonith_notify_client_t *new_client = NULL;
    stonith_private_t *private = stonith->st_private;

    if (event == NULL) {
        foreach_notify_entry(private, del_notify_entry, stonith);
        pcmk__trace("Removed callback");

        return pcmk_ok;
    }

    pcmk__debug("Removing callback for %s events", event);

    new_client = pcmk__assert_alloc(1, sizeof(stonith_notify_client_t));
    new_client->event = event;
    new_client->notify = NULL;

    list_item = g_list_find_custom(private->notify_list, new_client, stonithlib_GCompareFunc);

    stonith_set_notification(stonith, event, 0);

    if (list_item != NULL) {
        stonith_notify_client_t *list_client = list_item->data;

        if (private->notify_refcnt) {
            list_client->delete = TRUE;
            private->notify_deletes = TRUE;
        } else {
            private->notify_list = g_list_remove(private->notify_list, list_client);
            free(list_client);
        }

        pcmk__trace("Removed callback");

    } else {
        pcmk__trace("Callback not present");
    }
    free(new_client);
    return pcmk_ok;
}

static int
stonith_api_add_callback(stonith_t * stonith, int call_id, int timeout, int options,
                         void *user_data, const char *callback_name,
                         void (*callback) (stonith_t * st, stonith_callback_data_t * data))
{
    stonith_callback_client_t *blob = NULL;
    stonith_private_t *private = NULL;

    CRM_CHECK(stonith != NULL, return -EINVAL);
    CRM_CHECK(stonith->st_private != NULL, return -EINVAL);
    private = stonith->st_private;

    if (call_id == 0) { // Add global callback
        private->op_callback = callback;

    } else if (call_id < 0) { // Call failed immediately, so call callback now
        if (!(options & st_opt_report_only_success)) {
            pcmk__action_result_t result = PCMK__UNKNOWN_RESULT;

            pcmk__trace("Call failed, calling %s: %s", callback_name,
                        pcmk_strerror(call_id));
            pcmk__set_result(&result, CRM_EX_ERROR,
                             stonith__legacy2status(call_id), NULL);
            invoke_fence_action_callback(stonith, call_id, &result,
                                         user_data, callback);
        } else {
            pcmk__warn("Fencer call failed: %s", pcmk_strerror(call_id));
        }
        return FALSE;
    }

    blob = pcmk__assert_alloc(1, sizeof(stonith_callback_client_t));
    blob->id = callback_name;
    blob->only_success = (options & st_opt_report_only_success) ? TRUE : FALSE;
    blob->user_data = user_data;
    blob->callback = callback;
    blob->allow_timeout_updates = (options & st_opt_timeout_updates) ? TRUE : FALSE;

    if (timeout > 0) {
        set_callback_timeout(blob, stonith, call_id, timeout);
    }

    pcmk__intkey_table_insert(private->stonith_op_callback_table, call_id,
                              blob);
    pcmk__trace("Added callback to %s for call %d", callback_name, call_id);

    return TRUE;
}

/*!
 * \internal
 * \brief Get the data section of a fencer notification
 *
 * \param[in] msg    Notification XML
 * \param[in] ntype  Notification type
 */
static xmlNode *
get_event_data_xml(xmlNode *msg, const char *ntype)
{
    char *data_addr = pcmk__assert_asprintf("//%s", ntype);
    xmlNode *data = pcmk__xpath_find_one(msg->doc, data_addr, LOG_DEBUG);

    free(data_addr);
    return data;
}

/*
 <notify t="st_notify" subt="st_device_register" st_op="st_device_register" st_rc="0" >
   <st_calldata >
     <stonith_command t="stonith-ng" st_async_id="088fb640-431a-48b9-b2fc-c4ff78d0a2d9" st_op="st_device_register" st_callid="2" st_callopt="4096" st_timeout="0" st_clientid="088fb640-431a-48b9-b2fc-c4ff78d0a2d9" st_clientname="cts-fence-helper" >
       <st_calldata >
         <st_device_id id="test-id" origin="create_device_registration_xml" agent="fence_virsh" namespace="stonith-ng" >
           <attributes ipaddr="localhost" pcmk-portmal="some-host=pcmk-1 pcmk-3=3,4" login="root" identity_file="/root/.ssh/id_dsa" />
         </st_device_id>
       </st_calldata>
     </stonith_command>
   </st_calldata>
 </notify>

 <notify t="st_notify" subt="st_notify_fence" st_op="st_notify_fence" st_rc="0" >
   <st_calldata >
     <st_notify_fence st_rc="0" st_target="some-host" st_op="st_fence" st_delegate="test-id" st_origin="61dd7759-e229-4be7-b1f8-ef49dd14d9f0" />
   </st_calldata>
 </notify>
*/
static stonith_event_t *
xml_to_event(xmlNode *msg)
{
    stonith_event_t *event = pcmk__assert_alloc(1, sizeof(stonith_event_t));
    struct event_private *event_private = NULL;

    event->opaque = pcmk__assert_alloc(1, sizeof(struct event_private));
    event_private = (struct event_private *) event->opaque;

    pcmk__log_xml_trace(msg, "stonith_notify");

    // All notification types have the operation result and notification subtype
    stonith__xe_get_result(msg, &event_private->result);
    event->operation = pcmk__xe_get_copy(msg, PCMK__XA_ST_OP);

    // @COMPAT The API originally provided the result as a legacy return code
    event->result = pcmk_rc2legacy(stonith__result2rc(&event_private->result));

    // Some notification subtypes have additional information

    if (pcmk__str_eq(event->operation, PCMK__VALUE_ST_NOTIFY_FENCE,
                     pcmk__str_none)) {
        xmlNode *data = get_event_data_xml(msg, event->operation);

        if (data == NULL) {
            pcmk__err("No data for %s event", event->operation);
            pcmk__log_xml_notice(msg, "BadEvent");
        } else {
            event->origin = pcmk__xe_get_copy(data, PCMK__XA_ST_ORIGIN);
            event->action = pcmk__xe_get_copy(data, PCMK__XA_ST_DEVICE_ACTION);
            event->target = pcmk__xe_get_copy(data, PCMK__XA_ST_TARGET);
            event->executioner = pcmk__xe_get_copy(data, PCMK__XA_ST_DELEGATE);
            event->id = pcmk__xe_get_copy(data, PCMK__XA_ST_REMOTE_OP);
            event->client_origin = pcmk__xe_get_copy(data,
                                                     PCMK__XA_ST_CLIENTNAME);
            event->device = pcmk__xe_get_copy(data, PCMK__XA_ST_DEVICE_ID);
        }

    } else if (pcmk__str_any_of(event->operation,
                                STONITH_OP_DEVICE_ADD, STONITH_OP_DEVICE_DEL,
                                STONITH_OP_LEVEL_ADD, STONITH_OP_LEVEL_DEL,
                                NULL)) {
        xmlNode *data = get_event_data_xml(msg, event->operation);

        if (data == NULL) {
            pcmk__err("No data for %s event", event->operation);
            pcmk__log_xml_notice(msg, "BadEvent");
        } else {
            event->device = pcmk__xe_get_copy(data, PCMK__XA_ST_DEVICE_ID);
        }
    }

    return event;
}

static void
event_free(stonith_event_t * event)
{
    struct event_private *event_private = event->opaque;

    free(event->id);
    free(event->operation);
    free(event->origin);
    free(event->action);
    free(event->target);
    free(event->executioner);
    free(event->device);
    free(event->client_origin);
    pcmk__reset_result(&event_private->result);
    free(event->opaque);
    free(event);
}

static void
stonith_send_notification(gpointer data, gpointer user_data)
{
    struct notify_blob_s *blob = user_data;
    stonith_notify_client_t *entry = data;
    stonith_event_t *st_event = NULL;
    const char *event = NULL;

    if (blob->xml == NULL) {
        pcmk__warn("Skipping callback - NULL message");
        return;
    }

    event = pcmk__xe_get(blob->xml, PCMK__XA_SUBT);

    if (entry == NULL) {
        pcmk__warn("Skipping callback - NULL callback client");
        return;

    } else if (entry->delete) {
        pcmk__trace("Skipping callback - marked for deletion");
        return;

    } else if (entry->notify == NULL) {
        pcmk__warn("Skipping callback - NULL callback");
        return;

    } else if (!pcmk__str_eq(entry->event, event, pcmk__str_none)) {
        pcmk__trace("Skipping callback - event mismatch %p/%s vs. %s", entry, entry->event, event);
        return;
    }

    st_event = xml_to_event(blob->xml);

    pcmk__trace("Invoking callback for %p/%s event...", entry, event);
    // coverity[null_field]
    entry->notify(blob->stonith, st_event);
    pcmk__trace("Callback invoked...");

    event_free(st_event);
}

/*!
 * \internal
 * \brief Create and send an API request
 *
 * \param[in,out] stonith       Stonith connection
 * \param[in]     op            API operation to request
 * \param[in]     data          Data to attach to request
 * \param[out]    output_data   If not NULL, will be set to reply if synchronous
 * \param[in]     call_options  Bitmask of stonith_call_options to use
 * \param[in]     timeout       Error if not completed within this many seconds
 *
 * \return pcmk_ok (for synchronous requests) or positive call ID
 *         (for asynchronous requests) on success, -errno otherwise
 */
static int
stonith_send_command(stonith_t * stonith, const char *op, xmlNode * data, xmlNode ** output_data,
                     int call_options, int timeout)
{
    int rc = 0;
    int reply_id = -1;

    xmlNode *op_msg = NULL;
    xmlNode *op_reply = NULL;
    stonith_private_t *native = NULL;

    pcmk__assert((stonith != NULL) && (stonith->st_private != NULL)
                 && (op != NULL));
    native = stonith->st_private;

    if (output_data != NULL) {
        *output_data = NULL;
    }

    if ((stonith->state == stonith_disconnected) || (native->token == NULL)) {
        return -ENOTCONN;
    }

    /* Increment the call ID, which must be positive to avoid conflicting with
     * error codes. This shouldn't be a problem unless the client mucked with
     * it or the counter wrapped around.
     */
    stonith->call_id++;
    if (stonith->call_id < 1) {
        stonith->call_id = 1;
    }

    op_msg = stonith_create_op(stonith->call_id, native->token, op, data, call_options);
    if (op_msg == NULL) {
        return -EINVAL;
    }

    pcmk__xe_set_int(op_msg, PCMK__XA_ST_TIMEOUT, timeout);
    pcmk__trace("Sending %s message to fencer with timeout %ds", op, timeout);

    if (data) {
        const char *delay_s = pcmk__xe_get(data, PCMK__XA_ST_DELAY);

        if (delay_s) {
            pcmk__xe_set(op_msg, PCMK__XA_ST_DELAY, delay_s);
        }
    }

    {
        enum crm_ipc_flags ipc_flags = crm_ipc_flags_none;

        if (call_options & st_opt_sync_call) {
            pcmk__set_ipc_flags(ipc_flags, "fencing command",
                                crm_ipc_client_response);
        }
        rc = crm_ipc_send(native->ipc, op_msg, ipc_flags,
                          1000 * (timeout + 60), &op_reply);
    }
    pcmk__xml_free(op_msg);

    if (rc < 0) {
        pcmk__err("Couldn't perform %s operation (timeout=%ds): %s", op,
                  timeout, pcmk_strerror(rc));
        rc = -ECOMM;
        goto done;
    }

    pcmk__log_xml_trace(op_reply, "Reply");

    if (!(call_options & st_opt_sync_call)) {
        pcmk__trace("Async call %d, returning", stonith->call_id);
        pcmk__xml_free(op_reply);
        return stonith->call_id;
    }

    pcmk__xe_get_int(op_reply, PCMK__XA_ST_CALLID, &reply_id);

    if (reply_id == stonith->call_id) {
        pcmk__action_result_t result = PCMK__UNKNOWN_RESULT;

        pcmk__trace("Synchronous reply %d received", reply_id);

        stonith__xe_get_result(op_reply, &result);
        rc = pcmk_rc2legacy(stonith__result2rc(&result));
        pcmk__reset_result(&result);

        if ((call_options & st_opt_discard_reply) || output_data == NULL) {
            pcmk__trace("Discarding reply");

        } else {
            *output_data = op_reply;
            op_reply = NULL;    /* Prevent subsequent free */
        }

    } else if (reply_id <= 0) {
        pcmk__err("Received bad reply: No id set");
        pcmk__log_xml_err(op_reply, "Bad reply");
        pcmk__xml_free(op_reply);
        op_reply = NULL;
        rc = -ENOMSG;

    } else {
        pcmk__err("Received bad reply: %d (wanted %d)", reply_id,
                  stonith->call_id);
        pcmk__log_xml_err(op_reply, "Old reply");
        pcmk__xml_free(op_reply);
        op_reply = NULL;
        rc = -ENOMSG;
    }

  done:
    if (!crm_ipc_connected(native->ipc)) {
        pcmk__err("Fencer disconnected");
        free(native->token); native->token = NULL;
        stonith->state = stonith_disconnected;
    }

    pcmk__xml_free(op_reply);
    return rc;
}

/*!
 * \internal
 * \brief Process IPC messages for a fencer API connection
 *
 * This is used for testing purposes in scenarios that don't use a mainloop to
 * dispatch messages automatically.
 *
 * \param[in,out] stonith_api  Fencer API connetion object
 *
 * \return Standard Pacemaker return code
 */
int
stonith__api_dispatch(stonith_t *stonith_api)
{
    stonith_private_t *private = NULL;

    pcmk__assert(stonith_api != NULL);
    private = stonith_api->st_private;

    while (crm_ipc_ready(private->ipc)) {
        if (crm_ipc_read(private->ipc) > 0) {
            const char *msg = crm_ipc_buffer(private->ipc);

            stonith_dispatch_internal(msg, strlen(msg), stonith_api);
            pcmk__ipc_free_client_buffer(private->ipc);
        }

        if (!crm_ipc_connected(private->ipc)) {
            pcmk__err("Connection closed");
            return ENOTCONN;
        }
    }

    return pcmk_rc_ok;
}

static int
free_stonith_api(stonith_t *stonith)
{
    int rc = pcmk_ok;

    pcmk__trace("Destroying %p", stonith);

    if (stonith->state != stonith_disconnected) {
        pcmk__trace("Unregistering notifications and disconnecting %p first",
                    stonith);
        stonith->cmds->remove_notification(stonith, NULL);
        rc = stonith->cmds->disconnect(stonith);
    }

    if (stonith->state == stonith_disconnected) {
        stonith_private_t *private = stonith->st_private;

        pcmk__trace("Removing %u callbacks",
                    g_hash_table_size(private->stonith_op_callback_table));
        g_hash_table_destroy(private->stonith_op_callback_table);

        pcmk__trace("Destroying %u notification clients",
                    g_list_length(private->notify_list));
        g_list_free_full(private->notify_list, free);

        free(stonith->st_private);
        free(stonith->cmds);
        free(stonith);

    } else {
        pcmk__err("Not free'ing active connection: %s (%d)", pcmk_strerror(rc),
                  rc);
    }

    return rc;
}

static gboolean
is_fencing_param(gpointer key, gpointer value, gpointer user_data)
{
    return pcmk_stonith_param(key);
}

int
stonith__validate(stonith_t *st, int call_options, const char *rsc_id,
                  const char *agent, GHashTable *params, int timeout_sec,
                  char **output, char **error_output)
{
    int rc = pcmk_rc_ok;

    /* Use a dummy node name in case the agent requires a target. We assume the
     * actual target doesn't matter for validation purposes (if in practice,
     * that is incorrect, we will need to allow the caller to pass the target).
     */
    const char *target = "node1";
    char *host_arg = NULL;

    if (params != NULL) {
        const char *param = g_hash_table_lookup(params,
                                                PCMK_FENCING_HOST_ARGUMENT);

        host_arg = pcmk__str_copy(param);

        /* Remove special fencing params from the table before doing anything
         * else
         */
        g_hash_table_foreach_remove(params, is_fencing_param, NULL);
    }

#if PCMK__ENABLE_CIBSECRETS
    rc = pcmk__substitute_secrets(rsc_id, params);
    if (rc != pcmk_rc_ok) {
        pcmk__warn("Could not replace secret parameters for validation of %s: "
                   "%s",
                   agent, pcmk_rc_str(rc));
        // rc is standard return value, don't return it in this function
    }
#endif

    if (output) {
        *output = NULL;
    }
    if (error_output) {
        *error_output = NULL;
    }

    if (timeout_sec <= 0) {
        timeout_sec = PCMK_DEFAULT_ACTION_TIMEOUT_MS;
    }

    switch (get_namespace_from_agent(agent)) {
        case st_namespace_rhcs:
            rc = stonith__rhcs_validate(st, call_options, target, agent,
                                        params, host_arg, timeout_sec,
                                        output, error_output);
            rc = pcmk_legacy2rc(rc);
            break;

#if HAVE_STONITH_STONITH_H
        case st_namespace_lha:
            rc = stonith__lha_validate(st, call_options, target, agent,
                                       params, timeout_sec, output,
                                       error_output);
            rc = pcmk_legacy2rc(rc);
            break;
#endif

        case st_namespace_invalid:
            errno = ENOENT;
            rc = errno;

            if (error_output) {
                *error_output = pcmk__assert_asprintf("Agent %s not found",
                                                      agent);
            } else {
                pcmk__err("Agent %s not found", agent);
            }

            break;

        default:
            errno = EOPNOTSUPP;
            rc = errno;

            if (error_output) {
                *error_output = pcmk__assert_asprintf("Agent %s does not "
                                                      "support validation",
                                                      agent);
            } else {
                pcmk__err("Agent %s does not support validation", agent);
            }

            break;
    }

    free(host_arg);
    return rc;
}

static int
stonith_api_validate(stonith_t *st, int call_options, const char *rsc_id,
                     const char *namespace_s, const char *agent,
                     const stonith_key_value_t *params, int timeout_sec,
                     char **output, char **error_output)
{
    /* Validation should be done directly via the agent, so we can get it from
     * stonith_admin when the cluster is not running, which is important for
     * higher-level tools.
     */

    int rc = pcmk_ok;

    GHashTable *params_table = pcmk__strkey_table(free, free);

    // Convert parameter list to a hash table
    for (; params; params = params->next) {
        if (!pcmk_stonith_param(params->key)) {
            pcmk__insert_dup(params_table, params->key, params->value);
        }
    }

    rc = stonith__validate(st, call_options, rsc_id, agent, params_table,
                           timeout_sec, output, error_output);

    g_hash_table_destroy(params_table);
    return rc;
}

/*!
 * \internal
 * \brief Create a new fencer API connection object
 *
 * \return Newly allocated fencer API connection object, or \c NULL on
 *         allocation failure
 */
stonith_t *
stonith__api_new(void)
{
    stonith_t *new_stonith = NULL;
    stonith_private_t *private = NULL;

    new_stonith = calloc(1, sizeof(stonith_t));
    if (new_stonith == NULL) {
        return NULL;
    }

    private = calloc(1, sizeof(stonith_private_t));
    if (private == NULL) {
        free(new_stonith);
        return NULL;
    }
    new_stonith->st_private = private;

    private->stonith_op_callback_table = pcmk__intkey_table(stonith_destroy_op_callback);
    private->notify_list = NULL;
    private->notify_refcnt = 0;
    private->notify_deletes = FALSE;

    new_stonith->call_id = 1;
    new_stonith->state = stonith_disconnected;

    new_stonith->cmds = calloc(1, sizeof(stonith_api_operations_t));
    if (new_stonith->cmds == NULL) {
        free(new_stonith->st_private);
        free(new_stonith);
        return NULL;
    }

    new_stonith->cmds->free       = free_stonith_api;
    new_stonith->cmds->connect    = stonith_api_signon;
    new_stonith->cmds->disconnect = stonith_api_signoff;

    new_stonith->cmds->list       = stonith_api_list;
    new_stonith->cmds->monitor    = stonith_api_monitor;
    new_stonith->cmds->status     = stonith_api_status;
    new_stonith->cmds->fence      = stonith_api_fence;
    new_stonith->cmds->fence_with_delay = stonith_api_fence_with_delay;
    new_stonith->cmds->confirm    = stonith_api_confirm;
    new_stonith->cmds->history    = stonith_api_history;

    new_stonith->cmds->list_agents  = stonith_api_device_list;
    new_stonith->cmds->metadata     = stonith_api_device_metadata;

    new_stonith->cmds->query           = stonith_api_query;
    new_stonith->cmds->remove_device   = stonith_api_remove_device;
    new_stonith->cmds->register_device = stonith_api_register_device;

    new_stonith->cmds->remove_level          = stonith_api_remove_level;
    new_stonith->cmds->remove_level_full     = stonith_api_remove_level_full;
    new_stonith->cmds->register_level        = stonith_api_register_level;
    new_stonith->cmds->register_level_full   = stonith_api_register_level_full;

    new_stonith->cmds->remove_callback       = stonith_api_del_callback;
    new_stonith->cmds->register_callback     = stonith_api_add_callback;
    new_stonith->cmds->remove_notification   = stonith_api_del_notification;
    new_stonith->cmds->register_notification = stonith_api_add_notification;

    new_stonith->cmds->validate              = stonith_api_validate;

    return new_stonith;
}

/*!
 * \internal
 * \brief Free a fencer API connection object
 *
 * \param[in,out] stonith_api  Fencer API connection object
 */
void
stonith__api_free(stonith_t *stonith_api)
{
    pcmk__trace("Destroying %p", stonith_api);
    if (stonith_api != NULL) {
        stonith_api->cmds->free(stonith_api);
    }
}

/*!
 * \internal
 * \brief Connect to the fencer, retrying on failure
 *
 * \param[in,out] stonith       Fencer API connection object
 * \param[in]     name          Client name to use with fencer
 * \param[in]     max_attempts  Maximum number of attempts
 *
 * \return \c pcmk_rc_ok on success, or result of last attempt otherwise
 */
int
stonith__api_connect_retry(stonith_t *stonith_api, const char *name,
                           int max_attempts)
{
    int rc = EINVAL;    // if max_attempts is not positive

    for (int attempt = 1; attempt <= max_attempts; attempt++) {
        rc = stonith_api->cmds->connect(stonith_api, name, NULL);
        rc = pcmk_legacy2rc(rc);

        if (rc == pcmk_rc_ok) {
            return rc;
        }
        if (attempt < max_attempts) {
            pcmk__notice("Fencer connection attempt %d of %d failed "
                         "(retrying in 2s): %s " QB_XS " rc=%d",
                         attempt, max_attempts, pcmk_rc_str(rc), rc);
            sleep(2);
        }
    }
    pcmk__notice("Could not connect to fencer: %s " QB_XS " rc=%d",
                 pcmk_rc_str(rc), rc);
    return rc;
}

/*!
 * \internal
 * \brief Append a newly allocated STONITH key-value pair to a list
 *
 * \param[in,out] head   Head of key-value pair list (\c NULL for new list)
 * \param[in]     key    Key to add
 * \param[in]     value  Value to add
 *
 * \return Head of appended-to list (equal to \p head if \p head is not \c NULL)
 * \note The caller is responsible for freeing the return value using
 *       \c stonith__key_value_freeall().
 */
stonith_key_value_t *
stonith__key_value_add(stonith_key_value_t *head, const char *key,
                       const char *value)
{
    /* @COMPAT Replace this function with pcmk_prepend_nvpair(), and reverse the
     * list when finished adding to it; or with a hash table where order does
     * not matter
     */
    stonith_key_value_t *pair = pcmk__assert_alloc(1,
                                                   sizeof(stonith_key_value_t));

    pair->key = pcmk__str_copy(key);
    pair->value = pcmk__str_copy(value);

    if (head != NULL) {
        stonith_key_value_t *end = head;

        for (; end->next != NULL; end = end->next);
        end->next = pair;

    } else {
        head = pair;
    }

    return head;
}

/*!
 * \internal
 * \brief Free all items in a \c stonith_key_value_t list
 *
 * This means freeing the list itself with all of its nodes. Keys and values may
 * be freed depending on arguments.
 *
 * \param[in,out] head    Head of list
 * \param[in]     keys    If \c true, free all keys
 * \param[in]     values  If \c true, free all values
 */
void
stonith__key_value_freeall(stonith_key_value_t *head, bool keys, bool values)
{
    while (head != NULL) {
        stonith_key_value_t *next = head->next;

        if (keys) {
            free(head->key);
        }
        if (values) {
            free(head->value);
        }
        free(head);
        head = next;
    }
}

#define api_log_open() openlog("stonith-api", LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON)
#define api_log(level, fmt, args...) syslog(level, "%s: "fmt, __func__, args)

int
stonith_api_kick(uint32_t nodeid, const char *uname, int timeout, bool off)
{
    int rc = pcmk_ok;
    stonith_t *st = stonith__api_new();
    const char *action = off? PCMK_ACTION_OFF : PCMK_ACTION_REBOOT;

    api_log_open();
    if (st == NULL) {
        api_log(LOG_ERR, "API initialization failed, could not kick (%s) node %u/%s",
                action, nodeid, uname);
        return -EPROTO;
    }

    rc = st->cmds->connect(st, "stonith-api", NULL);
    if (rc != pcmk_ok) {
        api_log(LOG_ERR, "Connection failed, could not kick (%s) node %u/%s : %s (%d)",
                action, nodeid, uname, pcmk_strerror(rc), rc);
    } else {
        char *name = (uname == NULL)? pcmk__itoa(nodeid) : strdup(uname);
        int opts = 0;

        stonith__set_call_options(opts, name,
                                  st_opt_sync_call|st_opt_allow_self_fencing);
        if ((uname == NULL) && (nodeid > 0)) {
            stonith__set_call_options(opts, name, st_opt_cs_nodeid);
        }
        rc = st->cmds->fence(st, opts, name, action, timeout, 0);
        free(name);

        if (rc != pcmk_ok) {
            api_log(LOG_ERR, "Could not kick (%s) node %u/%s : %s (%d)",
                    action, nodeid, uname, pcmk_strerror(rc), rc);
        } else {
            api_log(LOG_NOTICE, "Node %u/%s kicked: %s", nodeid, uname, action);
        }
    }

    stonith__api_free(st);
    return rc;
}

time_t
stonith_api_time(uint32_t nodeid, const char *uname, bool in_progress)
{
    int rc = pcmk_ok;
    time_t when = 0;
    stonith_t *st = stonith__api_new();
    stonith_history_t *history = NULL, *hp = NULL;

    if (st == NULL) {
        api_log(LOG_ERR, "Could not retrieve fence history for %u/%s: "
                "API initialization failed", nodeid, uname);
        return when;
    }

    rc = st->cmds->connect(st, "stonith-api", NULL);
    if (rc != pcmk_ok) {
        api_log(LOG_NOTICE, "Connection failed: %s (%d)", pcmk_strerror(rc), rc);
    } else {
        int entries = 0;
        int progress = 0;
        int completed = 0;
        int opts = 0;
        char *name = (uname == NULL)? pcmk__itoa(nodeid) : strdup(uname);

        stonith__set_call_options(opts, name, st_opt_sync_call);
        if ((uname == NULL) && (nodeid > 0)) {
            stonith__set_call_options(opts, name, st_opt_cs_nodeid);
        }
        rc = st->cmds->history(st, opts, name, &history, 120);
        free(name);

        for (hp = history; hp; hp = hp->next) {
            entries++;
            if (in_progress) {
                progress++;
                if (hp->state != st_done && hp->state != st_failed) {
                    when = time(NULL);
                }

            } else if (hp->state == st_done) {
                completed++;
                if (hp->completed > when) {
                    when = hp->completed;
                }
            }
        }

        stonith__history_free(history);

        if(rc == pcmk_ok) {
            api_log(LOG_INFO, "Found %d entries for %u/%s: %d in progress, %d completed", entries, nodeid, uname, progress, completed);
        } else {
            api_log(LOG_ERR, "Could not retrieve fence history for %u/%s: %s (%d)", nodeid, uname, pcmk_strerror(rc), rc);
        }
    }

    stonith__api_free(st);

    if(when) {
        api_log(LOG_INFO, "Node %u/%s last kicked at: %ld", nodeid, uname, (long int)when);
    }
    return when;
}

/*!
 * \internal
 * \brief Check whether a fence agent with a given name exists
 *
 * \param[in] name     Agent name
 *
 * \retval \c true   If a fence agent named \p name exists
 * \retval \c false  Otherwise
 */
bool
stonith__agent_exists(const char *name)
{
    stonith_t *stonith_api = NULL;
    stonith_key_value_t *agents = NULL;
    bool rc = false;

    if (name == NULL) {
        return false;
    }

    stonith_api = stonith__api_new();
    if (stonith_api == NULL) {
        pcmk__err("Could not list fence agents: API memory allocation failed");
        return false;
    }

    // The list_agents method ignores its timeout argument
    stonith_api->cmds->list_agents(stonith_api, st_opt_sync_call, NULL, &agents,
                                   0);

    for (const stonith_key_value_t *iter = agents; iter != NULL;
         iter = iter->next) {
        if (pcmk__str_eq(iter->value, name, pcmk__str_none)) {
            rc = true;
            break;
        }
    }

    stonith__key_value_freeall(agents, true, true);
    stonith__api_free(stonith_api);
    return rc;
}

/*!
 * \internal
 * \brief Parse a target name from one line of a target list string
 *
 * \param[in]     line    One line of a target list string
 * \param[in]     len     String length of line
 * \param[in,out] output  List to add newly allocated target name to
 */
static void
parse_list_line(const char *line, int len, GList **output)
{
    size_t i = 0;
    size_t entry_start = 0;

    if (line == NULL) {
        return;
    }

    /* Skip complaints about additional parameters device doesn't understand
     *
     * @TODO Document or eliminate the implied restriction of target names
     */
    if (strstr(line, "invalid") || strstr(line, "variable")) {
        pcmk__debug("Skipping list output line: %s", line);
        return;
    }

    // Process line content, character by character
    for (i = 0; i <= len; i++) {

        if (isspace(line[i]) || (line[i] == ',') || (line[i] == ';')
            || (line[i] == '\0')) {
            // We've found a separator (i.e. the end of an entry)

            int rc = 0;
            char *entry = NULL;

            if (i == entry_start) {
                // Skip leading and sequential separators
                entry_start = i + 1;
                continue;
            }

            entry = pcmk__assert_alloc(i - entry_start + 1, sizeof(char));

            /* Read entry, stopping at first separator
             *
             * @TODO Document or eliminate these character restrictions
             */
            rc = sscanf(line + entry_start, "%[a-zA-Z0-9_-.]", entry);
            if (rc != 1) {
                pcmk__warn("Could not parse list output entry: %s "
                           QB_XS " entry_start=%d position=%d",
                           (line + entry_start), entry_start, i);
                free(entry);

            } else if (pcmk__strcase_any_of(entry, PCMK_ACTION_ON,
                                            PCMK_ACTION_OFF, NULL)) {
                /* Some agents print the target status in the list output,
                 * though none are known now (the separate list-status command
                 * is used for this, but it can also print "UNKNOWN"). To handle
                 * this possibility, skip such entries.
                 *
                 * @TODO Document or eliminate the implied restriction of target
                 * names.
                 */
                free(entry);

            } else {
                // We have a valid entry
                *output = g_list_append(*output, entry);
            }
            entry_start = i + 1;
        }
    }
}

/*!
 * \internal
 * \brief Parse a list of targets from a string
 *
 * \param[in] list_output  Target list as a string
 *
 * \return List of target names
 * \note The target list string format is flexible, to allow for user-specified
 *       lists such pcmk_host_list and the output of an agent's list action
 *       (whether direct or via the API, which escapes newlines). There may be
 *       multiple lines, separated by either a newline or an escaped newline
 *       (backslash n). Each line may have one or more target names, separated
 *       by any combination of whitespace, commas, and semi-colons. Lines
 *       containing "invalid" or "variable" will be ignored entirely. Target
 *       names "on" or "off" (case-insensitive) will be ignored. Target names
 *       may contain only alphanumeric characters, underbars (_), dashes (-),
 *       and dots (.) (if any other character occurs in the name, it and all
 *       subsequent characters in the name will be ignored).
 * \note The caller is responsible for freeing the result with
 *       g_list_free_full(result, free).
 */
GList *
stonith__parse_targets(const char *target_spec)
{
    GList *targets = NULL;

    if (target_spec != NULL) {
        size_t out_len = strlen(target_spec);
        size_t line_start = 0; // Starting index of line being processed

        for (size_t i = 0; i <= out_len; ++i) {
            if ((target_spec[i] == '\n') || (target_spec[i] == '\0')
                || ((target_spec[i] == '\\') && (target_spec[i + 1] == 'n'))) {
                // We've reached the end of one line of output

                int len = i - line_start;

                if (len > 0) {
                    char *line = strndup(target_spec + line_start, len);

                    pcmk__assert(line != NULL);

                    // cppcheck-suppress nullPointerOutOfMemory
                    line[len] = '\0'; // Because it might be a newline
                    parse_list_line(line, len, &targets);
                    free(line);
                }
                if (target_spec[i] == '\\') {
                    ++i; // backslash-n takes up two positions
                }
                line_start = i + 1;
            }
        }
    }
    return targets;
}

/*!
 * \internal
 * \brief Check whether a fencing failure was followed by an equivalent success
 *
 * \param[in] event        Fencing failure
 * \param[in] top_history  Complete fencing history (must be sorted by
 *                         stonith__sort_history() beforehand)
 *
 * \return The name of the node that executed the fencing if a later successful
 *         event exists, or NULL if no such event exists
 */
const char *
stonith__later_succeeded(const stonith_history_t *event,
                         const stonith_history_t *top_history)
{
    const char *other = NULL;

     for (const stonith_history_t *prev_hp = top_history;
          prev_hp != NULL; prev_hp = prev_hp->next) {
        if (prev_hp == event) {
            break;
        }
        if ((prev_hp->state == st_done) &&
            pcmk__str_eq(event->target, prev_hp->target, pcmk__str_casei) &&
            pcmk__str_eq(event->action, prev_hp->action, pcmk__str_none) &&
            ((event->completed < prev_hp->completed) ||
             ((event->completed == prev_hp->completed) && (event->completed_nsec < prev_hp->completed_nsec)))) {

            if ((event->delegate == NULL)
                || pcmk__str_eq(event->delegate, prev_hp->delegate,
                                pcmk__str_casei)) {
                // Prefer equivalent fencing by same executioner
                return prev_hp->delegate;

            } else if (other == NULL) {
                // Otherwise remember first successful executioner
                other = (prev_hp->delegate == NULL)? "some node" : prev_hp->delegate;
            }
        }
    }
    return other;
}

/*!
 * \internal
 * \brief Sort fencing history, pending first then by most recently completed
 *
 * \param[in,out] history    List of fencing actions
 *
 * \return New head of sorted \p history
 */
stonith_history_t *
stonith__sort_history(stonith_history_t *history)
{
    stonith_history_t *new = NULL, *pending = NULL, *hp, *np, *tmp;

    for (hp = history; hp; ) {
        tmp = hp->next;
        if ((hp->state == st_done) || (hp->state == st_failed)) {
            /* sort into new */
            if ((!new) || (hp->completed > new->completed) || 
                ((hp->completed == new->completed) && (hp->completed_nsec > new->completed_nsec))) {
                hp->next = new;
                new = hp;
            } else {
                np = new;
                do {
                    if ((!np->next) || (hp->completed > np->next->completed) ||
                        ((hp->completed == np->next->completed) && (hp->completed_nsec > np->next->completed_nsec))) {
                        hp->next = np->next;
                        np->next = hp;
                        break;
                    }
                    np = np->next;
                } while (1);
            }
        } else {
            /* put into pending */
            hp->next = pending;
            pending = hp;
        }
        hp = tmp;
    }

    /* pending actions don't have a completed-stamp so make them go front */
    if (pending) {
        stonith_history_t *last_pending = pending;

        while (last_pending->next) {
            last_pending = last_pending->next;
        }

        last_pending->next = new;
        new = pending;
    }
    return new;
}

/*!
 * \internal
 * \brief Return string equivalent of a fencing operation state value
 *
 * \param[in] state  Fencing operation state value
 *
 * \return Human-friendly string equivalent of \p state
 */
const char *
stonith__op_state_text(enum op_state state)
{
    // @COMPAT Move this to the fencer after dropping stonith_op_state_str()
    switch (state) {
        case st_query:
            return "querying";
        case st_exec:
            return "executing";
        case st_done:
            return "completed";
        case st_duplicate:
            return "duplicate";
        case st_failed:
            return "failed";
        default:
            return "unknown";
    }
}

stonith_history_t *
stonith__first_matching_event(stonith_history_t *history,
                              bool (*matching_fn)(stonith_history_t *, void *),
                              void *user_data)
{
    for (stonith_history_t *hp = history; hp; hp = hp->next) {
        if (matching_fn(hp, user_data)) {
            return hp;
        }
    }

    return NULL;
}

bool
stonith__event_state_pending(stonith_history_t *history, void *user_data)
{
    return history->state != st_failed && history->state != st_done;
}

bool
stonith__event_state_eq(stonith_history_t *history, void *user_data)
{
    return history->state == GPOINTER_TO_INT(user_data);
}

bool
stonith__event_state_neq(stonith_history_t *history, void *user_data)
{
    return history->state != GPOINTER_TO_INT(user_data);
}

/*!
 * \internal
 * \brief Check whether a given parameter exists in a fence agent's metadata
 *
 * \param[in] metadata  Agent metadata
 * \param[in] name      Parameter name
 *
 * \retval \c true   If \p name exists as a parameter in \p metadata
 * \retval \c false  Otherwise
 */
static bool
param_is_supported(xmlNode *metadata, const char *name)
{
    char *xpath_s = pcmk__assert_asprintf("//" PCMK_XE_PARAMETER
                                          "[@" PCMK_XA_NAME "='%s']",
                                          name);
    xmlXPathObject *xpath = pcmk__xpath_search(metadata->doc, xpath_s);
    bool supported = (pcmk__xpath_num_results(xpath) > 0);

    free(xpath_s);
    xmlXPathFreeObject(xpath);
    return supported;
}

/*!
 * \internal
 * \brief Get the default host argument based on a device's agent metadata
 *
 * If an agent supports the "plug" parameter, default to that. Otherwise default
 * to the "port" parameter if supported. Otherwise return \c NULL.
 *
 * \param[in] metadata  Agent metadata
 *
 * \return Parameter name for default host argument
 */
const char *
stonith__default_host_arg(xmlNode *metadata)
{
    CRM_CHECK(metadata != NULL, return NULL);

    if (param_is_supported(metadata, "plug")) {
        return "plug";
    }
    if (param_is_supported(metadata, "port")) {
        return "port";
    }
    return NULL;
}

/*!
 * \internal
 * \brief Retrieve fence agent meta-data asynchronously
 *
 * \param[in]     agent        Agent to execute
 * \param[in]     timeout_sec  Error if not complete within this time
 * \param[in]     callback     Function to call with result (this will always be
 *                             called, whether by this function directly or
 *                             later via the main loop, and on success the
 *                             metadata will be in its result argument's
 *                             action_stdout)
 * \param[in,out] user_data    User data to pass to callback
 *
 * \return Standard Pacemaker return code
 * \note The caller must use a main loop. This function is not a
 *       stonith_api_operations_t method because it does not need a stonith_t
 *       object and does not go through the fencer, but executes the agent
 *       directly.
 */
int
stonith__metadata_async(const char *agent, int timeout_sec,
                        void (*callback)(int pid,
                                         const pcmk__action_result_t *result,
                                         void *user_data),
                        void *user_data)
{
    switch (get_namespace_from_agent(agent)) {
        case st_namespace_rhcs:
            {
                stonith_action_t *action = NULL;
                int rc = pcmk_ok;

                action = stonith__action_create(agent, PCMK_ACTION_METADATA,
                                                NULL, timeout_sec, NULL, NULL,
                                                NULL);

                rc = stonith__execute_async(action, user_data, callback, NULL);
                if (rc != pcmk_ok) {
                    callback(0, stonith__action_result(action), user_data);
                    stonith__destroy_action(action);
                }
                return pcmk_legacy2rc(rc);
            }

#if HAVE_STONITH_STONITH_H
        case st_namespace_lha:
            // LHA metadata is simply synthesized, so simulate async
            {
                pcmk__action_result_t result = {
                    .exit_status = CRM_EX_OK,
                    .execution_status = PCMK_EXEC_DONE,
                    .exit_reason = NULL,
                    .action_stdout = NULL,
                    .action_stderr = NULL,
                };

                stonith__lha_metadata(agent, timeout_sec,
                                      &result.action_stdout);
                callback(0, &result, user_data);
                pcmk__reset_result(&result);
                return pcmk_rc_ok;
            }
#endif

        default:
            {
                pcmk__action_result_t result = {
                    .exit_status = CRM_EX_NOSUCH,
                    .execution_status = PCMK_EXEC_ERROR_HARD,
                    .exit_reason = pcmk__assert_asprintf("No such agent '%s'",
                                                         agent),
                    .action_stdout = NULL,
                    .action_stderr = NULL,
                };

                callback(0, &result, user_data);
                pcmk__reset_result(&result);
                return ENOENT;
            }
    }
}

/*!
 * \internal
 * \brief Return the exit status from an async action callback
 *
 * \param[in] data  Callback data
 *
 * \return Exit status from callback data
 */
int
stonith__exit_status(const stonith_callback_data_t *data)
{
    if ((data == NULL) || (data->opaque == NULL)) {
        return CRM_EX_ERROR;
    }
    return ((pcmk__action_result_t *) data->opaque)->exit_status;
}

/*!
 * \internal
 * \brief Return the execution status from an async action callback
 *
 * \param[in] data  Callback data
 *
 * \return Execution status from callback data
 */
int
stonith__execution_status(const stonith_callback_data_t *data)
{
    if ((data == NULL) || (data->opaque == NULL)) {
        return PCMK_EXEC_UNKNOWN;
    }
    return ((pcmk__action_result_t *) data->opaque)->execution_status;
}

/*!
 * \internal
 * \brief Return the exit reason from an async action callback
 *
 * \param[in] data  Callback data
 *
 * \return Exit reason from callback data
 */
const char *
stonith__exit_reason(const stonith_callback_data_t *data)
{
    if ((data == NULL) || (data->opaque == NULL)) {
        return NULL;
    }
    return ((pcmk__action_result_t *) data->opaque)->exit_reason;
}

/*!
 * \internal
 * \brief Return the exit status from an event notification
 *
 * \param[in] event  Event
 *
 * \return Exit status from event
 */
int
stonith__event_exit_status(const stonith_event_t *event)
{
    if ((event == NULL) || (event->opaque == NULL)) {
        return CRM_EX_ERROR;
    } else {
        struct event_private *event_private = event->opaque;

        return event_private->result.exit_status;
    }
}

/*!
 * \internal
 * \brief Return the execution status from an event notification
 *
 * \param[in] event  Event
 *
 * \return Execution status from event
 */
int
stonith__event_execution_status(const stonith_event_t *event)
{
    if ((event == NULL) || (event->opaque == NULL)) {
        return PCMK_EXEC_UNKNOWN;
    } else {
        struct event_private *event_private = event->opaque;

        return event_private->result.execution_status;
    }
}

/*!
 * \internal
 * \brief Return the exit reason from an event notification
 *
 * \param[in] event  Event
 *
 * \return Exit reason from event
 */
const char *
stonith__event_exit_reason(const stonith_event_t *event)
{
    if ((event == NULL) || (event->opaque == NULL)) {
        return NULL;
    } else {
        struct event_private *event_private = event->opaque;

        return event_private->result.exit_reason;
    }
}

/*!
 * \internal
 * \brief Return a human-friendly description of a fencing event
 *
 * \param[in] event  Event to describe
 *
 * \return Newly allocated string with description of \p event
 * \note The caller is responsible for freeing the return value.
 *       This function asserts on memory errors and never returns NULL.
 */
char *
stonith__event_description(const stonith_event_t *event)
{
    // Use somewhat readable defaults
    const char *origin = pcmk__s(event->client_origin, "a client");
    const char *origin_node = pcmk__s(event->origin, "a node");
    const char *executioner = pcmk__s(event->executioner, "the cluster");
    const char *device = pcmk__s(event->device, "unknown");
    const char *action = pcmk__s(event->action, event->operation);
    const char *target = pcmk__s(event->target, "no node");
    const char *reason = stonith__event_exit_reason(event);
    const char *status;

    if (action == NULL) {
        action = "(unknown)";
    }

    if (stonith__event_execution_status(event) != PCMK_EXEC_DONE) {
        status = pcmk_exec_status_str(stonith__event_execution_status(event));
    } else if (stonith__event_exit_status(event) != CRM_EX_OK) {
        status = pcmk_exec_status_str(PCMK_EXEC_ERROR);
    } else {
        status = crm_exit_str(CRM_EX_OK);
    }

    if (pcmk__str_eq(event->operation, PCMK__VALUE_ST_NOTIFY_HISTORY,
                     pcmk__str_none)) {
        return pcmk__assert_asprintf("Fencing history may have changed");

    } else if (pcmk__str_eq(event->operation, STONITH_OP_DEVICE_ADD,
                            pcmk__str_none)) {
        return pcmk__assert_asprintf("A fencing device (%s) was added", device);

    } else if (pcmk__str_eq(event->operation, STONITH_OP_DEVICE_DEL,
                            pcmk__str_none)) {
        return pcmk__assert_asprintf("A fencing device (%s) was removed",
                                     device);

    } else if (pcmk__str_eq(event->operation, STONITH_OP_LEVEL_ADD,
                            pcmk__str_none)) {
        return pcmk__assert_asprintf("A fencing topology level (%s) was added",
                                     device);

    } else if (pcmk__str_eq(event->operation, STONITH_OP_LEVEL_DEL,
                            pcmk__str_none)) {
        return pcmk__assert_asprintf("A fencing topology level (%s) was "
                                     "removed",
                                     device);
    }

    // event->operation should be PCMK__VALUE_ST_NOTIFY_FENCE at this point

    return pcmk__assert_asprintf("Operation %s of %s by %s for %s@%s: %s%s%s%s "
                                 "(ref=%s)",
                                 action, target, executioner, origin,
                                 origin_node, status,
                                 ((reason == NULL)? "" : " ("),
                                 pcmk__s(reason, ""),
                                 ((reason == NULL)? "" : ")"),
                                 pcmk__s(event->id, "(none)"));
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

// See comments in stonith-ng.h for why we re-declare before defining

stonith_t *stonith_api_new(void);

stonith_t *
stonith_api_new(void)
{
    return stonith__api_new();
}

void stonith_api_delete(stonith_t *stonith);

void
stonith_api_delete(stonith_t *stonith)
{
    stonith__api_free(stonith);
}

static void
stonith_dump_pending_op(gpointer key, gpointer value, gpointer user_data)
{
    int call = GPOINTER_TO_INT(key);
    stonith_callback_client_t *blob = value;

    pcmk__debug("Call %d (%s): pending", call, pcmk__s(blob->id, "no ID"));
}

void stonith_dump_pending_callbacks(stonith_t *stonith);

void
stonith_dump_pending_callbacks(stonith_t *stonith)
{
    stonith_private_t *private = stonith->st_private;

    if (private->stonith_op_callback_table == NULL) {
        return;
    }
    return g_hash_table_foreach(private->stonith_op_callback_table,
                                stonith_dump_pending_op, NULL);
}

bool stonith_dispatch(stonith_t *stonith_api);

bool
stonith_dispatch(stonith_t *stonith_api)
{
    return (stonith__api_dispatch(stonith_api) == pcmk_rc_ok);
}

stonith_key_value_t *stonith_key_value_add(stonith_key_value_t *head,
                                           const char *key, const char *value);

stonith_key_value_t *
stonith_key_value_add(stonith_key_value_t *head, const char *key,
                      const char *value)
{
    return stonith__key_value_add(head, key, value);
}

void stonith_key_value_freeall(stonith_key_value_t *head, int keys, int values);

void
stonith_key_value_freeall(stonith_key_value_t *head, int keys, int values)
{
    stonith__key_value_freeall(head, (keys != 0), (values != 0));
}

void stonith_history_free(stonith_history_t *head);

void
stonith_history_free(stonith_history_t *head)
{
    stonith__history_free(head);
}

int stonith_api_connect_retry(stonith_t *st, const char *name,
                              int max_attempts);

int
stonith_api_connect_retry(stonith_t *st, const char *name, int max_attempts)
{
    return pcmk_rc2legacy(stonith__api_connect_retry(st, name, max_attempts));
}

const char *stonith_op_state_str(enum op_state state);

const char *
stonith_op_state_str(enum op_state state)
{
    return stonith__op_state_text(state);
}

bool stonith_agent_exists(const char *agent, int timeout);

bool
stonith_agent_exists(const char *agent, int timeout)
{
    return stonith__agent_exists(agent);
}

const char *stonith_action_str(const char *action);

const char *
stonith_action_str(const char *action)
{
    if (action == NULL) {
        return "fencing";
    } else if (strcmp(action, PCMK_ACTION_ON) == 0) {
        return "unfencing";
    } else if (strcmp(action, PCMK_ACTION_OFF) == 0) {
        return "turning off";
    } else {
        return action;
    }
}

enum stonith_namespace stonith_text2namespace(const char *namespace_s);

enum stonith_namespace
stonith_text2namespace(const char *namespace_s)
{
    return parse_namespace(namespace_s);
}

const char *stonith_namespace2text(enum stonith_namespace st_namespace);

const char *
stonith_namespace2text(enum stonith_namespace st_namespace)
{
    return namespace_text(st_namespace);
}

enum stonith_namespace stonith_get_namespace(const char *agent,
                                             const char *namespace_s);

enum stonith_namespace
stonith_get_namespace(const char *agent, const char *namespace_s)
{
    if (pcmk__str_eq(namespace_s, "internal", pcmk__str_none)) {
        return st_namespace_internal;
    }
    return get_namespace_from_agent(agent);
}

// LCOV_EXCL_STOP
// End deprecated API
