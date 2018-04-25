/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/stat.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/msg_xml.h>

#include <tengine.h>
#include <controld_fsa.h>

#include <crm/cluster.h>        /* For ONLINESTATUS etc */

void te_update_confirm(const char *event, xmlNode * msg);

extern char *te_uuid;
gboolean shuttingdown = FALSE;
crm_graph_t *transition_graph;
crm_trigger_t *transition_trigger = NULL;

static unsigned long int stonith_max_attempts = 10;

/* #define rsc_op_template "//"XML_TAG_DIFF_ADDED"//"XML_TAG_CIB"//"XML_CIB_TAG_STATE"[@uname='%s']"//"XML_LRM_TAG_RSC_OP"[@id='%s]" */
#define rsc_op_template "//"XML_TAG_DIFF_ADDED"//"XML_TAG_CIB"//"XML_LRM_TAG_RSC_OP"[@id='%s']"

static const char *
get_node_id(xmlNode * rsc_op)
{
    xmlNode *node = rsc_op;

    while (node != NULL && safe_str_neq(XML_CIB_TAG_STATE, TYPE(node))) {
        node = node->parent;
    }

    CRM_CHECK(node != NULL, return NULL);
    return ID(node);
}

void
update_stonith_max_attempts(const char* value)
{
    if (safe_str_eq(value, CRM_INFINITY_S)) {
       stonith_max_attempts = CRM_SCORE_INFINITY;
    }
    else {
       stonith_max_attempts = crm_int_helper(value, NULL);
    }
}
static void
te_update_diff_v1(const char *event, xmlNode *diff)
{
    int lpc, max;
    xmlXPathObject *xpathObj = NULL;

    CRM_CHECK(diff != NULL, return);

    xml_log_patchset(LOG_TRACE, __FUNCTION__, diff);
    if (cib_config_changed(NULL, NULL, &diff)) {
        abort_transition(INFINITY, tg_restart, "Non-status change", diff);
        goto bail;              /* configuration changed */
    }

    /* Tickets Attributes - Added/Updated */
    xpathObj =
        xpath_search(diff,
                     "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_ADDED "//" XML_CIB_TAG_TICKETS);
    if (numXpathResults(xpathObj) > 0) {
        xmlNode *aborted = getXpathResult(xpathObj, 0);

        abort_transition(INFINITY, tg_restart, "Ticket attribute: update", aborted);
        goto bail;

    }
    freeXpathObject(xpathObj);

    /* Tickets Attributes - Removed */
    xpathObj =
        xpath_search(diff,
                     "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_REMOVED "//" XML_CIB_TAG_TICKETS);
    if (numXpathResults(xpathObj) > 0) {
        xmlNode *aborted = getXpathResult(xpathObj, 0);

        abort_transition(INFINITY, tg_restart, "Ticket attribute: removal", aborted);
        goto bail;
    }
    freeXpathObject(xpathObj);

    /* Transient Attributes - Added/Updated */
    xpathObj =
        xpath_search(diff,
                     "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_ADDED "//"
                     XML_TAG_TRANSIENT_NODEATTRS "//" XML_CIB_TAG_NVPAIR);
    max = numXpathResults(xpathObj);

    for (lpc = 0; lpc < max; lpc++) {
        xmlNode *attr = getXpathResult(xpathObj, lpc);
        const char *name = crm_element_value(attr, XML_NVPAIR_ATTR_NAME);
        const char *value = NULL;

        if (safe_str_eq(CRM_OP_PROBED, name)) {
            value = crm_element_value(attr, XML_NVPAIR_ATTR_VALUE);
        }

        if (crm_is_true(value) == FALSE) {
            abort_transition(INFINITY, tg_restart, "Transient attribute: update", attr);
            crm_log_xml_trace(attr, "Abort");
            goto bail;
        }
    }

    freeXpathObject(xpathObj);

    /* Transient Attributes - Removed */
    xpathObj =
        xpath_search(diff,
                     "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_REMOVED "//"
                     XML_TAG_TRANSIENT_NODEATTRS);
    if (numXpathResults(xpathObj) > 0) {
        xmlNode *aborted = getXpathResult(xpathObj, 0);

        abort_transition(INFINITY, tg_restart, "Transient attribute: removal", aborted);
        goto bail;

    }
    freeXpathObject(xpathObj);

    /*
     * Updates by, or in response to, TE actions will never contain updates
     * for more than one resource at a time, so such updates indicate an
     * LRM refresh.
     *
     * In that case, start a new transition rather than check each result
     * individually, which can result in _huge_ speedups in large clusters.
     *
     * Unfortunately, we can only do so when there are no pending actions.
     * Otherwise, we could mistakenly throw away those results here, and
     * the cluster will stall waiting for them and time out the operation.
     */
    if (transition_graph->pending == 0) {
        xpathObj = xpath_search(diff,
                                "//" F_CIB_UPDATE_RESULT
                                "//" XML_TAG_DIFF_ADDED
                                "//" XML_LRM_TAG_RESOURCE);
        max = numXpathResults(xpathObj);
        if (max > 1) {
            crm_debug("Ignoring resource operation updates due to history refresh of %d resources",
                      max);
            crm_log_xml_trace(diff, "lrm-refresh");
            abort_transition(INFINITY, tg_restart, "History refresh", NULL);
            goto bail;
        }
        freeXpathObject(xpathObj);
    }

    /* Process operation updates */
    xpathObj =
        xpath_search(diff,
                     "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_ADDED "//" XML_LRM_TAG_RSC_OP);
    max = numXpathResults(xpathObj);
    if (max > 0) {
        int lpc = 0;

        for (lpc = 0; lpc < max; lpc++) {
            xmlNode *rsc_op = getXpathResult(xpathObj, lpc);
            const char *node = get_node_id(rsc_op);

            process_graph_event(rsc_op, node);
        }
    }
    freeXpathObject(xpathObj);

    /* Detect deleted (as opposed to replaced or added) actions - eg. crm_resource -C */
    xpathObj = xpath_search(diff, "//" XML_TAG_DIFF_REMOVED "//" XML_LRM_TAG_RSC_OP);
    max = numXpathResults(xpathObj);
    for (lpc = 0; lpc < max; lpc++) {
        int path_max = 0;
        const char *op_id = NULL;
        char *rsc_op_xpath = NULL;
        xmlXPathObject *op_match = NULL;
        xmlNode *match = getXpathResult(xpathObj, lpc);

        CRM_LOG_ASSERT(match != NULL);
        if(match == NULL) { continue; };

        op_id = ID(match);

        path_max = strlen(rsc_op_template) + strlen(op_id) + 1;
        rsc_op_xpath = calloc(1, path_max);
        snprintf(rsc_op_xpath, path_max, rsc_op_template, op_id);

        op_match = xpath_search(diff, rsc_op_xpath);
        if (numXpathResults(op_match) == 0) {
            /* Prevent false positives by matching cancelations too */
            const char *node = get_node_id(match);
            crm_action_t *cancelled = get_cancel_action(op_id, node);

            if (cancelled == NULL) {
                crm_debug("No match for deleted action %s (%s on %s)", rsc_op_xpath, op_id,
                          node);
                abort_transition(INFINITY, tg_restart, "Resource op removal", match);
                freeXpathObject(op_match);
                free(rsc_op_xpath);
                goto bail;

            } else {
                crm_debug("Deleted lrm_rsc_op %s on %s was for graph event %d",
                          op_id, node, cancelled->id);
            }
        }

        freeXpathObject(op_match);
        free(rsc_op_xpath);
    }

  bail:
    freeXpathObject(xpathObj);
}

static void
process_lrm_resource_diff(xmlNode *lrm_resource, const char *node)
{
    for (xmlNode *rsc_op = __xml_first_child(lrm_resource); rsc_op != NULL;
         rsc_op = __xml_next(rsc_op)) {
        process_graph_event(rsc_op, node);
    }
}

static void
process_resource_updates(const char *node, xmlNode *xml, xmlNode *change,
                         const char *op, const char *xpath)
{
    xmlNode *rsc = NULL;

    if (xml == NULL) {
        return;

    } else if (strcmp((const char*)xml->name, XML_CIB_TAG_LRM) == 0) {
        xml = first_named_child(xml, XML_LRM_TAG_RESOURCES);
        crm_trace("Got %p in %s", xml, XML_CIB_TAG_LRM);
    }

    CRM_ASSERT(strcmp((const char*)xml->name, XML_LRM_TAG_RESOURCES) == 0);

    /*
     * Updates by, or in response to, TE actions will never contain updates
     * for more than one resource at a time, so such updates indicate an
     * LRM refresh.
     *
     * In that case, start a new transition rather than check each result
     * individually, which can result in _huge_ speedups in large clusters.
     *
     * Unfortunately, we can only do so when there are no pending actions.
     * Otherwise, we could mistakenly throw away those results here, and
     * the cluster will stall waiting for them and time out the operation.
     */
    if ((transition_graph->pending == 0)
        && xml->children && xml->children->next) {

        crm_log_xml_trace(change, "lrm-refresh");
        abort_transition(INFINITY, tg_restart, "History refresh", NULL);
        return;
    }

    for (rsc = __xml_first_child(xml); rsc != NULL; rsc = __xml_next(rsc)) {
        crm_trace("Processing %s", ID(rsc));
        process_lrm_resource_diff(rsc, node);
    }
}

#define NODE_PATT "/lrm[@id="
static char *get_node_from_xpath(const char *xpath) 
{
    char *nodeid = NULL;
    char *tmp = strstr(xpath, NODE_PATT);

    if(tmp) {
        tmp += strlen(NODE_PATT);
        tmp += 1;

        nodeid = strdup(tmp);
        tmp = strstr(nodeid, "\'");
        CRM_ASSERT(tmp);
        tmp[0] = 0;
    }
    return nodeid;
}

static char *extract_node_uuid(const char *xpath) 
{
    char *mutable_path = strdup(xpath);
    char *node_uuid = NULL;
    char *search = NULL;
    char *match = NULL;

    match = strstr(mutable_path, "node_state[@id=\'");
    if (match == NULL) {
        free(mutable_path);
        return NULL;
    }
    match += strlen("node_state[@id=\'");

    search = strchr(match, '\'');
    if (search == NULL) {
        free(mutable_path);
        return NULL;
    }
    search[0] = 0;

    node_uuid = strdup(match);
    free(mutable_path);
    return node_uuid;
}

static void
abort_unless_down(const char *xpath, const char *op, xmlNode *change,
                  const char *reason)
{
    char *node_uuid = NULL;
    crm_action_t *down = NULL;

    if(safe_str_neq(op, "delete")) {
        abort_transition(INFINITY, tg_restart, reason, change);
        return;
    }

    node_uuid = extract_node_uuid(xpath);
    if(node_uuid == NULL) {
        crm_err("Could not extract node ID from %s", xpath);
        abort_transition(INFINITY, tg_restart, reason, change);
        return;
    }

    down = match_down_event(node_uuid);
    if (down == NULL) {
        crm_trace("Not expecting %s to be down (%s)", node_uuid, xpath);
        abort_transition(INFINITY, tg_restart, reason, change);
    } else {
        crm_trace("Expecting changes to %s (%s)", node_uuid, xpath);
    }
    free(node_uuid);
}

static void
process_op_deletion(const char *xpath, xmlNode *change)
{
    char *mutable_key = strdup(xpath);
    char *key;
    char *node_uuid;
    crm_action_t *cancel = NULL;

    // Extract the part of xpath between last pair of single quotes
    key = strrchr(mutable_key, '\'');
    if (key != NULL) {
        *key = '\0';
        key = strrchr(mutable_key, '\'');
    }
    if (key == NULL) {
        crm_warn("Ignoring malformed CIB update (resource deletion of %s)",
                 xpath);
        free(mutable_key);
        return;
    }
    ++key;

    node_uuid = extract_node_uuid(xpath);
    cancel = get_cancel_action(key, node_uuid);
    if (cancel) {
        crm_info("Cancellation of %s on %s confirmed (%d)",
                 key, node_uuid, cancel->id);
        stop_te_timer(cancel->timer);
        te_action_confirmed(cancel);
        update_graph(transition_graph, cancel);
        trigger_graph();
    } else {
        abort_transition(INFINITY, tg_restart, "Resource operation removal",
                         change);
    }
    free(mutable_key);
    free(node_uuid);
}

static void
process_delete_diff(const char *xpath, const char *op, xmlNode *change)
{
    if (strstr(xpath, "/" XML_LRM_TAG_RSC_OP "[")) {
        process_op_deletion(xpath, change);

    } else if (strstr(xpath, "/" XML_CIB_TAG_LRM "[")) {
        abort_unless_down(xpath, op, change, "Resource state removal");

    } else if (strstr(xpath, "/" XML_CIB_TAG_STATE "[")) {
        abort_unless_down(xpath, op, change, "Node state removal");

    } else {
        crm_trace("Ignoring delete of %s", xpath);
    }
}

static void
process_node_state_diff(xmlNode *state, xmlNode *change, const char *op,
                        const char *xpath)
{
    xmlNode *lrm = first_named_child(state, XML_CIB_TAG_LRM);

    process_resource_updates(ID(state), lrm, change, op, xpath);
}

static void
process_status_diff(xmlNode *status, xmlNode *change, const char *op,
                    const char *xpath)
{
    for (xmlNode *state = __xml_first_child(status); state != NULL;
         state = __xml_next(state)) {
        process_node_state_diff(state, change, op, xpath);
    }
}

static void
process_cib_diff(xmlNode *cib, xmlNode *change, const char *op,
                 const char *xpath)
{
    xmlNode *status = first_named_child(cib, XML_CIB_TAG_STATUS);
    xmlNode *config = first_named_child(cib, XML_CIB_TAG_CONFIGURATION);

    if (status) {
        process_status_diff(status, change, op, xpath);
    }
    if (config) {
        abort_transition(INFINITY, tg_restart,
                         "Non-status-only change", change);
    }
}

static void
te_update_diff_v2(xmlNode *diff)
{
    crm_log_xml_trace(diff, "Patch:Raw");

    for (xmlNode *change = __xml_first_child(diff); change != NULL;
         change = __xml_next(change)) {

        xmlNode *match = NULL;
        const char *name = NULL;
        const char *xpath = crm_element_value(change, XML_DIFF_PATH);

        // Possible ops: create, modify, delete, move
        const char *op = crm_element_value(change, XML_DIFF_OP);

        // Ignore uninteresting updates
        if (op == NULL) {
            continue;

        } else if (xpath == NULL) {
            crm_trace("Ignoring %s change for version field", op);
            continue;

        } else if (strcmp(op, "move") == 0) {
            crm_trace("Ignoring move change at %s", xpath);
            continue;
        }

        // Find the result of create/modify ops
        if (strcmp(op, "create") == 0) {
            match = change->children;

        } else if (strcmp(op, "modify") == 0) {
            match = first_named_child(change, XML_DIFF_RESULT);
            if(match) {
                match = match->children;
            }

        } else if (strcmp(op, "delete") != 0) {
            crm_warn("Ignoring malformed CIB update (%s operation on %s is unrecognized)",
                     op, xpath);
            continue;
        }

        if (match) {
            if (match->type == XML_COMMENT_NODE) {
                crm_trace("Ignoring %s operation for comment at %s", op, xpath);
                continue;
            }
            name = (const char *)match->name;
        }

        crm_trace("Handling %s operation for %s%s%s",
                  op, (xpath? xpath : "CIB"),
                  (name? " matched by " : ""), (name? name : ""));

        if (strstr(xpath, "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION)) {
            abort_transition(INFINITY, tg_restart, "Configuration change",
                             change);
            break; // Won't be packaged with operation results we may be waiting for

        } else if (strstr(xpath, "/" XML_CIB_TAG_TICKETS)
                   || safe_str_eq(name, XML_CIB_TAG_TICKETS)) {
            abort_transition(INFINITY, tg_restart, "Ticket attribute change", change);
            break; // Won't be packaged with operation results we may be waiting for

        } else if (strstr(xpath, "/" XML_TAG_TRANSIENT_NODEATTRS "[")
                   || safe_str_eq(name, XML_TAG_TRANSIENT_NODEATTRS)) {
            abort_unless_down(xpath, op, change, "Transient attribute change");
            break; // Won't be packaged with operation results we may be waiting for

        } else if (strcmp(op, "delete") == 0) {
            process_delete_diff(xpath, op, change);

        } else if (name == NULL) {
            crm_warn("Ignoring malformed CIB update (%s at %s has no result)",
                     op, xpath);

        } else if (strcmp(name, XML_TAG_CIB) == 0) {
            process_cib_diff(match, change, op, xpath);

        } else if (strcmp(name, XML_CIB_TAG_STATUS) == 0) {
            process_status_diff(match, change, op, xpath);

        } else if (strcmp(name, XML_CIB_TAG_STATE) == 0) {
            process_node_state_diff(match, change, op, xpath);

        } else if (strcmp(name, XML_CIB_TAG_LRM) == 0) {
            process_resource_updates(ID(match), match, change, op, xpath);

        } else if (strcmp(name, XML_LRM_TAG_RESOURCES) == 0) {
            char *local_node = get_node_from_xpath(xpath);

            process_resource_updates(local_node, match, change, op, xpath);
            free(local_node);

        } else if (strcmp(name, XML_LRM_TAG_RESOURCE) == 0) {
            char *local_node = get_node_from_xpath(xpath);

            process_lrm_resource_diff(match, local_node);
            free(local_node);

        } else if (strcmp(name, XML_LRM_TAG_RSC_OP) == 0) {
            char *local_node = get_node_from_xpath(xpath);

            process_graph_event(match, local_node);
            free(local_node);

        } else {
            crm_warn("Ignoring malformed CIB update (%s at %s has unrecognized result %s)",
                     op, xpath, name);
        }
    }
}

void
te_update_diff(const char *event, xmlNode * msg)
{
    xmlNode *diff = NULL;
    const char *op = NULL;
    int rc = -EINVAL;
    int format = 1;
    int p_add[] = { 0, 0, 0 };
    int p_del[] = { 0, 0, 0 };

    CRM_CHECK(msg != NULL, return);
    crm_element_value_int(msg, F_CIB_RC, &rc);

    if (transition_graph == NULL) {
        crm_trace("No graph");
        return;

    } else if (rc < pcmk_ok) {
        crm_trace("Filter rc=%d (%s)", rc, pcmk_strerror(rc));
        return;

    } else if (transition_graph->complete
               && fsa_state != S_IDLE
               && fsa_state != S_TRANSITION_ENGINE
               && fsa_state != S_POLICY_ENGINE) {
        crm_trace("Filter state=%s, complete=%d", fsa_state2string(fsa_state),
                  transition_graph->complete);
        return;
    }

    op = crm_element_value(msg, F_CIB_OPERATION);
    diff = get_message_xml(msg, F_CIB_UPDATE_RESULT);

    xml_patch_versions(diff, p_add, p_del);
    crm_debug("Processing (%s) diff: %d.%d.%d -> %d.%d.%d (%s)", op,
              p_del[0], p_del[1], p_del[2], p_add[0], p_add[1], p_add[2],
              fsa_state2string(fsa_state));

    crm_element_value_int(diff, "format", &format);
    switch (format) {
        case 1:
            te_update_diff_v1(event, diff);
            break;
        case 2:
            te_update_diff_v2(diff);
            break;
        default:
            crm_warn("Ignoring malformed CIB update (unknown patch format %d)",
                     format);
    }
}

gboolean
process_te_message(xmlNode * msg, xmlNode * xml_data)
{
    const char *from = crm_element_value(msg, F_ORIG);
    const char *sys_to = crm_element_value(msg, F_CRM_SYS_TO);
    const char *sys_from = crm_element_value(msg, F_CRM_SYS_FROM);
    const char *ref = crm_element_value(msg, F_CRM_REFERENCE);
    const char *op = crm_element_value(msg, F_CRM_TASK);
    const char *type = crm_element_value(msg, F_CRM_MSG_TYPE);

    crm_trace("Processing %s (%s) message", op, ref);
    crm_log_xml_trace(msg, "ipc");

    if (op == NULL) {
        /* error */

    } else if (sys_to == NULL || strcasecmp(sys_to, CRM_SYSTEM_TENGINE) != 0) {
        crm_trace("Bad sys-to %s", crm_str(sys_to));
        return FALSE;

    } else if (safe_str_eq(op, CRM_OP_INVOKE_LRM)
               && safe_str_eq(sys_from, CRM_SYSTEM_LRMD)
/* 		  && safe_str_eq(type, XML_ATTR_RESPONSE) */
        ) {
        xmlXPathObject *xpathObj = NULL;

        crm_log_xml_trace(msg, "Processing (N)ACK");
        crm_debug("Processing (N)ACK %s from %s", crm_element_value(msg, F_CRM_REFERENCE), from);

        xpathObj = xpath_search(xml_data, "//" XML_LRM_TAG_RSC_OP);
        if (numXpathResults(xpathObj)) {
            int lpc = 0, max = numXpathResults(xpathObj);

            for (lpc = 0; lpc < max; lpc++) {
                xmlNode *rsc_op = getXpathResult(xpathObj, lpc);
                const char *node = get_node_id(rsc_op);

                process_graph_event(rsc_op, node);
            }
            freeXpathObject(xpathObj);

        } else {
            crm_log_xml_err(msg, "Invalid (N)ACK");
            freeXpathObject(xpathObj);
            return FALSE;
        }

    } else {
        crm_err("Unknown command: %s::%s from %s", type, op, sys_from);
    }

    crm_trace("finished processing message");

    return TRUE;
}

GHashTable *stonith_failures = NULL;
struct st_fail_rec {
    int count;
};

static gboolean
too_many_st_failures(const char *target)
{
    GHashTableIter iter;
    const char *key = NULL;
    struct st_fail_rec *value = NULL;

    if (stonith_failures == NULL) {
        return FALSE;
    }

    if (target == NULL) {
        g_hash_table_iter_init(&iter, stonith_failures);
        while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
            if (value->count >= stonith_max_attempts) {
                target = (const char*)key;
                goto too_many;
            }
        }
    } else {
        value = g_hash_table_lookup(stonith_failures, target);
        if ((value != NULL) && (value->count >= stonith_max_attempts)) {
            goto too_many;
        }
    }
    return FALSE;

too_many:
    crm_warn("Too many failures (%d) to fence %s, giving up",
             value->count, target);
    return TRUE;
}

/*!
 * \internal
 * \brief Reset a stonith fail count
 *
 * \param[in] target  Name of node to reset, or NULL for all
 */
void
st_fail_count_reset(const char *target)
{
    if (stonith_failures == NULL) {
        return;
    }

    if (target) {
        struct st_fail_rec *rec = NULL;

        rec = g_hash_table_lookup(stonith_failures, target);
        if (rec) {
            rec->count = 0;
        }
    } else {
        GHashTableIter iter;
        const char *key = NULL;
        struct st_fail_rec *rec = NULL;

        g_hash_table_iter_init(&iter, stonith_failures);
        while (g_hash_table_iter_next(&iter, (gpointer *) &key,
                                      (gpointer *) &rec)) {
            rec->count = 0;
        }
    }
}

void
st_fail_count_increment(const char *target)
{
    struct st_fail_rec *rec = NULL;

    if (stonith_failures == NULL) {
        stonith_failures = crm_str_table_new();
    }

    rec = g_hash_table_lookup(stonith_failures, target);
    if (rec) {
        rec->count++;
    } else {
        rec = malloc(sizeof(struct st_fail_rec));
        if(rec == NULL) {
            return;
        }

        rec->count = 1;
        g_hash_table_insert(stonith_failures, strdup(target), rec);
    }
}

/*!
 * \internal
 * \brief Abort transition due to stonith failure
 *
 * \param[in] abort_action  Whether to restart or stop transition
 * \param[in] target  Don't restart if this (NULL for any) has too many failures
 * \param[in] reason  Log this stonith action XML as abort reason (or NULL)
 */
void
abort_for_stonith_failure(enum transition_action abort_action,
                          const char *target, xmlNode *reason)
{
    /* If stonith repeatedly fails, we eventually give up on starting a new
     * transition for that reason.
     */
    if ((abort_action != tg_stop) && too_many_st_failures(target)) {
        abort_action = tg_stop;
    }
    abort_transition(INFINITY, abort_action, "Stonith failed", reason);
}

void
tengine_stonith_callback(stonith_t * stonith, stonith_callback_data_t * data)
{
    char *uuid = NULL;
    int target_rc = -1;
    int stonith_id = -1;
    int transition_id = -1;
    crm_action_t *action = NULL;
    int call_id = data->call_id;
    int rc = data->rc;
    char *userdata = data->userdata;

    CRM_CHECK(userdata != NULL, return);
    crm_notice("Stonith operation %d/%s: %s (%d)", call_id, (char *)userdata,
               pcmk_strerror(rc), rc);

    if (AM_I_DC == FALSE) {
        return;
    }

    /* crm_info("call=%d, optype=%d, node_name=%s, result=%d, node_list=%s, action=%s", */
    /*       op->call_id, op->optype, op->node_name, op->op_result, */
    /*       (char *)op->node_list, op->private_data); */

    /* filter out old STONITH actions */
    CRM_CHECK(decode_transition_key(userdata, &uuid, &transition_id, &stonith_id, &target_rc),
              crm_err("Invalid event detected");
              goto bail;
        );

    if (transition_graph->complete || stonith_id < 0 || safe_str_neq(uuid, te_uuid)
        || transition_graph->id != transition_id) {
        crm_info("Ignoring STONITH action initiated outside of the current transition");
        goto bail;
    }

    action = get_action(stonith_id, FALSE);
    if (action == NULL) {
        crm_err("Stonith action not matched");
        goto bail;
    }

    stop_te_timer(action->timer);
    if (rc == pcmk_ok) {
        const char *target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
        const char *uuid = crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);
        const char *op = crm_meta_value(action->params, "stonith_action"); 

        crm_info("Stonith operation %d for %s passed", call_id, target);
        if (action->confirmed == FALSE) {
            te_action_confirmed(action);
            if (safe_str_eq("on", op)) {
                const char *value = NULL;
                char *now = crm_itoa(time(NULL));

                update_attrd(target, CRM_ATTR_UNFENCED, now, NULL, FALSE);
                free(now);

                value = crm_meta_value(action->params, XML_OP_ATTR_DIGESTS_ALL);
                update_attrd(target, CRM_ATTR_DIGESTS_ALL, value, NULL, FALSE);

                value = crm_meta_value(action->params, XML_OP_ATTR_DIGESTS_SECURE);
                update_attrd(target, CRM_ATTR_DIGESTS_SECURE, value, NULL, FALSE);

            } else if (action->sent_update == FALSE) {
                send_stonith_update(action, target, uuid);
                action->sent_update = TRUE;
            }
        }
        st_fail_count_reset(target);

    } else {
        const char *target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
        enum transition_action abort_action = tg_restart;

        action->failed = TRUE;
        crm_notice("Stonith operation %d for %s failed (%s): aborting transition.",
                   call_id, target, pcmk_strerror(rc));

        /* If no fence devices were available, there's no use in immediately
         * checking again, so don't start a new transition in that case.
         */
        if (rc == -ENODEV) {
            crm_warn("No devices found in cluster to fence %s, giving up",
                     target);
            abort_action = tg_stop;
        }

        /* Increment the fail count now, so abort_for_stonith_failure() can
         * check it. Non-DC nodes will increment it in tengine_stonith_notify().
         */
        st_fail_count_increment(target);
        abort_for_stonith_failure(abort_action, target, NULL);
    }

    update_graph(transition_graph, action);
    trigger_graph();

  bail:
    free(userdata);
    free(uuid);
    return;
}

void
cib_fencing_updated(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    if (rc < pcmk_ok) {
        crm_err("Fencing update %d for %s: failed - %s (%d)",
                call_id, (char *)user_data, pcmk_strerror(rc), rc);
        crm_log_xml_warn(msg, "Failed update");
        abort_transition(INFINITY, tg_shutdown, "CIB update failed", NULL);

    } else {
        crm_info("Fencing update %d for %s: complete", call_id, (char *)user_data);
    }
}

void
cib_action_updated(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    if (rc < pcmk_ok) {
        crm_err("Update %d FAILED: %s", call_id, pcmk_strerror(rc));
    }
}

gboolean
action_timer_callback(gpointer data)
{
    crm_action_timer_t *timer = NULL;

    CRM_CHECK(data != NULL, return FALSE);

    timer = (crm_action_timer_t *) data;
    stop_te_timer(timer);

    crm_warn("Timer popped (timeout=%d, abort_level=%d, complete=%s)",
             timer->timeout,
             transition_graph->abort_priority, transition_graph->complete ? "true" : "false");

    CRM_CHECK(timer->action != NULL, return FALSE);

    if (transition_graph->complete) {
        crm_warn("Ignoring timeout while not in transition");

    } else {
        /* fail the action */
        gboolean send_update = TRUE;
        const char *task = crm_element_value(timer->action->xml, XML_LRM_ATTR_TASK);

        print_action(LOG_ERR, "Aborting transition, action lost: ", timer->action);

        timer->action->failed = TRUE;
        te_action_confirmed(timer->action);
        abort_transition(INFINITY, tg_restart, "Action lost", NULL);

        update_graph(transition_graph, timer->action);
        trigger_graph();

        if (timer->action->type != action_type_rsc) {
            send_update = FALSE;
        } else if (safe_str_eq(task, RSC_CANCEL)) {
            /* we don't need to update the CIB with these */
            send_update = FALSE;
        }

        if (send_update) {
            cib_action_update(timer->action, PCMK_LRM_OP_TIMEOUT, PCMK_OCF_UNKNOWN_ERROR);
        }
    }

    return FALSE;
}
