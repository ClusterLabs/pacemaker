/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/stat.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>
#include <crm/msg_xml.h>
#include <crm/cluster.h>        /* For ONLINESTATUS etc */

#include <pacemaker-controld.h>

void te_update_confirm(const char *event, xmlNode * msg);

extern char *te_uuid;
gboolean shuttingdown = FALSE;
pcmk__graph_t *transition_graph;
crm_trigger_t *transition_trigger = NULL;

/* #define RSC_OP_TEMPLATE "//"XML_TAG_DIFF_ADDED"//"XML_TAG_CIB"//"XML_CIB_TAG_STATE"[@uname='%s']"//"XML_LRM_TAG_RSC_OP"[@id='%s]" */
#define RSC_OP_TEMPLATE "//"XML_TAG_DIFF_ADDED"//"XML_TAG_CIB"//"XML_LRM_TAG_RSC_OP"[@id='%s']"

// An explicit shutdown-lock of 0 means the lock has been cleared
static bool
shutdown_lock_cleared(xmlNode *lrm_resource)
{
    time_t shutdown_lock = 0;

    return (crm_element_value_epoch(lrm_resource, XML_CONFIG_ATTR_SHUTDOWN_LOCK,
                                    &shutdown_lock) == pcmk_ok)
           && (shutdown_lock == 0);
}

static void
te_update_diff_v1(const char *event, xmlNode *diff)
{
    int lpc, max;
    xmlXPathObject *xpathObj = NULL;

    CRM_CHECK(diff != NULL, return);

    xml_log_patchset(LOG_TRACE, __func__, diff);
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

    // Check for lrm_resource entries
    xpathObj = xpath_search(diff,
                            "//" F_CIB_UPDATE_RESULT
                            "//" XML_TAG_DIFF_ADDED
                            "//" XML_LRM_TAG_RESOURCE);
    max = numXpathResults(xpathObj);

    /*
     * Updates by, or in response to, graph actions will never affect more than
     * one resource at a time, so such updates indicate an LRM refresh. In that
     * case, start a new transition rather than check each result individually,
     * which can result in _huge_ speedups in large clusters.
     *
     * Unfortunately, we can only do so when there are no pending actions.
     * Otherwise, we could mistakenly throw away those results here, and
     * the cluster will stall waiting for them and time out the operation.
     */
    if ((transition_graph->pending == 0) && (max > 1)) {
        crm_debug("Ignoring resource operation updates due to history refresh of %d resources",
                  max);
        crm_log_xml_trace(diff, "lrm-refresh");
        abort_transition(INFINITY, tg_restart, "History refresh", NULL);
        goto bail;
    }

    if (max == 1) {
        xmlNode *lrm_resource = getXpathResult(xpathObj, 0);

        if (shutdown_lock_cleared(lrm_resource)) {
            // @TODO would be more efficient to abort once after transition done
            abort_transition(INFINITY, tg_restart, "Shutdown lock cleared",
                             lrm_resource);
            // Still process results, so we stop timers and update failcounts
        }
    }
    freeXpathObject(xpathObj);

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

        path_max = strlen(RSC_OP_TEMPLATE) + strlen(op_id) + 1;
        rsc_op_xpath = calloc(1, path_max);
        snprintf(rsc_op_xpath, path_max, RSC_OP_TEMPLATE, op_id);

        op_match = xpath_search(diff, rsc_op_xpath);
        if (numXpathResults(op_match) == 0) {
            /* Prevent false positives by matching cancelations too */
            const char *node = get_node_id(match);
            pcmk__graph_action_t *cancelled = get_cancel_action(op_id, node);

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
    for (xmlNode *rsc_op = pcmk__xml_first_child(lrm_resource); rsc_op != NULL;
         rsc_op = pcmk__xml_next(rsc_op)) {
        process_graph_event(rsc_op, node);
    }
    if (shutdown_lock_cleared(lrm_resource)) {
        // @TODO would be more efficient to abort once after transition done
        abort_transition(INFINITY, tg_restart, "Shutdown lock cleared",
                         lrm_resource);
    }
}

static void
process_resource_updates(const char *node, xmlNode *xml, xmlNode *change,
                         const char *op, const char *xpath)
{
    xmlNode *rsc = NULL;

    if (xml == NULL) {
        return;
    }

    if (strcmp(TYPE(xml), XML_CIB_TAG_LRM) == 0) {
        xml = first_named_child(xml, XML_LRM_TAG_RESOURCES);
        CRM_CHECK(xml != NULL, return);
    }

    CRM_CHECK(strcmp(TYPE(xml), XML_LRM_TAG_RESOURCES) == 0, return);

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

    for (rsc = pcmk__xml_first_child(xml); rsc != NULL;
         rsc = pcmk__xml_next(rsc)) {
        crm_trace("Processing %s", ID(rsc));
        process_lrm_resource_diff(rsc, node);
    }
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
    pcmk__graph_action_t *down = NULL;

    if(!pcmk__str_eq(op, "delete", pcmk__str_casei)) {
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
    if (confirm_cancel_action(key, node_uuid) == FALSE) {
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
    for (xmlNode *state = pcmk__xml_first_child(status); state != NULL;
         state = pcmk__xml_next(state)) {
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

    for (xmlNode *change = pcmk__xml_first_child(diff); change != NULL;
         change = pcmk__xml_next(change)) {

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
                   || pcmk__str_eq(name, XML_CIB_TAG_TICKETS, pcmk__str_casei)) {
            abort_transition(INFINITY, tg_restart, "Ticket attribute change", change);
            break; // Won't be packaged with operation results we may be waiting for

        } else if (strstr(xpath, "/" XML_TAG_TRANSIENT_NODEATTRS "[")
                   || pcmk__str_eq(name, XML_TAG_TRANSIENT_NODEATTRS, pcmk__str_casei)) {
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
            char *local_node = pcmk__xpath_node_id(xpath, "lrm");

            process_resource_updates(local_node, match, change, op, xpath);
            free(local_node);

        } else if (strcmp(name, XML_LRM_TAG_RESOURCE) == 0) {
            char *local_node = pcmk__xpath_node_id(xpath, "lrm");

            process_lrm_resource_diff(match, local_node);
            free(local_node);

        } else if (strcmp(name, XML_LRM_TAG_RSC_OP) == 0) {
            char *local_node = pcmk__xpath_node_id(xpath, "lrm");

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
        crm_trace("Filter state=%s (complete)", fsa_state2string(fsa_state));
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
        crm_trace("Bad sys-to: %s", pcmk__s(sys_to, "missing"));
        return FALSE;

    } else if (pcmk__str_eq(op, CRM_OP_INVOKE_LRM, pcmk__str_casei)
               && pcmk__str_eq(sys_from, CRM_SYSTEM_LRMD, pcmk__str_casei)
/* 		  && pcmk__str_eq(type, XML_ATTR_RESPONSE, pcmk__str_casei) */
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

void
cib_action_updated(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    if (rc < pcmk_ok) {
        crm_err("Update %d FAILED: %s", call_id, pcmk_strerror(rc));
    }
}

/*!
 * \brief Handle a timeout in node-to-node communication
 *
 * \param[in] data  Pointer to graph action
 *
 * \return FALSE (indicating that source should be not be re-added)
 */
gboolean
action_timer_callback(gpointer data)
{
    pcmk__graph_action_t *action = (pcmk__graph_action_t *) data;
    const char *task = NULL;
    const char *on_node = NULL;
    const char *via_node = NULL;

    CRM_CHECK(data != NULL, return FALSE);

    stop_te_timer(action);

    task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
    on_node = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
    via_node = crm_element_value(action->xml, XML_LRM_ATTR_ROUTER_NODE);

    if (transition_graph->complete) {
        crm_notice("Node %s did not send %s result (via %s) within %dms "
                   "(ignoring because transition not in progress)",
                   (on_node? on_node : ""), (task? task : "unknown action"),
                   (via_node? via_node : "controller"), action->timeout);
    } else {
        /* fail the action */

        crm_err("Node %s did not send %s result (via %s) within %dms "
                "(action timeout plus cluster-delay)",
                (on_node? on_node : ""), (task? task : "unknown action"),
                (via_node? via_node : "controller"),
                action->timeout + transition_graph->network_delay);
        pcmk__log_graph_action(LOG_ERR, action);

        pcmk__set_graph_action_flags(action, pcmk__graph_action_failed);

        te_action_confirmed(action, transition_graph);
        abort_transition(INFINITY, tg_restart, "Action lost", NULL);

        // Record timeout in the CIB if appropriate
        if ((action->type == pcmk__rsc_graph_action)
            && controld_action_is_recordable(task)) {
            controld_record_action_timeout(action);
        }
    }

    return FALSE;
}
