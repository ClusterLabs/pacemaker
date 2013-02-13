/* 
 * Copyright (C) 2009 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/stat.h>
#include <sys/param.h>
#include <sys/types.h>
#include <dirent.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/common/util.h>
#include <crm/transition.h>
#include <crm/common/iso8601.h>
#include <crm/pengine/status.h>
#include <allocate.h>

cib_t *global_cib = NULL;
GListPtr op_fail = NULL;
gboolean quiet = FALSE;

#define new_node_template "//"XML_CIB_TAG_NODE"[@uname='%s']"
#define node_template "//"XML_CIB_TAG_STATE"[@uname='%s']"
#define rsc_template "//"XML_CIB_TAG_STATE"[@uname='%s']//"XML_LRM_TAG_RESOURCE"[@id='%s']"
#define op_template  "//"XML_CIB_TAG_STATE"[@uname='%s']//"XML_LRM_TAG_RESOURCE"[@id='%s']/"XML_LRM_TAG_RSC_OP"[@id='%s']"
/* #define op_template  "//"XML_CIB_TAG_STATE"[@uname='%s']//"XML_LRM_TAG_RESOURCE"[@id='%s']/"XML_LRM_TAG_RSC_OP"[@id='%s' and @"XML_LRM_ATTR_CALLID"='%d']" */

#define FAKE_TE_ID	"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

#define quiet_log(fmt, args...) do {		\
	if(quiet == FALSE) {			\
	    printf(fmt , ##args);		\
	}					\
    } while(0)

extern void cleanup_alloc_calculations(pe_working_set_t * data_set);

extern xmlNode *do_calculations(pe_working_set_t * data_set, xmlNode * xml_input, crm_time_t * now);

char *use_date = NULL;
static crm_time_t *
get_date(void)
{
    if (use_date) {
        return crm_time_new(use_date);
    }
    return NULL;
}

static xmlNode *
find_resource(xmlNode * cib_node, const char *resource)
{
    char *xpath = NULL;
    xmlNode *match = NULL;
    const char *node = crm_element_value(cib_node, XML_ATTR_UNAME);
    int max = strlen(rsc_template) + strlen(resource) + strlen(node) + 1;

    xpath = calloc(1, max);

    snprintf(xpath, max, rsc_template, node, resource);
    match = get_xpath_object(xpath, cib_node, LOG_DEBUG_2);

    free(xpath);
    return match;
}

static void
create_node_entry(cib_t * cib_conn, char *node)
{
    int rc = pcmk_ok;
    int max = strlen(new_node_template) + strlen(node) + 1;
    char *xpath = NULL;

    xpath = calloc(1, max);

    snprintf(xpath, max, new_node_template, node);
    rc = cib_conn->cmds->query(cib_conn, xpath, NULL, cib_xpath | cib_sync_call | cib_scope_local);

    if (rc == -ENXIO) {
        xmlNode *cib_object = create_xml_node(NULL, XML_CIB_TAG_NODE);

        /* Using node uname as uuid ala corosync/openais */
        crm_xml_add(cib_object, XML_ATTR_ID, node);
        crm_xml_add(cib_object, XML_ATTR_UNAME, node);
        cib_conn->cmds->create(cib_conn, XML_CIB_TAG_NODES, cib_object,
                               cib_sync_call | cib_scope_local);
        /* Not bothering with subsequent query to see if it exists,
           we'll bomb out later in the call to query_node_uuid()... */

        free_xml(cib_object);
    }

    free(xpath);
}

static xmlNode *
inject_node_state(cib_t * cib_conn, char *node)
{
    int rc = pcmk_ok;
    int max = strlen(rsc_template) + strlen(node) + 1;
    char *xpath = NULL;
    xmlNode *cib_object = NULL;

    xpath = calloc(1, max);

    create_node_entry(cib_conn, node);

    snprintf(xpath, max, node_template, node);
    rc = cib_conn->cmds->query(cib_conn, xpath, &cib_object,
                               cib_xpath | cib_sync_call | cib_scope_local);

    if (cib_object && ID(cib_object) == NULL) {
        crm_err("Detected multiple node_state entries for xpath=%s, bailing", xpath);
        crm_log_xml_warn(cib_object, "Duplicates");
        crm_exit(1);
    }

    if (rc == -ENXIO) {
        char *uuid = NULL;

        query_node_uuid(cib_conn, node, &uuid);

        cib_object = create_xml_node(NULL, XML_CIB_TAG_STATE);
        crm_xml_add(cib_object, XML_ATTR_UUID, uuid);
        crm_xml_add(cib_object, XML_ATTR_UNAME, node);
        cib_conn->cmds->create(cib_conn, XML_CIB_TAG_STATUS, cib_object,
                               cib_sync_call | cib_scope_local);
        free_xml(cib_object);
        free(uuid);

        rc = cib_conn->cmds->query(cib_conn, xpath, &cib_object,
                                   cib_xpath | cib_sync_call | cib_scope_local);
    }

    free(xpath);
    CRM_ASSERT(rc == pcmk_ok);
    return cib_object;
}

static xmlNode *
modify_node(cib_t * cib_conn, char *node, gboolean up)
{
    xmlNode *cib_node = inject_node_state(cib_conn, node);

    if (up) {
        crm_xml_add(cib_node, XML_NODE_IN_CLUSTER, XML_BOOLEAN_YES);
        crm_xml_add(cib_node, XML_NODE_IS_PEER, ONLINESTATUS);
        crm_xml_add(cib_node, XML_NODE_JOIN_STATE, CRMD_JOINSTATE_MEMBER);
        crm_xml_add(cib_node, XML_NODE_EXPECTED, CRMD_JOINSTATE_MEMBER);

    } else {
        crm_xml_add(cib_node, XML_NODE_IN_CLUSTER, XML_BOOLEAN_NO);
        crm_xml_add(cib_node, XML_NODE_IS_PEER, OFFLINESTATUS);
        crm_xml_add(cib_node, XML_NODE_JOIN_STATE, CRMD_JOINSTATE_DOWN);
        crm_xml_add(cib_node, XML_NODE_EXPECTED, CRMD_JOINSTATE_DOWN);
    }

    crm_xml_add(cib_node, XML_ATTR_ORIGIN, crm_system_name);
    return cib_node;
}

static void
inject_transient_attr(xmlNode * cib_node, const char *name, const char *value)
{
    xmlNode *attrs = NULL;
    xmlNode *container = NULL;
    xmlNode *nvp = NULL;
    const char *node_uuid = ID(cib_node);
    char *nvp_id = crm_concat(name, node_uuid, '-');

    crm_info("Injecting attribute %s=%s into %s '%s'", name, value, xmlGetNodePath(cib_node),
             ID(cib_node));

    attrs = first_named_child(cib_node, XML_TAG_TRANSIENT_NODEATTRS);
    if (attrs == NULL) {
        attrs = create_xml_node(cib_node, XML_TAG_TRANSIENT_NODEATTRS);
        crm_xml_add(attrs, XML_ATTR_ID, node_uuid);
    }

    container = first_named_child(attrs, XML_TAG_ATTR_SETS);
    if (container == NULL) {
        container = create_xml_node(attrs, XML_TAG_ATTR_SETS);
        crm_xml_add(container, XML_ATTR_ID, node_uuid);
    }

    nvp = create_xml_node(container, XML_CIB_TAG_NVPAIR);
    crm_xml_add(nvp, XML_ATTR_ID, nvp_id);
    crm_xml_add(nvp, XML_NVPAIR_ATTR_NAME, name);
    crm_xml_add(nvp, XML_NVPAIR_ATTR_VALUE, value);

    free(nvp_id);
}

static xmlNode *
inject_resource(xmlNode * cib_node, const char *resource, const char *rclass, const char *rtype,
                const char *rprovider)
{
    xmlNode *lrm = NULL;
    xmlNode *container = NULL;
    xmlNode *cib_resource = NULL;
    char *xpath = NULL;

    cib_resource = find_resource(cib_node, resource);
    if (cib_resource != NULL) {
        return cib_resource;
    }

    /* One day, add query for class, provider, type */

    if (rclass == NULL || rtype == NULL) {
        fprintf(stderr, "Resource %s not found in the status section of %s."
                "  Please supply the class and type to continue\n", resource, ID(cib_node));
        return NULL;

    } else if (safe_str_neq(rclass, "ocf")
               && safe_str_neq(rclass, "stonith")
               && safe_str_neq(rclass, "heartbeat")
               && safe_str_neq(rclass, "lsb")) {
        fprintf(stderr, "Invalid class for %s: %s\n", resource, rclass);
        return NULL;

    } else if (safe_str_eq(rclass, "ocf") && rprovider == NULL) {
        fprintf(stderr, "Please specify the provider for resource %s\n", resource);
        return NULL;
    }

    xpath = (char *)xmlGetNodePath(cib_node);
    crm_info("Injecting new resource %s into %s '%s'", resource, xpath, ID(cib_node));
    free(xpath);

    lrm = first_named_child(cib_node, XML_CIB_TAG_LRM);
    if (lrm == NULL) {
        const char *node_uuid = ID(cib_node);

        lrm = create_xml_node(cib_node, XML_CIB_TAG_LRM);
        crm_xml_add(lrm, XML_ATTR_ID, node_uuid);
    }

    container = first_named_child(lrm, XML_LRM_TAG_RESOURCES);
    if (container == NULL) {
        container = create_xml_node(lrm, XML_LRM_TAG_RESOURCES);
    }

    cib_resource = create_xml_node(container, XML_LRM_TAG_RESOURCE);
    crm_xml_add(cib_resource, XML_ATTR_ID, resource);

    crm_xml_add(cib_resource, XML_AGENT_ATTR_CLASS, rclass);
    crm_xml_add(cib_resource, XML_AGENT_ATTR_PROVIDER, rprovider);
    crm_xml_add(cib_resource, XML_ATTR_TYPE, rtype);

    return cib_resource;
}

static lrmd_event_data_t *
create_op(xmlNode * cib_resource, const char *task, int interval, int outcome)
{
    lrmd_event_data_t *op = NULL;
    xmlNode *xop = NULL;

    op = calloc(1, sizeof(lrmd_event_data_t));

    op->rsc_id = strdup(ID(cib_resource));
    op->interval = interval;
    op->op_type = strdup(task);

    op->rc = outcome;
    op->op_status = 0;
    op->params = NULL;          /* TODO: Fill me in */

    op->call_id = 0;
    for (xop = __xml_first_child(cib_resource); xop != NULL; xop = __xml_next(xop)) {
        int tmp = 0;

        crm_element_value_int(xop, XML_LRM_ATTR_CALLID, &tmp);
        if (tmp > op->call_id) {
            op->call_id = tmp;
        }
    }
    op->call_id++;

    return op;
}

static xmlNode *
inject_op(xmlNode * cib_resource, lrmd_event_data_t * op, int target_rc)
{
    return create_operation_update(cib_resource, op, CRM_FEATURE_SET, target_rc, crm_system_name,
                                   LOG_DEBUG_2);
}

static void
update_failcounts(xmlNode * cib_node, const char *resource, int interval, int rc)
{
    if (rc == 0) {
        return;

    } else if (rc == 7 && interval == 0) {
        return;

    } else {
        char *name = NULL;
        char *now = crm_itoa(time(NULL));

        name = crm_concat("fail-count", resource, '-');
        inject_transient_attr(cib_node, name, "value++");

        name = crm_concat("last-failure", resource, '-');
        inject_transient_attr(cib_node, name, now);

        free(name);
        free(now);
    }
}

static gboolean
exec_pseudo_action(crm_graph_t * graph, crm_action_t * action)
{
    const char *node = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
    const char *task = crm_element_value(action->xml, XML_LRM_ATTR_TASK_KEY);

    action->confirmed = TRUE;

    quiet_log(" * Pseudo action:   %s%s%s\n", task, node ? " on " : "", node ? node : "");
    update_graph(graph, action);
    return TRUE;
}

GListPtr resource_list = NULL;

static gboolean
exec_rsc_action(crm_graph_t * graph, crm_action_t * action)
{
    int rc = 0;
    GListPtr gIter = NULL;
    lrmd_event_data_t *op = NULL;
    int target_outcome = 0;

    const char *rtype = NULL;
    const char *rclass = NULL;
    const char *resource = NULL;
    const char *rprovider = NULL;
    const char *operation = crm_element_value(action->xml, "operation");
    const char *target_rc_s = crm_meta_value(action->params, XML_ATTR_TE_TARGET_RC);

    xmlNode *cib_node = NULL;
    xmlNode *cib_resource = NULL;
    xmlNode *action_rsc = first_named_child(action->xml, XML_CIB_TAG_RESOURCE);

    char *node = crm_element_value_copy(action->xml, XML_LRM_ATTR_TARGET);

    if (safe_str_eq(operation, "probe_complete")) {
        crm_info("Skipping %s op for %s\n", crm_element_value(action->xml, "operation"), node);
        goto done;
    }

    if (action_rsc == NULL) {
        crm_log_xml_err(action->xml, "Bad");
        free(node);
        return FALSE;
    }

    /* Look for the preferred name
     * If not found, try the expected 'local' name
     * If not found use the preferred name anyway
     */
    resource = crm_element_value(action_rsc, XML_ATTR_ID);
    if (pe_find_resource(resource_list, resource) == NULL) {
        const char *longname = crm_element_value(action_rsc, XML_ATTR_ID_LONG);

        if (pe_find_resource(resource_list, longname)) {
            resource = longname;
        }
    }

    if (safe_str_eq(operation, "delete")) {
        quiet_log(" * Resource action: %-15s delete on %s\n", resource, node);
        goto done;
    }

    rclass = crm_element_value(action_rsc, XML_AGENT_ATTR_CLASS);
    rtype = crm_element_value(action_rsc, XML_ATTR_TYPE);
    rprovider = crm_element_value(action_rsc, XML_AGENT_ATTR_PROVIDER);

    if (target_rc_s != NULL) {
        target_outcome = crm_parse_int(target_rc_s, "0");
    }

    CRM_ASSERT(global_cib->cmds->query(global_cib, NULL, NULL, cib_sync_call | cib_scope_local) ==
               pcmk_ok);

    cib_node = inject_node_state(global_cib, node);
    CRM_ASSERT(cib_node != NULL);

    cib_resource = inject_resource(cib_node, resource, rclass, rtype, rprovider);
    CRM_ASSERT(cib_resource != NULL);

    op = convert_graph_action(cib_resource, action, 0, target_outcome);
    if (op->interval) {
        quiet_log(" * Resource action: %-15s %s=%d on %s\n", resource, op->op_type, op->interval,
                  node);
    } else {
        quiet_log(" * Resource action: %-15s %s on %s\n", resource, op->op_type, node);
    }

    for (gIter = op_fail; gIter != NULL; gIter = gIter->next) {
        char *spec = (char *)gIter->data;
        char *key = NULL;

        key = calloc(1, 1 + strlen(spec));
        snprintf(key, strlen(spec), "%s_%s_%d@%s=", resource, op->op_type, op->interval, node);

        if (strncasecmp(key, spec, strlen(key)) == 0) {
            rc = sscanf(spec, "%*[^=]=%d", (int *)&op->rc);

            action->failed = TRUE;
            graph->abort_priority = INFINITY;
            printf("\tPretending action %d failed with rc=%d\n", action->id, op->rc);
            update_failcounts(cib_node, resource, op->interval, op->rc);
            free(key);
            break;
        }
        free(key);
    }

    inject_op(cib_resource, op, target_outcome);
    lrmd_free_event(op);

    rc = global_cib->cmds->modify(global_cib, XML_CIB_TAG_STATUS, cib_node,
                                  cib_sync_call | cib_scope_local);
    CRM_ASSERT(rc == pcmk_ok);

  done:
    free(node);
    free_xml(cib_node);
    action->confirmed = TRUE;
    update_graph(graph, action);
    return TRUE;
}

static gboolean
exec_crmd_action(crm_graph_t * graph, crm_action_t * action)
{
    const char *node = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
    const char *task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);

    action->confirmed = TRUE;

    quiet_log(" * Cluster action:  %s on %s\n", task, node);
    update_graph(graph, action);
    return TRUE;
}

#define STATUS_PATH_MAX 512
static gboolean
exec_stonith_action(crm_graph_t * graph, crm_action_t * action)
{
    int rc = 0;
    char xpath[STATUS_PATH_MAX];
    char *target = crm_element_value_copy(action->xml, XML_LRM_ATTR_TARGET);
    xmlNode *cib_node = modify_node(global_cib, target, FALSE);

    crm_xml_add(cib_node, XML_ATTR_ORIGIN, __FUNCTION__);
    CRM_ASSERT(cib_node != NULL);

    quiet_log(" * Fencing %s\n", target);
    rc = global_cib->cmds->replace(global_cib, XML_CIB_TAG_STATUS, cib_node,
                                   cib_sync_call | cib_scope_local);
    CRM_ASSERT(rc == pcmk_ok);

    snprintf(xpath, STATUS_PATH_MAX, "//node_state[@uname='%s']/%s", target, XML_CIB_TAG_LRM);
    rc = global_cib->cmds->delete(global_cib, xpath, NULL,
                                  cib_xpath | cib_sync_call | cib_scope_local);

    snprintf(xpath, STATUS_PATH_MAX, "//node_state[@uname='%s']/%s", target,
             XML_TAG_TRANSIENT_NODEATTRS);
    rc = global_cib->cmds->delete(global_cib, xpath, NULL,
                                  cib_xpath | cib_sync_call | cib_scope_local);

    action->confirmed = TRUE;
    update_graph(graph, action);
    free_xml(cib_node);
    free(target);
    return TRUE;
}

static void
print_cluster_status(pe_working_set_t * data_set)
{
    char *online_nodes = NULL;
    char *offline_nodes = NULL;

    GListPtr gIter = NULL;

    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;
        const char *node_mode = NULL;

        if (node->details->unclean) {
            if (node->details->online && node->details->unclean) {
                node_mode = "UNCLEAN (online)";

            } else if (node->details->pending) {
                node_mode = "UNCLEAN (pending)";

            } else {
                node_mode = "UNCLEAN (offline)";
            }

        } else if (node->details->pending) {
            node_mode = "pending";

        } else if (node->details->standby_onfail && node->details->online) {
            node_mode = "standby (on-fail)";

        } else if (node->details->standby) {
            if (node->details->online) {
                node_mode = "standby";
            } else {
                node_mode = "OFFLINE (standby)";
            }

        } else if (node->details->online) {
            node_mode = "online";
            online_nodes = add_list_element(online_nodes, node->details->uname);
            continue;

        } else {
            node_mode = "OFFLINE";
            offline_nodes = add_list_element(offline_nodes, node->details->uname);
            continue;
        }

        if (safe_str_eq(node->details->uname, node->details->id)) {
            printf("Node %s: %s\n", node->details->uname, node_mode);
        } else {
            printf("Node %s (%s): %s\n", node->details->uname, node->details->id, node_mode);
        }
    }

    if (online_nodes) {
        printf("Online: [%s ]\n", online_nodes);
        free(online_nodes);
    }
    if (offline_nodes) {
        printf("OFFLINE: [%s ]\n", offline_nodes);
        free(offline_nodes);
    }

    fprintf(stdout, "\n");
    for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
        resource_t *rsc = (resource_t *) gIter->data;

        if (is_set(rsc->flags, pe_rsc_orphan)
            && rsc->role == RSC_ROLE_STOPPED) {
            continue;
        }
        rsc->fns->print(rsc, NULL, pe_print_printf, stdout);
    }
    fprintf(stdout, "\n");
}

static int
run_simulation(pe_working_set_t * data_set)
{
    crm_graph_t *transition = NULL;
    enum transition_status graph_rc = -1;

    crm_graph_functions_t exec_fns = {
        exec_pseudo_action,
        exec_rsc_action,
        exec_crmd_action,
        exec_stonith_action,
    };

    set_graph_functions(&exec_fns);

    quiet_log("\nExecuting cluster transition:\n");
    transition = unpack_graph(data_set->graph, crm_system_name);
    print_graph(LOG_DEBUG, transition);

    resource_list = data_set->resources;
    do {
        graph_rc = run_graph(transition);

    } while (graph_rc == transition_active);
    resource_list = NULL;

    if (graph_rc != transition_complete) {
        fprintf(stdout, "Transition failed: %s\n", transition_status(graph_rc));
        print_graph(LOG_ERR, transition);
    }
    destroy_graph(transition);
    if (graph_rc != transition_complete) {
        fprintf(stdout, "An invalid transition was produced\n");
    }

    if (quiet == FALSE) {
        xmlNode *cib_object = NULL;
        int rc =
            global_cib->cmds->query(global_cib, NULL, &cib_object, cib_sync_call | cib_scope_local);

        CRM_ASSERT(rc == pcmk_ok);
        quiet_log("\nRevised cluster status:\n");
        cleanup_alloc_calculations(data_set);
        data_set->input = cib_object;
        data_set->now = get_date();

        cluster_status(data_set);
        print_cluster_status(data_set);
    }

    if (graph_rc != transition_complete) {
        return graph_rc;
    }
    return 0;
}

static char *
create_action_name(action_t * action)
{
    char *action_name = NULL;
    const char *prefix = NULL;
    const char *action_host = NULL;
    const char *task = action->task;

    if (action->node) {
        action_host = action->node->details->uname;
    } else if (is_not_set(action->flags, pe_action_pseudo)) {
        action_host = "<none>";
    }

    if (safe_str_eq(action->task, RSC_CANCEL)) {
        prefix = "Cancel ";
        task = "monitor";       /* TO-DO: Hack! */
    }

    if (action->rsc && action->rsc->clone_name) {
        char *key = NULL;
        const char *name = action->rsc->clone_name;
        const char *interval_s = g_hash_table_lookup(action->meta, XML_LRM_ATTR_INTERVAL);

        int interval = crm_parse_int(interval_s, "0");

        if (safe_str_eq(action->task, RSC_NOTIFY)
            || safe_str_eq(action->task, RSC_NOTIFIED)) {
            const char *n_type = g_hash_table_lookup(action->meta, "notify_key_type");
            const char *n_task = g_hash_table_lookup(action->meta, "notify_key_operation");

            CRM_ASSERT(n_type != NULL);
            CRM_ASSERT(n_task != NULL);
            key = generate_notify_key(name, n_type, n_task);

        } else {
            key = generate_op_key(name, task, interval);
        }

        if (action_host) {
            action_name = g_strdup_printf("%s%s %s", prefix ? prefix : "", key, action_host);
        } else {
            action_name = g_strdup_printf("%s%s", prefix ? prefix : "", key);
        }
        free(key);

    } else if (safe_str_eq(action->task, CRM_OP_FENCE)) {
        action_name = g_strdup_printf("%s%s %s", prefix ? prefix : "", action->task, action_host);

    } else if (action_host) {
        action_name = g_strdup_printf("%s%s %s", prefix ? prefix : "", action->uuid, action_host);

    } else {
        action_name = g_strdup_printf("%s", action->uuid);
    }

    return action_name;
}

static void
create_dotfile(pe_working_set_t * data_set, const char *dot_file, gboolean all_actions)
{
    GListPtr gIter = NULL;
    FILE *dot_strm = fopen(dot_file, "w");

    if (dot_strm == NULL) {
        crm_perror(LOG_ERR, "Could not open %s for writing", dot_file);
        return;
    }

    fprintf(dot_strm, " digraph \"g\" {\n");
    for (gIter = data_set->actions; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;
        const char *style = "dashed";
        const char *font = "black";
        const char *color = "black";
        char *action_name = create_action_name(action);

        crm_trace("Action %d: %p", action->id, action);

        if (is_set(action->flags, pe_action_pseudo)) {
            font = "orange";
        }

        if (is_set(action->flags, pe_action_dumped)) {
            style = "bold";
            color = "green";

        } else if (action->rsc != NULL && is_not_set(action->rsc->flags, pe_rsc_managed)) {
            color = "red";
            font = "purple";
            if (all_actions == FALSE) {
                goto dont_write;
            }

        } else if (is_set(action->flags, pe_action_optional)) {
            color = "blue";
            if (all_actions == FALSE) {
                goto dont_write;
            }

        } else {
            color = "red";
            CRM_CHECK(is_set(action->flags, pe_action_runnable) == FALSE,;
                );
        }

        set_bit(action->flags, pe_action_dumped);
        fprintf(dot_strm, "\"%s\" [ style=%s color=\"%s\" fontcolor=\"%s\"]\n",
                action_name, style, color, font);
  dont_write:
        free(action_name);
    }

    for (gIter = data_set->actions; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;

        GListPtr gIter2 = NULL;

        for (gIter2 = action->actions_before; gIter2 != NULL; gIter2 = gIter2->next) {
            action_wrapper_t *before = (action_wrapper_t *) gIter2->data;

            char *before_name = NULL;
            char *after_name = NULL;
            const char *style = "dashed";
            gboolean optional = TRUE;

            if (before->state == pe_link_dumped) {
                optional = FALSE;
                style = "bold";
            } else if (is_set(action->flags, pe_action_pseudo)
                       && (before->type & pe_order_stonith_stop)) {
                continue;
            } else if (before->state == pe_link_dup) {
                continue;
            } else if (before->type == pe_order_none) {
                continue;
            } else if (is_set(before->action->flags, pe_action_dumped)
                       && is_set(action->flags, pe_action_dumped)
                       && before->type != pe_order_load) {
                optional = FALSE;
            }

            if (all_actions || optional == FALSE) {
                before_name = create_action_name(before->action);
                after_name = create_action_name(action);
                fprintf(dot_strm, "\"%s\" -> \"%s\" [ style = %s]\n",
                        before_name, after_name, style);
                free(before_name);
                free(after_name);
            }
        }
    }

    fprintf(dot_strm, "}\n");
    if (dot_strm != NULL) {
        fflush(dot_strm);
        fclose(dot_strm);
    }
}

static int
find_ticket_state(cib_t * the_cib, const char *ticket_id, xmlNode ** ticket_state_xml)
{
    int offset = 0;
    static int xpath_max = 1024;
    int rc = pcmk_ok;
    xmlNode *xml_search = NULL;

    char *xpath_string = NULL;

    CRM_ASSERT(ticket_state_xml != NULL);
    *ticket_state_xml = NULL;

    xpath_string = calloc(1, xpath_max);
    offset += snprintf(xpath_string + offset, xpath_max - offset, "%s", "/cib/status/tickets");

    if (ticket_id) {
        offset += snprintf(xpath_string + offset, xpath_max - offset, "/%s[@id=\"%s\"]",
                           XML_CIB_TAG_TICKET_STATE, ticket_id);
    }

    rc = the_cib->cmds->query(the_cib, xpath_string, &xml_search,
                              cib_sync_call | cib_scope_local | cib_xpath);

    if (rc != pcmk_ok) {
        goto bail;
    }

    crm_log_xml_debug(xml_search, "Match");
    if (xml_has_children(xml_search)) {
        if (ticket_id) {
            fprintf(stdout, "Multiple ticket_states match ticket_id=%s\n", ticket_id);
        }
        *ticket_state_xml = xml_search;
    } else {
        *ticket_state_xml = xml_search;
    }

  bail:
    free(xpath_string);
    return rc;
}

static int
set_ticket_state_attr(const char *ticket_id, const char *attr_name,
                      const char *attr_value, cib_t * cib, int cib_options)
{
    int rc = pcmk_ok;
    xmlNode *xml_top = NULL;
    xmlNode *ticket_state_xml = NULL;

    rc = find_ticket_state(cib, ticket_id, &ticket_state_xml);
    if (rc == pcmk_ok) {
        crm_debug("Found a match state for ticket: id=%s", ticket_id);
        xml_top = ticket_state_xml;

    } else if (rc != -ENXIO) {
        return rc;

    } else {
        xmlNode *xml_obj = NULL;

        xml_top = create_xml_node(NULL, XML_CIB_TAG_STATUS);
        xml_obj = create_xml_node(xml_top, XML_CIB_TAG_TICKETS);
        ticket_state_xml = create_xml_node(xml_obj, XML_CIB_TAG_TICKET_STATE);
        crm_xml_add(ticket_state_xml, XML_ATTR_ID, ticket_id);
    }

    crm_xml_add(ticket_state_xml, attr_name, attr_value);

    crm_log_xml_debug(xml_top, "Update");

    rc = cib->cmds->modify(cib, XML_CIB_TAG_STATUS, xml_top, cib_options);

    free_xml(xml_top);

    return rc;
}

static void
modify_configuration(pe_working_set_t * data_set,
                     const char *quorum, GListPtr node_up, GListPtr node_down, GListPtr node_fail,
                     GListPtr op_inject, GListPtr ticket_grant, GListPtr ticket_revoke,
                     GListPtr ticket_standby, GListPtr ticket_activate)
{
    int rc = pcmk_ok;
    GListPtr gIter = NULL;

    xmlNode *cib_op = NULL;
    xmlNode *cib_node = NULL;
    xmlNode *cib_resource = NULL;

    lrmd_event_data_t *op = NULL;

    if (quorum) {
        xmlNode *top = create_xml_node(NULL, XML_TAG_CIB);

        quiet_log(" + Setting quorum: %s\n", quorum);
        /* crm_xml_add(top, XML_ATTR_DC_UUID, dc_uuid);      */
        crm_xml_add(top, XML_ATTR_HAVE_QUORUM, quorum);

        rc = global_cib->cmds->modify(global_cib, NULL, top, cib_sync_call | cib_scope_local);
        CRM_ASSERT(rc == pcmk_ok);
    }

    for (gIter = node_up; gIter != NULL; gIter = gIter->next) {
        char *node = (char *)gIter->data;

        quiet_log(" + Bringing node %s online\n", node);
        cib_node = modify_node(global_cib, node, TRUE);
        CRM_ASSERT(cib_node != NULL);

        rc = global_cib->cmds->modify(global_cib, XML_CIB_TAG_STATUS, cib_node,
                                      cib_sync_call | cib_scope_local);
        CRM_ASSERT(rc == pcmk_ok);
    }

    for (gIter = node_down; gIter != NULL; gIter = gIter->next) {
        char *node = (char *)gIter->data;

        quiet_log(" + Taking node %s offline\n", node);
        cib_node = modify_node(global_cib, node, FALSE);
        CRM_ASSERT(cib_node != NULL);

        rc = global_cib->cmds->modify(global_cib, XML_CIB_TAG_STATUS, cib_node,
                                      cib_sync_call | cib_scope_local);
        CRM_ASSERT(rc == pcmk_ok);
    }

    for (gIter = node_fail; gIter != NULL; gIter = gIter->next) {
        char *node = (char *)gIter->data;

        quiet_log(" + Failing node %s\n", node);
        cib_node = modify_node(global_cib, node, TRUE);
        crm_xml_add(cib_node, XML_NODE_IN_CLUSTER, XML_BOOLEAN_NO);
        CRM_ASSERT(cib_node != NULL);

        rc = global_cib->cmds->modify(global_cib, XML_CIB_TAG_STATUS, cib_node,
                                      cib_sync_call | cib_scope_local);
        CRM_ASSERT(rc == pcmk_ok);
    }

    for (gIter = ticket_grant; gIter != NULL; gIter = gIter->next) {
        char *ticket_id = (char *)gIter->data;

        quiet_log(" + Granting ticket %s\n", ticket_id);
        rc = set_ticket_state_attr(ticket_id, "granted", "true",
                                   global_cib, cib_sync_call | cib_scope_local);

        CRM_ASSERT(rc == pcmk_ok);
    }

    for (gIter = ticket_revoke; gIter != NULL; gIter = gIter->next) {
        char *ticket_id = (char *)gIter->data;

        quiet_log(" + Revoking ticket %s\n", ticket_id);
        rc = set_ticket_state_attr(ticket_id, "granted", "false",
                                   global_cib, cib_sync_call | cib_scope_local);

        CRM_ASSERT(rc == pcmk_ok);
    }

    for (gIter = ticket_standby; gIter != NULL; gIter = gIter->next) {
        char *ticket_id = (char *)gIter->data;

        quiet_log(" + Making ticket %s standby\n", ticket_id);
        rc = set_ticket_state_attr(ticket_id, "standby", "true",
                                   global_cib, cib_sync_call | cib_scope_local);

        CRM_ASSERT(rc == pcmk_ok);
    }

    for (gIter = ticket_activate; gIter != NULL; gIter = gIter->next) {
        char *ticket_id = (char *)gIter->data;

        quiet_log(" + Activating ticket %s\n", ticket_id);
        rc = set_ticket_state_attr(ticket_id, "standby", "false",
                                   global_cib, cib_sync_call | cib_scope_local);

        CRM_ASSERT(rc == pcmk_ok);
    }

    for (gIter = op_inject; gIter != NULL; gIter = gIter->next) {
        char *spec = (char *)gIter->data;

        int rc = 0;
        int outcome = 0;
        int interval = 0;

        char *key = NULL;
        char *node = NULL;
        char *task = NULL;
        char *resource = NULL;

        const char *rtype = NULL;
        const char *rclass = NULL;
        const char *rprovider = NULL;

        resource_t *rsc = NULL;

        quiet_log(" + Injecting %s into the configuration\n", spec);

        key = calloc(1, strlen(spec) + 1);
        node = calloc(1, strlen(spec) + 1);
        rc = sscanf(spec, "%[^@]@%[^=]=%d", key, node, &outcome);
        CRM_CHECK(rc == 3,
                  fprintf(stderr, "Invalid operation spec: %s.  Only found %d fields\n", spec, rc);
                  continue);

        parse_op_key(key, &resource, &task, &interval);

        rsc = pe_find_resource(data_set->resources, resource);
        if (rsc == NULL) {
            fprintf(stderr, " - Invalid resource name: %s\n", resource);
        } else {
            rclass = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
            rtype = crm_element_value(rsc->xml, XML_ATTR_TYPE);
            rprovider = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);

            cib_node = inject_node_state(global_cib, node);
            CRM_ASSERT(cib_node != NULL);

            update_failcounts(cib_node, resource, interval, outcome);

            cib_resource = inject_resource(cib_node, resource, rclass, rtype, rprovider);
            CRM_ASSERT(cib_resource != NULL);

            op = create_op(cib_resource, task, interval, outcome);
            CRM_ASSERT(op != NULL);

            cib_op = inject_op(cib_resource, op, 0);
            CRM_ASSERT(cib_op != NULL);
            lrmd_free_event(op);

            rc = global_cib->cmds->modify(global_cib, XML_CIB_TAG_STATUS, cib_node,
                                          cib_sync_call | cib_scope_local);
            CRM_ASSERT(rc == pcmk_ok);
        }
        free(task);
        free(node);
        free(key);
    }
}

static void
setup_input(const char *input, const char *output)
{
    int rc = pcmk_ok;
    cib_t *cib_conn = NULL;
    xmlNode *cib_object = NULL;
    char *local_output = NULL;

    if (input == NULL) {
        /* Use live CIB */
        cib_conn = cib_new();
        rc = cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);

        if (rc == pcmk_ok) {
            cib_object = get_cib_copy(cib_conn);
        }

        cib_conn->cmds->signoff(cib_conn);
        cib_delete(cib_conn);
        cib_conn = NULL;

        if (cib_object == NULL) {
            fprintf(stderr, "Live CIB query failed: empty result\n");
            crm_exit(3);
        }

    } else if (safe_str_eq(input, "-")) {
        cib_object = filename2xml(NULL);

    } else {
        cib_object = filename2xml(input);
    }

    if (get_object_root(XML_CIB_TAG_STATUS, cib_object) == NULL) {
        create_xml_node(cib_object, XML_CIB_TAG_STATUS);
    }

    if (cli_config_update(&cib_object, NULL, FALSE) == FALSE) {
        free_xml(cib_object);
        crm_exit(-ENOKEY);
    }

    if (validate_xml(cib_object, NULL, FALSE) != TRUE) {
        free_xml(cib_object);
        crm_exit(-pcmk_err_dtd_validation);
    }

    if (output == NULL) {
        char *pid = crm_itoa(getpid());

        local_output = get_shadow_file(pid);
        output = local_output;
        free(pid);
    }

    rc = write_xml_file(cib_object, output, FALSE);
    free_xml(cib_object);
    cib_object = NULL;

    if (rc < 0) {
        fprintf(stderr, "Could not create '%s': %s\n", output, strerror(errno));
        crm_exit(rc);
    }
    setenv("CIB_file", output, 1);
    free(local_output);
}


/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",    0, 0, '?', "\tThis text"},
    {"version", 0, 0, '$', "\tVersion information"  },
    {"quiet",   0, 0, 'Q', "\tDisplay only essentialoutput"},
    {"verbose", 0, 0, 'V', "\tIncrease debug output"},

    {"-spacer-",      0, 0, '-', "\nOperations:"},
    {"run",           0, 0, 'R', "\tDetermine the cluster's response to the given configuration and status"},
    {"simulate",      0, 0, 'S', "Simulate the transition's execution and display the resulting cluster status"},
    {"in-place",      0, 0, 'X', "Simulate the transition's execution and store the result back to the input file"},
    {"show-scores",   0, 0, 's', "Show allocation scores"},
    {"show-utilization",   0, 0, 'U', "Show utilization information"},
    {"profile",       1, 0, 'P', "Run all tests in the named directory to create profiling data"},

    {"-spacer-",     0, 0, '-', "\nSynthetic Cluster Events:"},
    {"node-up",      1, 0, 'u', "\tBring a node online"},
    {"node-down",    1, 0, 'd', "\tTake a node offline"},
    {"node-fail",    1, 0, 'f', "\tMark a node as failed"},
    {"op-inject",    1, 0, 'i', "\tGenerate a failure for the cluster to react to in the simulation"},
    {"-spacer-",     0, 0, '-', "\t\tValue is of the form ${resource}_${task}_${interval}@${node}=${rc}."},
    {"-spacer-",     0, 0, '-', "\t\tEg. memcached_monitor_20000@bart.example.com=7"},
    {"-spacer-",     0, 0, '-', "\t\tFor more information on OCF return codes, refer to: http://www.clusterlabs.org/doc/en-US/Pacemaker/1.1/html/Pacemaker_Explained/s-ocf-return-codes.html"},
    {"op-fail",      1, 0, 'F', "\tIf the specified task occurs during the simulation, have it fail with return code ${rc}"},
    {"-spacer-",     0, 0, '-', "\t\tValue is of the form ${resource}_${task}_${interval}@${node}=${rc}."},
    {"-spacer-",     0, 0, '-', "\t\tEg. memcached_stop_0@bart.example.com=1\n"},
    {"-spacer-",     0, 0, '-', "\t\tThe transition will normally stop at the failed action.  Save the result with --save-output and re-run with --xml-file"},
    {"set-datetime", 1, 0, 't', "Set date/time"},
    {"quorum",       1, 0, 'q', "\tSpecify a value for quorum"},
    {"ticket-grant",     1, 0, 'g', "Grant a ticket"},
    {"ticket-revoke",    1, 0, 'r', "Revoke a ticket"},
    {"ticket-standby",   1, 0, 'b', "Make a ticket standby"},
    {"ticket-activate",  1, 0, 'e', "Activate a ticket"},

    {"-spacer-",     0, 0, '-', "\nOutput Options:"},
    
    {"save-input",   1, 0, 'I', "\tSave the input configuration to the named file"},
    {"save-output",  1, 0, 'O', "Save the output configuration to the named file"},
    {"save-graph",   1, 0, 'G', "\tSave the transition graph (XML format) to the named file"},
    {"save-dotfile", 1, 0, 'D', "Save the transition graph (DOT format) to the named file"},
    {"all-actions",  0, 0, 'a', "\tDisplay all possible actions in the DOT graph - even ones not part of the transition"},
    
    {"-spacer-",    0, 0, '-', "\nData Source:"},
    {"live-check",  0, 0, 'L', "\tConnect to the CIB and use the current contents as input"},
    {"xml-file",    1, 0, 'x', "\tRetrieve XML from the named file"},
    {"xml-pipe",    0, 0, 'p', "\tRetrieve XML from stdin"},

    {"-spacer-",    0, 0, '-', "\nExamples:\n"},
    {"-spacer-",    0, 0, '-', "Pretend a recurring monitor action found memcached stopped on node fred.example.com and, during recovery, that the memcached stop action failed", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " crm_simulate -LS --op-inject memcached:0_monitor_20000@bart.example.com=7 --op-fail memcached:0_stop_0@fred.example.com=1 --save-output /tmp/memcached-test.xml", pcmk_option_example},
    {"-spacer-",    0, 0, '-', "Now see what the reaction to the stop failure would be", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " crm_simulate -S --xml-file /tmp/memcached-test.xml", pcmk_option_example},
    
    {0, 0, 0, 0}
};
/* *INDENT-ON* */

static void
profile_one(const char *xml_file)
{
    xmlNode *cib_object = NULL;
    pe_working_set_t data_set;

    printf("* Testing %s\n", xml_file);
    cib_object = filename2xml(xml_file);
    if (get_object_root(XML_CIB_TAG_STATUS, cib_object) == NULL) {
        create_xml_node(cib_object, XML_CIB_TAG_STATUS);
    }

    if (cli_config_update(&cib_object, NULL, FALSE) == FALSE) {
        free_xml(cib_object);
        return;
    }

    if (validate_xml(cib_object, NULL, FALSE) != TRUE) {
        free_xml(cib_object);
        return;
    }

    set_working_set_defaults(&data_set);

    data_set.input = cib_object;
    data_set.now = get_date();
    do_calculations(&data_set, cib_object, NULL);

    cleanup_alloc_calculations(&data_set);
}

#ifndef FILENAME_MAX
#  define FILENAME_MAX 512
#endif

static int
profile_all(const char *dir)
{
    struct dirent **namelist;

    int lpc = 0;
    int file_num = scandir(dir, &namelist, 0, alphasort);

    if (file_num > 0) {
        struct stat prop;
        char buffer[FILENAME_MAX + 1];

        while (file_num--) {
            if ('.' == namelist[file_num]->d_name[0]) {
                free(namelist[file_num]);
                continue;

            } else if (strstr(namelist[file_num]->d_name, ".xml") == NULL) {
                free(namelist[file_num]);
                continue;
            }

            lpc++;
            snprintf(buffer, FILENAME_MAX, "%s/%s", dir, namelist[file_num]->d_name);
            if (stat(buffer, &prop) == 0 && S_ISREG(prop.st_mode)) {
                profile_one(buffer);
            }
            free(namelist[file_num]);
        }
        free(namelist);
    }

    return lpc;
}

int
main(int argc, char **argv)
{
    int rc = 0;
    guint modified = 0;

    gboolean store = FALSE;
    gboolean process = FALSE;
    gboolean simulate = FALSE;
    gboolean all_actions = FALSE;
    gboolean have_stdout = FALSE;

    pe_working_set_t data_set;

    const char *xml_file = "-";
    const char *quorum = NULL;
    const char *test_dir = NULL;
    const char *dot_file = NULL;
    const char *graph_file = NULL;
    const char *input_file = NULL;
    const char *output_file = NULL;

    int flag = 0;
    int index = 0;
    int argerr = 0;

    GListPtr node_up = NULL;
    GListPtr node_down = NULL;
    GListPtr node_fail = NULL;
    GListPtr op_inject = NULL;
    GListPtr ticket_grant = NULL;
    GListPtr ticket_revoke = NULL;
    GListPtr ticket_standby = NULL;
    GListPtr ticket_activate = NULL;

    xmlNode *input = NULL;

    crm_log_cli_init("crm_simulate");
    crm_set_options(NULL, "datasource operation [additional options]",
                    long_options, "Tool for simulating the cluster's response to events");

    if (argc < 2) {
        crm_help('?', EX_USAGE);
    }

    while (1) {
        flag = crm_get_option(argc, argv, &index);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                if (have_stdout == FALSE) {
                    /* Redirect stderr to stdout so we can grep the output */
                    have_stdout = TRUE;
                    close(STDERR_FILENO);
                    dup2(STDOUT_FILENO, STDERR_FILENO);
                }

                crm_bump_log_level(argc, argv);
                break;
            case '?':
            case '$':
                crm_help(flag, EX_OK);
                break;
            case 'p':
                xml_file = "-";
                break;
            case 'Q':
                quiet = TRUE;
                break;
            case 'L':
                xml_file = NULL;
                break;
            case 'x':
                xml_file = optarg;
                break;
            case 'u':
                modified++;
                node_up = g_list_append(node_up, optarg);
                break;
            case 'd':
                modified++;
                node_down = g_list_append(node_down, optarg);
                break;
            case 'f':
                modified++;
                node_fail = g_list_append(node_fail, optarg);
                break;
            case 't':
                use_date = strdup(optarg);
                break;
            case 'i':
                modified++;
                op_inject = g_list_append(op_inject, optarg);
                break;
            case 'F':
                process = TRUE;
                simulate = TRUE;
                op_fail = g_list_append(op_fail, optarg);
                break;
            case 'q':
                modified++;
                quorum = optarg;
                break;
            case 'g':
                modified++;
                ticket_grant = g_list_append(ticket_grant, optarg);
                break;
            case 'r':
                modified++;
                ticket_revoke = g_list_append(ticket_revoke, optarg);
                break;
            case 'b':
                modified++;
                ticket_standby = g_list_append(ticket_standby, optarg);
                break;
            case 'e':
                modified++;
                ticket_activate = g_list_append(ticket_activate, optarg);
                break;
            case 'a':
                all_actions = TRUE;
                break;
            case 's':
                process = TRUE;
                show_scores = TRUE;
                break;
            case 'U':
                process = TRUE;
                show_utilization = TRUE;
                break;
            case 'S':
                process = TRUE;
                simulate = TRUE;
                break;
            case 'X':
                store = TRUE;
                process = TRUE;
                simulate = TRUE;
                break;
            case 'R':
                process = TRUE;
                break;
            case 'D':
                process = TRUE;
                dot_file = optarg;
                break;
            case 'G':
                process = TRUE;
                graph_file = optarg;
                break;
            case 'I':
                input_file = optarg;
                break;
            case 'O':
                output_file = optarg;
                break;
            case 'P':
                test_dir = optarg;
                break;
            default:
                ++argerr;
                break;
        }
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        crm_help('?', EX_USAGE);
    }

    if (test_dir != NULL) {
        return profile_all(test_dir);
    }

    setup_input(xml_file, store ? xml_file : output_file);

    global_cib = cib_new();
    global_cib->cmds->signon(global_cib, crm_system_name, cib_command);

    set_working_set_defaults(&data_set);

    if (data_set.now != NULL) {
        quiet_log(" + Setting effective cluster time: %s", use_date);
        crm_time_log(LOG_WARNING, "Set fake 'now' to", data_set.now,
                     crm_time_log_date | crm_time_log_timeofday);
    }

    rc = global_cib->cmds->query(global_cib, NULL, &input, cib_sync_call | cib_scope_local);
    CRM_ASSERT(rc == pcmk_ok);

    data_set.input = input;
    data_set.now = get_date();
    cluster_status(&data_set);

    if (quiet == FALSE) {
        quiet_log("\nCurrent cluster status:\n");
        print_cluster_status(&data_set);
    }

    if (modified) {
        quiet_log("Performing requested modifications\n");
        modify_configuration(&data_set, quorum, node_up, node_down, node_fail, op_inject,
                             ticket_grant, ticket_revoke, ticket_standby, ticket_activate);

        rc = global_cib->cmds->query(global_cib, NULL, &input, cib_sync_call);
        if (rc != pcmk_ok) {
            fprintf(stderr, "Could not connect to the CIB for input: %s\n", pcmk_strerror(rc));
            goto done;
        }

        cleanup_alloc_calculations(&data_set);
        data_set.now = get_date();
        data_set.input = input;
    }

    if (input_file != NULL) {
        rc = write_xml_file(input, input_file, FALSE);
        if (rc < 0) {
            fprintf(stderr, "Could not create '%s': %s\n", input_file, strerror(errno));
            goto done;
        }
    }

    rc = 0;
    if (process || simulate) {
        crm_time_t *local_date = NULL;

        if (show_scores && show_utilization) {
            printf("Allocation scores and utilization information:\n");
        } else if (show_scores) {
            fprintf(stdout, "Allocation scores:\n");
        } else if (show_utilization) {
            printf("Utilization information:\n");
        }

        do_calculations(&data_set, input, local_date);
        input = NULL;           /* Don't try and free it twice */

        if (graph_file != NULL) {
            char *msg_buffer = dump_xml_formatted(data_set.graph);
            FILE *graph_strm = fopen(graph_file, "w");

            if (graph_strm == NULL) {
                crm_perror(LOG_ERR, "Could not open %s for writing", graph_file);

            } else {
                if (fprintf(graph_strm, "%s\n", msg_buffer) < 0) {
                    crm_perror(LOG_ERR, "Write to %s failed", graph_file);
                }
                fflush(graph_strm);
                fclose(graph_strm);
            }
            free(msg_buffer);
        }

        if (dot_file != NULL) {
            create_dotfile(&data_set, dot_file, all_actions);
        }

        if (quiet == FALSE) {
            GListPtr gIter = NULL;

            quiet_log("%sTransition Summary:\n", show_scores || show_utilization
                      || modified ? "\n" : "");
            fflush(stdout);

            for (gIter = data_set.resources; gIter != NULL; gIter = gIter->next) {
                resource_t *rsc = (resource_t *) gIter->data;

                LogActions(rsc, &data_set, TRUE);
            }
        }
    }

    if (simulate) {
        rc = run_simulation(&data_set);
    }

  done:
    cleanup_alloc_calculations(&data_set);

    global_cib->cmds->signoff(global_cib);
    cib_delete(global_cib);
    free(use_date);
    fflush(stderr);
    return crm_exit(rc);
}
