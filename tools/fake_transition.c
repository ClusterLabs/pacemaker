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
#include "fake_transition.h"

static bool fake_quiet = FALSE;
static cib_t *fake_cib = NULL;
static GListPtr fake_resource_list = NULL;
static GListPtr fake_op_fail_list = NULL;

#define STATUS_PATH_MAX 512

#define quiet_log(fmt, args...) do {              \
              if(fake_quiet) {                         \
                  crm_trace(fmt, ##args);         \
              } else {                            \
                  printf(fmt , ##args);           \
              }                                   \
    } while(0)

#define new_node_template "//"XML_CIB_TAG_NODE"[@uname='%s']"
#define node_template "//"XML_CIB_TAG_STATE"[@uname='%s']"
#define rsc_template "//"XML_CIB_TAG_STATE"[@uname='%s']//"XML_LRM_TAG_RESOURCE"[@id='%s']"
#define op_template  "//"XML_CIB_TAG_STATE"[@uname='%s']//"XML_LRM_TAG_RESOURCE"[@id='%s']/"XML_LRM_TAG_RSC_OP"[@id='%s']"
/* #define op_template  "//"XML_CIB_TAG_STATE"[@uname='%s']//"XML_LRM_TAG_RESOURCE"[@id='%s']/"XML_LRM_TAG_RSC_OP"[@id='%s' and @"XML_LRM_ATTR_CALLID"='%d']" */


static void
inject_transient_attr(xmlNode * cib_node, const char *name, const char *value)
{
    xmlNode *attrs = NULL;
    xmlNode *container = NULL;
    xmlNode *nvp = NULL;
    const char *node_uuid = ID(cib_node);
    char *nvp_id = crm_concat(name, node_uuid, '-');

    quiet_log("Injecting attribute %s=%s into %s '%s'", name, value, xmlGetNodePath(cib_node),
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

static void
create_node_entry(cib_t * cib_conn, const char *node)
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
    op->t_run = time(NULL);
    op->t_rcchange = op->t_run;

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

static xmlNode *
inject_node_state(cib_t * cib_conn, const char *node, const char *uuid)
{
    int rc = pcmk_ok;
    int max = strlen(rsc_template) + strlen(node) + 1;
    char *xpath = NULL;
    xmlNode *cib_object = NULL;

    xpath = calloc(1, max);

    /* if (bringing_nodes_online) { */
        create_node_entry(cib_conn, node);
    /* } */

    snprintf(xpath, max, node_template, node);
    rc = cib_conn->cmds->query(cib_conn, xpath, &cib_object,
                               cib_xpath | cib_sync_call | cib_scope_local);

    if (cib_object && ID(cib_object) == NULL) {
        crm_err("Detected multiple node_state entries for xpath=%s, bailing", xpath);
        crm_log_xml_warn(cib_object, "Duplicates");
        crm_exit(ENOTUNIQ);
    }

    if (rc == -ENXIO) {
        char *found_uuid = NULL;

        if (uuid == NULL) {
            query_node_uuid(cib_conn, node, &found_uuid, NULL);
        } else {
            found_uuid = strdup(uuid);
        }

        cib_object = create_xml_node(NULL, XML_CIB_TAG_STATE);
        crm_xml_add(cib_object, XML_ATTR_UUID, found_uuid);
        crm_xml_add(cib_object, XML_ATTR_UNAME, node);
        cib_conn->cmds->create(cib_conn, XML_CIB_TAG_STATUS, cib_object,
                               cib_sync_call | cib_scope_local);
        free_xml(cib_object);
        free(found_uuid);

        rc = cib_conn->cmds->query(cib_conn, xpath, &cib_object,
                                   cib_xpath | cib_sync_call | cib_scope_local);
        crm_trace("injecting node state for %s. rc is %d", node, rc);
    }

    free(xpath);
    CRM_ASSERT(rc == pcmk_ok);
    return cib_object;
}

static xmlNode *
modify_node(cib_t * cib_conn, char *node, gboolean up)
{
    xmlNode *cib_node = inject_node_state(cib_conn, node, NULL);

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

static xmlNode *
find_resource_xml(xmlNode * cib_node, const char *resource)
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


static xmlNode *
inject_resource(xmlNode * cib_node, const char *resource, const char *rclass, const char *rtype,
                const char *rprovider)
{
    xmlNode *lrm = NULL;
    xmlNode *container = NULL;
    xmlNode *cib_resource = NULL;
    char *xpath = NULL;

    cib_resource = find_resource_xml(cib_node, resource);
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
               && safe_str_neq(rclass, "service")
               && safe_str_neq(rclass, "upstart")
               && safe_str_neq(rclass, "systemd")
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
    CRM_LOG_ASSERT(offset > 0);
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

void
modify_configuration(pe_working_set_t * data_set, cib_t *cib,
                     const char *quorum, const char *watchdog, GListPtr node_up, GListPtr node_down, GListPtr node_fail,
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

        rc = cib->cmds->modify(cib, NULL, top, cib_sync_call | cib_scope_local);
        CRM_ASSERT(rc == pcmk_ok);
    }

    if (watchdog) {
        quiet_log(" + Setting watchdog: %s\n", watchdog);

        rc = update_attr_delegate(cib, cib_sync_call | cib_scope_local,
                             XML_CIB_TAG_CRMCONFIG, NULL, NULL, NULL, NULL,
                             XML_ATTR_HAVE_WATCHDOG, watchdog, FALSE, NULL, NULL);

        CRM_ASSERT(rc == pcmk_ok);
    }

    for (gIter = node_up; gIter != NULL; gIter = gIter->next) {
        char *node = (char *)gIter->data;

        quiet_log(" + Bringing node %s online\n", node);
        cib_node = modify_node(cib, node, TRUE);
        CRM_ASSERT(cib_node != NULL);

        rc = cib->cmds->modify(cib, XML_CIB_TAG_STATUS, cib_node,
                                      cib_sync_call | cib_scope_local);
        CRM_ASSERT(rc == pcmk_ok);
        free_xml(cib_node);
    }

    for (gIter = node_down; gIter != NULL; gIter = gIter->next) {
        char xpath[STATUS_PATH_MAX];
        char *node = (char *)gIter->data;

        quiet_log(" + Taking node %s offline\n", node);
        cib_node = modify_node(cib, node, FALSE);
        CRM_ASSERT(cib_node != NULL);

        rc = cib->cmds->modify(cib, XML_CIB_TAG_STATUS, cib_node,
                                      cib_sync_call | cib_scope_local);
        CRM_ASSERT(rc == pcmk_ok);
        free_xml(cib_node);

        snprintf(xpath, STATUS_PATH_MAX, "//node_state[@uname='%s']/%s", node, XML_CIB_TAG_LRM);
        cib->cmds->delete(cib, xpath, NULL,
                                      cib_xpath | cib_sync_call | cib_scope_local);

        snprintf(xpath, STATUS_PATH_MAX, "//node_state[@uname='%s']/%s", node,
                 XML_TAG_TRANSIENT_NODEATTRS);
        cib->cmds->delete(cib, xpath, NULL,
                                      cib_xpath | cib_sync_call | cib_scope_local);

    }

    for (gIter = node_fail; gIter != NULL; gIter = gIter->next) {
        char *node = (char *)gIter->data;

        quiet_log(" + Failing node %s\n", node);
        cib_node = modify_node(cib, node, TRUE);
        crm_xml_add(cib_node, XML_NODE_IN_CLUSTER, XML_BOOLEAN_NO);
        CRM_ASSERT(cib_node != NULL);

        rc = cib->cmds->modify(cib, XML_CIB_TAG_STATUS, cib_node,
                                      cib_sync_call | cib_scope_local);
        CRM_ASSERT(rc == pcmk_ok);
        free_xml(cib_node);
    }

    for (gIter = ticket_grant; gIter != NULL; gIter = gIter->next) {
        char *ticket_id = (char *)gIter->data;

        quiet_log(" + Granting ticket %s\n", ticket_id);
        rc = set_ticket_state_attr(ticket_id, "granted", "true",
                                   cib, cib_sync_call | cib_scope_local);

        CRM_ASSERT(rc == pcmk_ok);
    }

    for (gIter = ticket_revoke; gIter != NULL; gIter = gIter->next) {
        char *ticket_id = (char *)gIter->data;

        quiet_log(" + Revoking ticket %s\n", ticket_id);
        rc = set_ticket_state_attr(ticket_id, "granted", "false",
                                   cib, cib_sync_call | cib_scope_local);

        CRM_ASSERT(rc == pcmk_ok);
    }

    for (gIter = ticket_standby; gIter != NULL; gIter = gIter->next) {
        char *ticket_id = (char *)gIter->data;

        quiet_log(" + Making ticket %s standby\n", ticket_id);
        rc = set_ticket_state_attr(ticket_id, "standby", "true",
                                   cib, cib_sync_call | cib_scope_local);

        CRM_ASSERT(rc == pcmk_ok);
    }

    for (gIter = ticket_activate; gIter != NULL; gIter = gIter->next) {
        char *ticket_id = (char *)gIter->data;

        quiet_log(" + Activating ticket %s\n", ticket_id);
        rc = set_ticket_state_attr(ticket_id, "standby", "false",
                                   cib, cib_sync_call | cib_scope_local);

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

            cib_node = inject_node_state(cib, node, NULL);
            CRM_ASSERT(cib_node != NULL);

            update_failcounts(cib_node, resource, interval, outcome);

            cib_resource = inject_resource(cib_node, resource, rclass, rtype, rprovider);
            CRM_ASSERT(cib_resource != NULL);

            op = create_op(cib_resource, task, interval, outcome);
            CRM_ASSERT(op != NULL);

            cib_op = inject_op(cib_resource, op, 0);
            CRM_ASSERT(cib_op != NULL);
            lrmd_free_event(op);

            rc = cib->cmds->modify(cib, XML_CIB_TAG_STATUS, cib_node,
                                          cib_sync_call | cib_scope_local);
            CRM_ASSERT(rc == pcmk_ok);
        }
        free(task);
        free(node);
        free(key);
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

static gboolean
exec_rsc_action(crm_graph_t * graph, crm_action_t * action)
{
    int rc = 0;
    GListPtr gIter = NULL;
    lrmd_event_data_t *op = NULL;
    int target_outcome = 0;
    gboolean uname_is_uuid = FALSE;

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
    char *uuid = crm_element_value_copy(action->xml, XML_LRM_ATTR_TARGET_UUID);
    const char *router_node = crm_element_value(action->xml, XML_LRM_ATTR_ROUTER_NODE);

    if (safe_str_eq(operation, CRM_OP_PROBED)
        || safe_str_eq(operation, CRM_OP_REPROBE)) {
        crm_info("Skipping %s op for %s\n", operation, node);
        goto done;
    }

    if (action_rsc == NULL) {
        crm_log_xml_err(action->xml, "Bad");
        free(node); free(uuid);
        return FALSE;
    }

    /* Look for the preferred name
     * If not found, try the expected 'local' name
     * If not found use the preferred name anyway
     */
    resource = crm_element_value(action_rsc, XML_ATTR_ID);
    if (pe_find_resource(fake_resource_list, resource) == NULL) {
        const char *longname = crm_element_value(action_rsc, XML_ATTR_ID_LONG);

        if (pe_find_resource(fake_resource_list, longname)) {
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

    CRM_ASSERT(fake_cib->cmds->query(fake_cib, NULL, NULL, cib_sync_call | cib_scope_local) ==
               pcmk_ok);

    if (router_node) {
        uname_is_uuid = TRUE;
    }

    cib_node = inject_node_state(fake_cib, node, uname_is_uuid ? node : uuid);
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

    for (gIter = fake_op_fail_list; gIter != NULL; gIter = gIter->next) {
        char *spec = (char *)gIter->data;
        char *key = NULL;

        key = calloc(1, 1 + strlen(spec));
        snprintf(key, strlen(spec), "%s_%s_%d@%s=", resource, op->op_type, op->interval, node);

        if (strncasecmp(key, spec, strlen(key)) == 0) {
            sscanf(spec, "%*[^=]=%d", (int *)&op->rc);

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

    rc = fake_cib->cmds->modify(fake_cib, XML_CIB_TAG_STATUS, cib_node,
                                  cib_sync_call | cib_scope_local);
    CRM_ASSERT(rc == pcmk_ok);

  done:
    free(node); free(uuid);
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
    xmlNode *rsc = first_named_child(action->xml, XML_CIB_TAG_RESOURCE);

    action->confirmed = TRUE;

    if(rsc) {
        quiet_log(" * Cluster action:  %s for %s on %s\n", task, ID(rsc), node);
    } else {
        quiet_log(" * Cluster action:  %s on %s\n", task, node);
    }
    update_graph(graph, action);
    return TRUE;
}

static gboolean
exec_stonith_action(crm_graph_t * graph, crm_action_t * action)
{
    const char *op = crm_meta_value(action->params, "stonith_action");
    char *target = crm_element_value_copy(action->xml, XML_LRM_ATTR_TARGET);

    quiet_log(" * Fencing %s (%s)\n", target, op);
    if(safe_str_neq(op, "on")) {
        int rc = 0;
        char xpath[STATUS_PATH_MAX];
        xmlNode *cib_node = modify_node(fake_cib, target, FALSE);

        crm_xml_add(cib_node, XML_ATTR_ORIGIN, __FUNCTION__);
        CRM_ASSERT(cib_node != NULL);

        rc = fake_cib->cmds->replace(fake_cib, XML_CIB_TAG_STATUS, cib_node,
                                   cib_sync_call | cib_scope_local);
        CRM_ASSERT(rc == pcmk_ok);

        snprintf(xpath, STATUS_PATH_MAX, "//node_state[@uname='%s']/%s", target, XML_CIB_TAG_LRM);
        fake_cib->cmds->delete(fake_cib, xpath, NULL,
                                      cib_xpath | cib_sync_call | cib_scope_local);

        snprintf(xpath, STATUS_PATH_MAX, "//node_state[@uname='%s']/%s", target,
                 XML_TAG_TRANSIENT_NODEATTRS);
        fake_cib->cmds->delete(fake_cib, xpath, NULL,
                                      cib_xpath | cib_sync_call | cib_scope_local);

        free_xml(cib_node);
    }

    action->confirmed = TRUE;
    update_graph(graph, action);
    free(target);
    return TRUE;
}

int
run_simulation(pe_working_set_t * data_set, cib_t *cib, GListPtr op_fail_list, bool quiet)
{
    crm_graph_t *transition = NULL;
    enum transition_status graph_rc = -1;

    crm_graph_functions_t exec_fns = {
        exec_pseudo_action,
        exec_rsc_action,
        exec_crmd_action,
        exec_stonith_action,
    };

    fake_cib = cib;
    fake_quiet = quiet;
    fake_op_fail_list = op_fail_list;

    quiet_log("\nExecuting cluster transition:\n");

    set_graph_functions(&exec_fns);
    transition = unpack_graph(data_set->graph, crm_system_name);
    print_graph(LOG_DEBUG, transition);

    fake_resource_list = data_set->resources;
    do {
        graph_rc = run_graph(transition);

    } while (graph_rc == transition_active);
    fake_resource_list = NULL;

    if (graph_rc != transition_complete) {
        fprintf(stdout, "Transition failed: %s\n", transition_status(graph_rc));
        print_graph(LOG_ERR, transition);
    }
    destroy_graph(transition);
    if (graph_rc != transition_complete) {
        fprintf(stdout, "An invalid transition was produced\n");
    }

    if (graph_rc != transition_complete) {
        return graph_rc;
    }
    return 0;
}
