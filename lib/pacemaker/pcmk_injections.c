/*
 * Copyright 2009-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/stat.h>
#include <sys/param.h>
#include <sys/types.h>
#include <dirent.h>

#include <libxml/tree.h>                // xmlNode

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/cib/internal.h>
#include <crm/common/util.h>
#include <crm/common/iso8601.h>
#include <crm/lrmd_events.h>            // lrmd_event_data_t, etc.
#include <crm/lrmd_internal.h>
#include <crm/pengine/status.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

// @TODO Replace this with a new scheduler flag
bool pcmk__simulate_node_config = false;

#define XPATH_NODE_CONFIG   "//" PCMK_XE_NODE "[@" PCMK_XA_UNAME "='%s']"
#define XPATH_NODE_STATE    "//" PCMK__XE_NODE_STATE "[@" PCMK_XA_UNAME "='%s']"
#define XPATH_NODE_STATE_BY_ID "//" PCMK__XE_NODE_STATE "[@" PCMK_XA_ID "='%s']"
#define XPATH_RSC_HISTORY   XPATH_NODE_STATE \
                            "//" PCMK__XE_LRM_RESOURCE "[@" PCMK_XA_ID "='%s']"


/*!
 * \internal
 * \brief Inject a fictitious transient node attribute into scheduler input
 *
 * \param[in,out] out       Output object for displaying error messages
 * \param[in,out] cib_node  \c PCMK__XE_NODE_STATE XML to inject attribute into
 * \param[in]     name      Transient node attribute name to inject
 * \param[in]     value     Transient node attribute value to inject
 */
static void
inject_transient_attr(pcmk__output_t *out, xmlNode *cib_node,
                      const char *name, const char *value)
{
    xmlNode *attrs = NULL;
    xmlNode *instance_attrs = NULL;
    const char *node_uuid = pcmk__xe_id(cib_node);

    out->message(out, "inject-attr", name, value, cib_node);

    attrs = pcmk__xe_first_child(cib_node, PCMK__XE_TRANSIENT_ATTRIBUTES, NULL,
                                 NULL);
    if (attrs == NULL) {
        attrs = pcmk__xe_create(cib_node, PCMK__XE_TRANSIENT_ATTRIBUTES);
        pcmk__xe_set(attrs, PCMK_XA_ID, node_uuid);
    }

    instance_attrs = pcmk__xe_first_child(attrs, PCMK_XE_INSTANCE_ATTRIBUTES,
                                          NULL, NULL);
    if (instance_attrs == NULL) {
        instance_attrs = pcmk__xe_create(attrs, PCMK_XE_INSTANCE_ATTRIBUTES);
        pcmk__xe_set(instance_attrs, PCMK_XA_ID, node_uuid);
    }

    crm_create_nvpair_xml(instance_attrs, NULL, name, value);
}

/*!
 * \internal
 * \brief Inject a fictitious fail count into a scheduler input
 *
 * \param[in,out] out          Output object for displaying error messages
 * \param[in,out] cib_conn     CIB connection
 * \param[in,out] cib_node     Node state XML to inject into
 * \param[in]     resource     ID of resource for fail count to inject
 * \param[in]     task         Action name for fail count to inject
 * \param[in]     interval_ms  Action interval (in milliseconds) for fail count
 * \param[in]     exit_status  Action result for fail count to inject (if
 *                             \c PCMK_OCF_OK, or \c PCMK_OCF_NOT_RUNNING when
 *                             \p interval_ms is 0, inject nothing)
 * \param[in]     infinity     If true, set fail count to "INFINITY", otherwise
 *                             increase it by 1
 */
void
pcmk__inject_failcount(pcmk__output_t *out, cib_t *cib_conn, xmlNode *cib_node,
                       const char *resource, const char *task,
                       guint interval_ms, int exit_status, bool infinity)
{
    char *name = NULL;
    char *value = NULL;

    int failcount = 0;
    xmlNode *output = NULL;

    CRM_CHECK((out != NULL) && (cib_conn != NULL) && (cib_node != NULL)
              && (resource != NULL) && (task != NULL), return);

    if ((exit_status == PCMK_OCF_OK)
        || ((exit_status == PCMK_OCF_NOT_RUNNING) && (interval_ms == 0))) {
        return;
    }

    // Get current failcount and increment it
    name = pcmk__failcount_name(resource, task, interval_ms);

    if (cib__get_node_attrs(out, cib_conn, PCMK_XE_STATUS,
                            pcmk__xe_id(cib_node), NULL, NULL, NULL, name,
                            NULL, &output) == pcmk_rc_ok) {

        if (pcmk__xe_get_int(output, PCMK_XA_VALUE, &failcount) != pcmk_rc_ok) {
            failcount = 0;
        }
    }

    if (infinity) {
        value = pcmk__str_copy(PCMK_VALUE_INFINITY);

    } else {
        value = pcmk__itoa(failcount + 1);
    }

    inject_transient_attr(out, cib_node, name, value);

    free(name);
    free(value);
    pcmk__xml_free(output);

    name = pcmk__lastfailure_name(resource, task, interval_ms);
    value = pcmk__ttoa(time(NULL));
    inject_transient_attr(out, cib_node, name, value);

    free(name);
    free(value);
}

/*!
 * \internal
 * \brief Create a CIB configuration entry for a fictitious node
 *
 * \param[in,out] cib_conn  CIB object to use
 * \param[in]     node      Node name to use
 */
static void
create_node_entry(cib_t *cib_conn, const char *node)
{
    int rc = pcmk_ok;
    char *xpath = pcmk__assert_asprintf(XPATH_NODE_CONFIG, node);

    rc = cib_conn->cmds->query(cib_conn, xpath, NULL, cib_xpath|cib_sync_call);

    if (rc == -ENXIO) { // Only add if not already existing
        xmlNode *cib_object = pcmk__xe_create(NULL, PCMK_XE_NODE);

        pcmk__xe_set(cib_object, PCMK_XA_ID, node); // Use node name as ID
        pcmk__xe_set(cib_object, PCMK_XA_UNAME, node);
        cib_conn->cmds->create(cib_conn, PCMK_XE_NODES, cib_object,
                               cib_sync_call);
        /* Not bothering with subsequent query to see if it exists,
           we'll bomb out later in the call to query_node_uuid()... */

        pcmk__xml_free(cib_object);
    }

    free(xpath);
}

/*!
 * \internal
 * \brief Synthesize a fake executor event for an action
 *
 * \param[in] cib_resource  XML for any existing resource action history
 * \param[in] task          Name of action to synthesize
 * \param[in] interval_ms   Interval of action to synthesize
 * \param[in] outcome       Result of action to synthesize
 *
 * \return Newly allocated executor event
 * \note It is the caller's responsibility to free the result with
 *       lrmd_free_event().
 */
static lrmd_event_data_t *
create_op(const xmlNode *cib_resource, const char *task, guint interval_ms,
          int outcome)
{
    lrmd_event_data_t *op = NULL;
    xmlNode *xop = NULL;

    op = lrmd_new_event(pcmk__xe_id(cib_resource), task, interval_ms);
    lrmd__set_result(op, outcome, PCMK_EXEC_DONE, "Simulated action result");
    op->params = NULL; // Not needed for simulation purposes
    op->t_run = time(NULL);
    op->t_rcchange = op->t_run;

    // Use a call ID higher than any existing history entries
    op->call_id = 0;
    for (xop = pcmk__xe_first_child(cib_resource, NULL, NULL, NULL);
         xop != NULL; xop = pcmk__xe_next(xop, NULL)) {

        int tmp = 0;

        pcmk__xe_get_int(xop, PCMK__XA_CALL_ID, &tmp);
        if (tmp > op->call_id) {
            op->call_id = tmp;
        }
    }
    op->call_id++;

    return op;
}

/*!
 * \internal
 * \brief Inject a fictitious resource history entry into a scheduler input
 *
 * \param[in,out] cib_resource  Resource history XML to inject entry into
 * \param[in,out] op            Action result to inject
 * \param[in]     node          Name of node where the action occurred
 * \param[in]     target_rc     Expected result for action to inject
 *
 * \return XML of injected resource history entry
 */
xmlNode *
pcmk__inject_action_result(xmlNode *cib_resource, lrmd_event_data_t *op,
                           const char *node, int target_rc)
{
    return pcmk__create_history_xml(cib_resource, op, CRM_FEATURE_SET,
                                    target_rc, node, crm_system_name);
}

/*!
 * \internal
 * \brief Inject a fictitious node into a scheduler input
 *
 * \param[in,out] cib_conn  Scheduler input CIB to inject node into
 * \param[in]     node      Name of node to inject
 * \param[in]     uuid      UUID of node to inject
 *
 * \return XML of \c PCMK__XE_NODE_STATE entry for new node
 * \note If the global pcmk__simulate_node_config has been set to true, a
 *       node entry in the configuration section will be added, as well as a
 *       node state entry in the status section.
 */
xmlNode *
pcmk__inject_node(cib_t *cib_conn, const char *node, const char *uuid)
{
    int rc = pcmk_ok;
    xmlNode *cib_object = NULL;
    char *xpath = pcmk__assert_asprintf(XPATH_NODE_STATE, node);
    bool duplicate = false;
    char *found_uuid = NULL;

    if (pcmk__simulate_node_config) {
        create_node_entry(cib_conn, node);
    }

    rc = cib_conn->cmds->query(cib_conn, xpath, &cib_object,
                               cib_xpath|cib_sync_call);

    if ((cib_object != NULL) && (pcmk__xe_id(cib_object) == NULL)) {
        pcmk__err("Detected multiple " PCMK__XE_NODE_STATE " entries for "
                  "xpath=%s, bailing",
                  xpath);
        duplicate = true;
        goto done;
    }

    if (rc == -ENXIO) {
        if (uuid == NULL) {
            query_node_uuid(cib_conn, node, &found_uuid, NULL);
        } else {
            found_uuid = strdup(uuid);
        }

        if (found_uuid) {
            char *xpath_by_uuid = pcmk__assert_asprintf(XPATH_NODE_STATE_BY_ID,
                                                        found_uuid);

            /* It's possible that a PCMK__XE_NODE_STATE entry doesn't have a
             * PCMK_XA_UNAME yet
             */
            rc = cib_conn->cmds->query(cib_conn, xpath_by_uuid, &cib_object,
                                       cib_xpath|cib_sync_call);

            if ((cib_object != NULL) && (pcmk__xe_id(cib_object) == NULL)) {
                pcmk__err("Can't inject node state for %s because multiple "
                          "state entries found for ID %s",
                          node, found_uuid);
                duplicate = true;
                free(xpath_by_uuid);
                goto done;

            } else if (cib_object != NULL) {
                pcmk__xe_set(cib_object, PCMK_XA_UNAME, node);

                rc = cib_conn->cmds->modify(cib_conn, PCMK_XE_STATUS,
                                            cib_object, cib_sync_call);
            }

            free(xpath_by_uuid);
        }
    }

    if (rc == -ENXIO) {
        cib_object = pcmk__xe_create(NULL, PCMK__XE_NODE_STATE);
        pcmk__xe_set(cib_object, PCMK_XA_ID, found_uuid);
        pcmk__xe_set(cib_object, PCMK_XA_UNAME, node);
        cib_conn->cmds->create(cib_conn, PCMK_XE_STATUS, cib_object,
                               cib_sync_call);
        pcmk__xml_free(cib_object);

        rc = cib_conn->cmds->query(cib_conn, xpath, &cib_object,
                                   cib_xpath|cib_sync_call);
        pcmk__trace("Injecting node state for %s (rc=%d)", node, rc);
    }

done:
    free(found_uuid);
    free(xpath);

    if (duplicate) {
        pcmk__log_xml_warn(cib_object, "Duplicates");
        crm_exit(CRM_EX_SOFTWARE);
        return NULL; // not reached, but makes static analysis happy
    }

    pcmk__assert(rc == pcmk_ok);
    return cib_object;
}

/*!
 * \internal
 * \brief Inject a fictitious node state change into a scheduler input
 *
 * \param[in,out] cib_conn  Scheduler input CIB to inject into
 * \param[in]     node      Name of node to inject change for
 * \param[in]     up        If true, change state to online, otherwise offline
 *
 * \return XML of changed (or added) node state entry
 */
xmlNode *
pcmk__inject_node_state_change(cib_t *cib_conn, const char *node, bool up)
{
    xmlNode *cib_node = pcmk__inject_node(cib_conn, node, NULL);

    if (up) {
        pcmk__xe_set(cib_node, PCMK__XA_IN_CCM, PCMK_VALUE_TRUE);
        pcmk__xe_set(cib_node, PCMK_XA_CRMD, PCMK_VALUE_ONLINE);
        pcmk__xe_set(cib_node, PCMK__XA_JOIN, CRMD_JOINSTATE_MEMBER);
        pcmk__xe_set(cib_node, PCMK_XA_EXPECTED, CRMD_JOINSTATE_MEMBER);

    } else {
        pcmk__xe_set(cib_node, PCMK__XA_IN_CCM, PCMK_VALUE_FALSE);
        pcmk__xe_set(cib_node, PCMK_XA_CRMD, PCMK_VALUE_OFFLINE);
        pcmk__xe_set(cib_node, PCMK__XA_JOIN, CRMD_JOINSTATE_DOWN);
        pcmk__xe_set(cib_node, PCMK_XA_EXPECTED, CRMD_JOINSTATE_DOWN);
    }

    pcmk__xe_set(cib_node, PCMK_XA_CRM_DEBUG_ORIGIN, crm_system_name);
    return cib_node;
}

/*!
 * \internal
 * \brief Check whether a node has history for a given resource
 *
 * \param[in,out] cib_node  Node state XML to check
 * \param[in]     resource  Resource name to check for
 *
 * \return Resource's \c PCMK__XE_LRM_RESOURCE XML entry beneath \p cib_node if
 *         found, otherwise \c NULL
 */
static xmlNode *
find_resource_xml(xmlNode *cib_node, const char *resource)
{
    const char *node = pcmk__xe_get(cib_node, PCMK_XA_UNAME);
    char *xpath = pcmk__assert_asprintf(XPATH_RSC_HISTORY, node, resource);
    xmlNode *match = pcmk__xpath_find_one(cib_node->doc, xpath, LOG_TRACE);

    free(xpath);
    return match;
}

/*!
 * \internal
 * \brief Inject a resource history element into a scheduler input
 *
 * \param[in,out] out       Output object for displaying error messages
 * \param[in,out] cib_node  Node state XML to inject resource history entry into
 * \param[in]     resource  ID (in configuration) of resource to inject
 * \param[in]     lrm_name  ID as used in history (could be clone instance)
 * \param[in]     rclass    Resource agent class of resource to inject
 * \param[in]     rtype     Resource agent type of resource to inject
 * \param[in]     rprovider Resource agent provider of resource to inject
 *
 * \return XML of injected resource history element
 * \note If a history element already exists under either \p resource or
 *       \p lrm_name, this will return it rather than injecting a new one.
 */
xmlNode *
pcmk__inject_resource_history(pcmk__output_t *out, xmlNode *cib_node,
                              const char *resource, const char *lrm_name,
                              const char *rclass, const char *rtype,
                              const char *rprovider)
{
    xmlNode *lrm = NULL;
    xmlNode *container = NULL;
    xmlNode *cib_resource = NULL;

    cib_resource = find_resource_xml(cib_node, resource);
    if (cib_resource != NULL) {
        /* If an existing LRM history entry uses the resource name,
         * continue using it, even if lrm_name is different.
         */
        return cib_resource;
    }

    // Check for history entry under preferred name
    if (strcmp(resource, lrm_name) != 0) {
        cib_resource = find_resource_xml(cib_node, lrm_name);
        if (cib_resource != NULL) {
            return cib_resource;
        }
    }

    if ((rclass == NULL) || (rtype == NULL)) {
        // @TODO query configuration for class, provider, type
        out->err(out,
                 "Resource %s not found in the status section of %s "
                 "(supply class and type to continue)",
                 resource, pcmk__xe_id(cib_node));
        return NULL;

    } else if (!pcmk__strcase_any_of(rclass,
                                     PCMK_RESOURCE_CLASS_OCF,
                                     PCMK_RESOURCE_CLASS_STONITH,
                                     PCMK_RESOURCE_CLASS_SERVICE,
                                     PCMK_RESOURCE_CLASS_SYSTEMD,
                                     PCMK_RESOURCE_CLASS_LSB, NULL)) {
        out->err(out, "Invalid class for %s: %s", resource, rclass);
        return NULL;

    } else if (pcmk__is_set(pcmk_get_ra_caps(rclass), pcmk_ra_cap_provider)
               && (rprovider == NULL)) {
        // @TODO query configuration for provider
        out->err(out, "Please specify the provider for resource %s", resource);
        return NULL;
    }

    pcmk__info("Injecting new resource %s into node state '%s'", lrm_name,
               pcmk__xe_id(cib_node));

    lrm = pcmk__xe_first_child(cib_node, PCMK__XE_LRM, NULL, NULL);
    if (lrm == NULL) {
        const char *node_uuid = pcmk__xe_id(cib_node);

        lrm = pcmk__xe_create(cib_node, PCMK__XE_LRM);
        pcmk__xe_set(lrm, PCMK_XA_ID, node_uuid);
    }

    container = pcmk__xe_first_child(lrm, PCMK__XE_LRM_RESOURCES, NULL, NULL);
    if (container == NULL) {
        container = pcmk__xe_create(lrm, PCMK__XE_LRM_RESOURCES);
    }

    cib_resource = pcmk__xe_create(container, PCMK__XE_LRM_RESOURCE);

    // If we're creating a new entry, use the preferred name
    pcmk__xe_set(cib_resource, PCMK_XA_ID, lrm_name);

    pcmk__xe_set(cib_resource, PCMK_XA_CLASS, rclass);
    pcmk__xe_set(cib_resource, PCMK_XA_PROVIDER, rprovider);
    pcmk__xe_set(cib_resource, PCMK_XA_TYPE, rtype);

    return cib_resource;
}

/*!
 * \internal
 * \brief Inject a ticket attribute into ticket state
 *
 * \param[in,out] out          Output object for displaying error messages
 * \param[in]     ticket_id    Ticket whose state should be changed
 * \param[in]     attr_name    Ticket attribute name to inject
 * \param[in]     attr_value   Boolean value of ticket attribute to inject
 * \param[in,out] cib          CIB object to use
 *
 * \return Standard Pacemaker return code
 */
static int
set_ticket_state_attr(pcmk__output_t *out, const char *ticket_id,
                      const char *attr_name, bool attr_value, cib_t *cib)
{
    int rc = pcmk_rc_ok;
    xmlNode *xml_top = NULL;
    xmlNode *ticket_state_xml = NULL;

    // Check for an existing ticket state entry
    rc = pcmk__get_ticket_state(cib, ticket_id, &ticket_state_xml);

    if (rc == pcmk_rc_duplicate_id) {
        out->err(out, "Multiple " PCMK__XE_TICKET_STATE "s match ticket_id=%s",
                 ticket_id);
        rc = pcmk_rc_ok;
    }

    if (rc == pcmk_rc_ok) { // Ticket state found, use it
        pcmk__debug("Injecting attribute into existing ticket state %s",
                    ticket_id);
        xml_top = ticket_state_xml;

    } else if (rc == ENXIO) { // No ticket state, create it
        xmlNode *xml_obj = NULL;

        xml_top = pcmk__xe_create(NULL, PCMK_XE_STATUS);
        xml_obj = pcmk__xe_create(xml_top, PCMK_XE_TICKETS);
        ticket_state_xml = pcmk__xe_create(xml_obj, PCMK__XE_TICKET_STATE);
        pcmk__xe_set(ticket_state_xml, PCMK_XA_ID, ticket_id);

    } else { // Error
        return rc;
    }

    // Add the attribute to the ticket state
    pcmk__xe_set_bool(ticket_state_xml, attr_name, attr_value);
    pcmk__log_xml_debug(xml_top, "Update");

    // Commit the change to the CIB
    rc = cib->cmds->modify(cib, PCMK_XE_STATUS, xml_top, cib_sync_call);
    rc = pcmk_legacy2rc(rc);

    pcmk__xml_free(xml_top);
    return rc;
}

/*!
 * \internal
 * \brief Inject a fictitious action into the cluster
 *
 * \param[in,out] out       Output object for displaying error messages
 * \param[in]     spec      Action specification to inject
 * \param[in,out] cib       CIB object for scheduler input
 * \param[in]     scheduler  Scheduler data
 */
static void
inject_action(pcmk__output_t *out, const char *spec, cib_t *cib,
              const pcmk_scheduler_t *scheduler)
{
    int rc;
    int outcome = PCMK_OCF_OK;
    guint interval_ms = 0;

    char *key = NULL;
    char *node = NULL;
    char *task = NULL;
    char *resource = NULL;

    const char *rtype = NULL;
    const char *rclass = NULL;
    const char *rprovider = NULL;

    xmlNode *cib_op = NULL;
    xmlNode *cib_node = NULL;
    xmlNode *cib_resource = NULL;
    const pcmk_resource_t *rsc = NULL;
    lrmd_event_data_t *op = NULL;
    bool infinity = false;

    out->message(out, "inject-spec", spec);

    key = pcmk__assert_alloc(strlen(spec) + 1, sizeof(char));
    node = pcmk__assert_alloc(strlen(spec) + 1, sizeof(char));
    rc = sscanf(spec, "%[^@]@%[^=]=%d", key, node, &outcome);
    if (rc != 3) {
        out->err(out, "Invalid operation spec: %s.  Only found %d fields",
                 spec, rc);
        goto done;
    }

    parse_op_key(key, &resource, &task, &interval_ms);

    rsc = pe_find_resource(scheduler->priv->resources, resource);
    if (rsc == NULL) {
        out->err(out, "Invalid resource name: %s", resource);
        goto done;
    }

    rclass = pcmk__xe_get(rsc->priv->xml, PCMK_XA_CLASS);
    rtype = pcmk__xe_get(rsc->priv->xml, PCMK_XA_TYPE);
    rprovider = pcmk__xe_get(rsc->priv->xml, PCMK_XA_PROVIDER);

    cib_node = pcmk__inject_node(cib, node, NULL);
    pcmk__assert(cib_node != NULL);

    if (pcmk__str_eq(task, PCMK_ACTION_STOP, pcmk__str_none)) {
        infinity = true;

    } else if (pcmk__str_eq(task, PCMK_ACTION_START, pcmk__str_none)
               && pcmk__is_set(scheduler->flags,
                               pcmk__sched_start_failure_fatal)) {
        infinity = true;
    }

    pcmk__inject_failcount(out, cib, cib_node, resource, task, interval_ms,
                           outcome, infinity);

    cib_resource = pcmk__inject_resource_history(out, cib_node,
                                                 resource, resource,
                                                 rclass, rtype, rprovider);
    pcmk__assert(cib_resource != NULL);

    op = create_op(cib_resource, task, interval_ms, outcome);
    pcmk__assert(op != NULL);

    cib_op = pcmk__inject_action_result(cib_resource, op, node, 0);
    pcmk__assert(cib_op != NULL);
    lrmd_free_event(op);

    rc = cib->cmds->modify(cib, PCMK_XE_STATUS, cib_node, cib_sync_call);
    pcmk__assert(rc == pcmk_ok);

done:
    free(task);
    free(node);
    free(key);
}

/*!
 * \internal
 * \brief Inject fictitious scheduler inputs
 *
 * \param[in,out] scheduler   Scheduler data
 * \param[in,out] cib         CIB object for scheduler input to modify
 * \param[in]     injections  Injections to apply
 */
void
pcmk__inject_scheduler_input(pcmk_scheduler_t *scheduler, cib_t *cib,
                             const pcmk_injections_t *injections)
{
    int rc = pcmk_ok;
    const GList *iter = NULL;
    xmlNode *cib_node = NULL;
    pcmk__output_t *out = scheduler->priv->out;

    out->message(out, "inject-modify-config", injections->quorum,
                 injections->watchdog);
    if (injections->quorum != NULL) {
        xmlNode *top = pcmk__xe_create(NULL, PCMK_XE_CIB);

        /* pcmk__xe_set(top, PCMK_XA_DC_UUID, dc_uuid);      */
        pcmk__xe_set(top, PCMK_XA_HAVE_QUORUM, injections->quorum);

        rc = cib->cmds->modify(cib, NULL, top, cib_sync_call);
        pcmk__assert(rc == pcmk_ok);
    }

    if (injections->watchdog != NULL) {
        rc = cib__update_node_attr(out, cib, cib_sync_call, PCMK_XE_CRM_CONFIG,
                                   NULL, NULL, NULL, NULL,
                                   PCMK_OPT_HAVE_WATCHDOG, injections->watchdog,
                                   NULL, NULL);
        pcmk__assert(rc == pcmk_rc_ok);
    }

    for (iter = injections->node_up; iter != NULL; iter = iter->next) {
        const char *node = (const char *) iter->data;

        out->message(out, "inject-modify-node", "Online", node);

        cib_node = pcmk__inject_node_state_change(cib, node, true);
        pcmk__assert(cib_node != NULL);

        rc = cib->cmds->modify(cib, PCMK_XE_STATUS, cib_node, cib_sync_call);
        pcmk__assert(rc == pcmk_ok);
        pcmk__xml_free(cib_node);
    }

    for (iter = injections->node_down; iter != NULL; iter = iter->next) {
        const char *node = (const char *) iter->data;
        char *xpath = NULL;

        out->message(out, "inject-modify-node", "Offline", node);

        cib_node = pcmk__inject_node_state_change(cib, node, false);
        pcmk__assert(cib_node != NULL);

        rc = cib->cmds->modify(cib, PCMK_XE_STATUS, cib_node, cib_sync_call);
        pcmk__assert(rc == pcmk_ok);
        pcmk__xml_free(cib_node);

        xpath = pcmk__assert_asprintf("//" PCMK__XE_NODE_STATE
                                      "[@" PCMK_XA_UNAME "='%s']"
                                      "/" PCMK__XE_LRM,
                                      node);
        cib->cmds->remove(cib, xpath, NULL, cib_xpath|cib_sync_call);
        free(xpath);

        xpath = pcmk__assert_asprintf("//" PCMK__XE_NODE_STATE
                                      "[@" PCMK_XA_UNAME "='%s']"
                                      "/" PCMK__XE_TRANSIENT_ATTRIBUTES,
                                      node);
        cib->cmds->remove(cib, xpath, NULL, cib_xpath|cib_sync_call);
        free(xpath);
    }

    for (iter = injections->node_fail; iter != NULL; iter = iter->next) {
        const char *node = (const char *) iter->data;

        out->message(out, "inject-modify-node", "Failing", node);

        cib_node = pcmk__inject_node_state_change(cib, node, true);
        pcmk__xe_set(cib_node, PCMK__XA_IN_CCM, PCMK_VALUE_FALSE);
        pcmk__assert(cib_node != NULL);

        rc = cib->cmds->modify(cib, PCMK_XE_STATUS, cib_node, cib_sync_call);
        pcmk__assert(rc == pcmk_ok);
        pcmk__xml_free(cib_node);
    }

    for (iter = injections->ticket_grant; iter != NULL; iter = iter->next) {
        const char *ticket_id = (const char *) iter->data;

        out->message(out, "inject-modify-ticket", "Granting", ticket_id);

        rc = set_ticket_state_attr(out, ticket_id, PCMK__XA_GRANTED, true, cib);
        pcmk__assert(rc == pcmk_rc_ok);
    }

    for (iter = injections->ticket_revoke; iter != NULL; iter = iter->next) {
        const char *ticket_id = (const char *) iter->data;

        out->message(out, "inject-modify-ticket", "Revoking", ticket_id);

        rc = set_ticket_state_attr(out, ticket_id, PCMK__XA_GRANTED, false,
                                   cib);
        pcmk__assert(rc == pcmk_rc_ok);
    }

    for (iter = injections->ticket_standby; iter != NULL; iter = iter->next) {
        const char *ticket_id = (const char *) iter->data;

        out->message(out, "inject-modify-ticket", "Standby", ticket_id);

        rc = set_ticket_state_attr(out, ticket_id, PCMK_XA_STANDBY, true, cib);
        pcmk__assert(rc == pcmk_rc_ok);
    }

    for (iter = injections->ticket_activate; iter != NULL; iter = iter->next) {
        const char *ticket_id = (const char *) iter->data;

        out->message(out, "inject-modify-ticket", "Activating", ticket_id);

        rc = set_ticket_state_attr(out, ticket_id, PCMK_XA_STANDBY, false, cib);
        pcmk__assert(rc == pcmk_rc_ok);
    }

    for (iter = injections->op_inject; iter != NULL; iter = iter->next) {
        inject_action(out, (const char *) iter->data, cib, scheduler);
    }

    if (!out->is_quiet(out)) {
        out->end_list(out);
    }
}

void
pcmk_free_injections(pcmk_injections_t *injections)
{
    if (injections == NULL) {
        return;
    }

    g_list_free_full(injections->node_up, g_free);
    g_list_free_full(injections->node_down, g_free);
    g_list_free_full(injections->node_fail, g_free);
    g_list_free_full(injections->op_fail, g_free);
    g_list_free_full(injections->op_inject, g_free);
    g_list_free_full(injections->ticket_grant, g_free);
    g_list_free_full(injections->ticket_revoke, g_free);
    g_list_free_full(injections->ticket_standby, g_free);
    g_list_free_full(injections->ticket_activate, g_free);
    free(injections->quorum);
    free(injections->watchdog);

    free(injections);
}
