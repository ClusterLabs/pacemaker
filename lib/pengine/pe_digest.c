/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>
#include <stdbool.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>
#include <crm/pengine/internal.h>
#include "pe_status_private.h"

extern bool pcmk__is_daemon;

/*!
 * \internal
 * \brief Free an operation digest cache entry
 *
 * \param[in] ptr  Pointer to cache entry to free
 *
 * \note The argument is a gpointer so this can be used as a hash table
 *       free function.
 */
void
pe__free_digests(gpointer ptr)
{
    op_digest_cache_t *data = ptr;

    if (data != NULL) {
        free_xml(data->params_all);
        free_xml(data->params_secure);
        free_xml(data->params_restart);

        free(data->digest_all_calc);
        free(data->digest_restart_calc);
        free(data->digest_secure_calc);

        free(data);
    }
}

// Return true if XML attribute name is substring of a given string
static bool
attr_in_string(xmlAttrPtr a, void *user_data)
{
    bool filter = false;
    char *name = crm_strdup_printf(" %s ", (const char *) a->name);

    if (strstr((const char *) user_data, name) == NULL) {
        crm_trace("Filtering %s (not found in '%s')",
                  (const char *) a->name, (const char *) user_data);
        filter = true;
    }
    free(name);
    return filter;
}

// Return true if XML attribute name is not substring of a given string
static bool
attr_not_in_string(xmlAttrPtr a, void *user_data)
{
    bool filter = false;
    char *name = crm_strdup_printf(" %s ", (const char *) a->name);

    if (strstr((const char *) user_data, name) != NULL) {
        crm_trace("Filtering %s (found in '%s')",
                  (const char *) a->name, (const char *) user_data);
        filter = true;
    }
    free(name);
    return filter;
}

#if ENABLE_VERSIONED_ATTRS
static void
append_versioned_params(xmlNode *versioned_params, const char *ra_version, xmlNode *params)
{
    GHashTable *hash = pe_unpack_versioned_parameters(versioned_params, ra_version);
    char *key = NULL;
    char *value = NULL;
    GHashTableIter iter;

    g_hash_table_iter_init(&iter, hash);
    while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &value)) {
        crm_xml_add(params, key, value);
    }
    g_hash_table_destroy(hash);
}

static void
append_all_versioned_params(pe_resource_t *rsc, pe_node_t *node,
                            pe_action_t *action, xmlNode *xml_op,
                            pe_working_set_t *data_set)
{
    const char *ra_version = NULL;
    xmlNode *local_versioned_params = NULL;
    pe_rsc_action_details_t *details = pe_rsc_action_details(action);

    local_versioned_params = create_xml_node(NULL, XML_TAG_RSC_VER_ATTRS);
    pe_get_versioned_attributes(local_versioned_params, rsc, node, data_set);
    if (xml_op != NULL) {
        ra_version = crm_element_value(xml_op, XML_ATTR_RA_VERSION);
    }
    append_versioned_params(local_versioned_params, ra_version,
                            data->params_all);
    append_versioned_params(rsc->versioned_parameters, ra_version,
                            data->params_all);
    append_versioned_params(details->versioned_parameters, ra_version,
                            data->params_all);
}
#endif

/*!
 * \internal
 * \brief Add digest of all parameters to a digest cache entry
 *
 * \param[out]    data         Digest cache entry to modify
 * \param[in]     rsc          Resource that action was for
 * \param[in]     node         Node action was performed on
 * \param[in]     params       Resource parameters evaluated for node
 * \param[in]     task         Name of action performed
 * \param[in,out] interval_ms  Action's interval (will be reset if in overrides)
 * \param[in]     xml_op       XML of operation in CIB status (if available)
 * \param[in]     op_version   CRM feature set to use for digest calculation
 * \param[in]     overrides    Key/value table to override resource parameters
 * \param[in]     data_set     Cluster working set
 */
static void
calculate_main_digest(op_digest_cache_t *data, pe_resource_t *rsc,
                      pe_node_t *node, GHashTable *params,
                      const char *task, guint *interval_ms,
                      xmlNode *xml_op, const char *op_version,
                      GHashTable *overrides, pe_working_set_t *data_set)
{
    pe_action_t *action = NULL;

    data->params_all = create_xml_node(NULL, XML_TAG_PARAMS);

    /* REMOTE_CONTAINER_HACK: Allow Pacemaker Remote nodes to run containers
     * that themselves are Pacemaker Remote nodes
     */
    if (pe__add_bundle_remote_name(rsc, data_set, data->params_all,
                                   XML_RSC_ATTR_REMOTE_RA_ADDR)) {
        crm_trace("Set address for bundle connection %s (on %s)",
                  rsc->id, node->details->uname);
    }

    // If interval was overridden, reset it
    if (overrides != NULL) {
        const char *interval_s = g_hash_table_lookup(overrides, CRM_META "_"
                                                     XML_LRM_ATTR_INTERVAL);

        if (interval_s != NULL) {
            long long value_ll;

            if ((pcmk__scan_ll(interval_s, &value_ll, 0LL) == pcmk_rc_ok)
                && (value_ll >= 0) && (value_ll <= G_MAXUINT)) {
                *interval_ms = (guint) value_ll;
            }
        }
    }

    action = custom_action(rsc, pcmk__op_key(rsc->id, task, *interval_ms),
                           task, node, TRUE, FALSE, data_set);
    if (overrides != NULL) {
        g_hash_table_foreach(overrides, hash2field, data->params_all);
    }
    g_hash_table_foreach(params, hash2field, data->params_all);
    g_hash_table_foreach(action->extra, hash2field, data->params_all);
    g_hash_table_foreach(action->meta, hash2metafield, data->params_all);

#if ENABLE_VERSIONED_ATTRS
    append_all_versioned_params(rsc, node, action, xml_op, data_set);
#endif

    pcmk__filter_op_for_digest(data->params_all);

    pe_free_action(action);

    data->digest_all_calc = calculate_operation_digest(data->params_all,
                                                       op_version);
}

// Return true if XML attribute name is a Pacemaker-defined fencing parameter
static bool
is_fence_param(xmlAttrPtr attr, void *user_data)
{
    return pcmk_stonith_param((const char *) attr->name);
}

/*!
 * \internal
 * \brief Add secure digest to a digest cache entry
 *
 * \param[out] data        Digest cache entry to modify
 * \param[in]  rsc         Resource that action was for
 * \param[in]  params      Resource parameters evaluated for node
 * \param[in]  xml_op      XML of operation in CIB status (if available)
 * \param[in]  op_version  CRM feature set to use for digest calculation
 * \param[in]  overrides   Key/value hash table to override resource parameters
 */
static void
calculate_secure_digest(op_digest_cache_t *data, pe_resource_t *rsc,
                        GHashTable *params, xmlNode *xml_op,
                        const char *op_version, GHashTable *overrides)
{
    const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    const char *secure_list = NULL;

    if (xml_op == NULL) {
        secure_list = " passwd password user ";
    } else {
        secure_list = crm_element_value(xml_op, XML_LRM_ATTR_OP_SECURE);
    }

    data->params_secure = create_xml_node(NULL, XML_TAG_PARAMS);
    if (overrides != NULL) {
        g_hash_table_foreach(overrides, hash2field, data->params_secure);
    }

    g_hash_table_foreach(params, hash2field, data->params_secure);
    if (secure_list != NULL) {
        pcmk__xe_remove_matching_attrs(data->params_secure, attr_not_in_string,
                                       (void *) secure_list);
    }
    if (pcmk_is_set(pcmk_get_ra_caps(class),
                    pcmk_ra_cap_fence_params)) {
        /* For stonith resources, Pacemaker adds special parameters,
         * but these are not listed in fence agent meta-data, so the
         * controller will not hash them. That means we have to filter
         * them out before calculating our hash for comparison.
         */
        pcmk__xe_remove_matching_attrs(data->params_secure, is_fence_param,
                                       NULL);
    }
    pcmk__filter_op_for_digest(data->params_secure);

    /* CRM_meta_timeout *should* be part of a digest for recurring operations.
     * However, currently the controller does not add timeout to secure digests,
     * because it only includes parameters declared by the resource agent.
     * Remove any timeout that made it this far, to match.
     *
     * @TODO Update the controller to add the timeout (which will require
     * bumping the feature set and checking that here).
     */
    xml_remove_prop(data->params_secure, CRM_META "_" XML_ATTR_TIMEOUT);

    data->digest_secure_calc = calculate_operation_digest(data->params_secure,
                                                          op_version);
}

/*!
 * \internal
 * \brief Add restart digest to a digest cache entry
 *
 * \param[out] data        Digest cache entry to modify
 * \param[in]  xml_op      XML of operation in CIB status (if available)
 * \param[in]  op_version  CRM feature set to use for digest calculation
 *
 * \note This function doesn't need to handle overrides because it starts with
 *       data->params_all, which already has overrides applied.
 */
static void
calculate_restart_digest(op_digest_cache_t *data, xmlNode *xml_op,
                         const char *op_version)
{
    const char *value = NULL;

    // We must have XML of resource operation history
    if (xml_op == NULL) {
        return;
    }

    // And the history must have a restart digest to compare against
    if (crm_element_value(xml_op, XML_LRM_ATTR_RESTART_DIGEST) == NULL) {
        return;
    }

    // Start with a copy of all parameters
    data->params_restart = copy_xml(data->params_all);

    // Then filter out reloadable parameters, if any
    value = crm_element_value(xml_op, XML_LRM_ATTR_OP_RESTART);
    if (value != NULL) {
        pcmk__xe_remove_matching_attrs(data->params_restart, attr_in_string,
                                       (void *) value);
    }

    value = crm_element_value(xml_op, XML_ATTR_CRM_VERSION);
    data->digest_restart_calc = calculate_operation_digest(data->params_restart,
                                                           value);
}

/*!
 * \internal
 * \brief Create a new digest cache entry with calculated digests
 *
 * \param[in]     rsc          Resource that action was for
 * \param[in]     task         Name of action performed
 * \param[in,out] interval_ms  Action's interval (will be reset if in overrides)
 * \param[in]     node         Node action was performed on
 * \param[in]     xml_op       XML of operation in CIB status (if available)
 * \param[in]     overrides    Key/value table to override resource parameters
 * \param[in]     calc_secure  Whether to calculate secure digest
 * \param[in]     data_set     Cluster working set
 *
 * \return Pointer to new digest cache entry (or NULL on memory error)
 * \note It is the caller's responsibility to free the result using
 *       pe__free_digests().
 */
op_digest_cache_t *
pe__calculate_digests(pe_resource_t *rsc, const char *task, guint *interval_ms,
                      pe_node_t *node, xmlNode *xml_op, GHashTable *overrides,
                      bool calc_secure, pe_working_set_t *data_set)
{
    op_digest_cache_t *data = calloc(1, sizeof(op_digest_cache_t));
    const char *op_version = CRM_FEATURE_SET;
    GHashTable *params = NULL;

    if (data == NULL) {
        return NULL;
    }
    if (xml_op != NULL) {
        op_version = crm_element_value(xml_op, XML_ATTR_CRM_VERSION);
    }

    params = pe_rsc_params(rsc, node, data_set);
    calculate_main_digest(data, rsc, node, params, task, interval_ms, xml_op,
                          op_version, overrides, data_set);
    if (calc_secure) {
        calculate_secure_digest(data, rsc, params, xml_op, op_version,
                                overrides);
    }
    calculate_restart_digest(data, xml_op, op_version);
    return data;
}

/*!
 * \internal
 * \brief Calculate action digests and store in node's digest cache
 *
 * \param[in] rsc          Resource that action was for
 * \param[in] task         Name of action performed
 * \param[in] interval_ms  Action's interval
 * \param[in] node         Node action was performed on
 * \param[in] xml_op       XML of operation in CIB status (if available)
 * \param[in] calc_secure  Whether to calculate secure digest
 * \param[in] data_set     Cluster working set
 *
 * \return Pointer to node's digest cache entry
 */
static op_digest_cache_t *
rsc_action_digest(pe_resource_t *rsc, const char *task, guint interval_ms,
                  pe_node_t *node, xmlNode *xml_op, bool calc_secure,
                  pe_working_set_t *data_set)
{
    op_digest_cache_t *data = NULL;
    char *key = pcmk__op_key(rsc->id, task, interval_ms);

    data = g_hash_table_lookup(node->details->digest_cache, key);
    if (data == NULL) {
        data = pe__calculate_digests(rsc, task, &interval_ms, node, xml_op,
                                     NULL, calc_secure, data_set);
        CRM_ASSERT(data != NULL);
        g_hash_table_insert(node->details->digest_cache, strdup(key), data);
    }
    free(key);
    return data;
}

/*!
 * \internal
 * \brief Calculate operation digests and compare against an XML history entry
 *
 * \param[in] rsc       Resource to check
 * \param[in] xml_op    Resource history XML
 * \param[in] node      Node to use for digest calculation
 * \param[in] data_set  Cluster working set
 *
 * \return Pointer to node's digest cache entry, with comparison result set
 */
op_digest_cache_t *
rsc_action_digest_cmp(pe_resource_t * rsc, xmlNode * xml_op, pe_node_t * node,
                      pe_working_set_t * data_set)
{
    op_digest_cache_t *data = NULL;
    guint interval_ms = 0;

    const char *op_version;
    const char *task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
    const char *digest_all;
    const char *digest_restart;

    CRM_ASSERT(node != NULL);

    op_version = crm_element_value(xml_op, XML_ATTR_CRM_VERSION);
    digest_all = crm_element_value(xml_op, XML_LRM_ATTR_OP_DIGEST);
    digest_restart = crm_element_value(xml_op, XML_LRM_ATTR_RESTART_DIGEST);

    crm_element_value_ms(xml_op, XML_LRM_ATTR_INTERVAL_MS, &interval_ms);
    data = rsc_action_digest(rsc, task, interval_ms, node, xml_op,
                             pcmk_is_set(data_set->flags, pe_flag_sanitized),
                             data_set);

    data->rc = RSC_DIGEST_MATCH;
    if (digest_restart && data->digest_restart_calc && strcmp(data->digest_restart_calc, digest_restart) != 0) {
        pe_rsc_info(rsc, "Parameters to %ums-interval %s action for %s on %s "
                         "changed: hash was %s vs. now %s (restart:%s) %s",
                    interval_ms, task, rsc->id, node->details->uname,
                    pcmk__s(digest_restart, "missing"),
                    data->digest_restart_calc,
                    op_version,
                    crm_element_value(xml_op, XML_ATTR_TRANSITION_MAGIC));
        data->rc = RSC_DIGEST_RESTART;

    } else if (digest_all == NULL) {
        /* it is unknown what the previous op digest was */
        data->rc = RSC_DIGEST_UNKNOWN;

    } else if (strcmp(digest_all, data->digest_all_calc) != 0) {
        pe_rsc_info(rsc, "Parameters to %ums-interval %s action for %s on %s "
                         "changed: hash was %s vs. now %s (%s:%s) %s",
                    interval_ms, task, rsc->id, node->details->uname,
                    pcmk__s(digest_all, "missing"), data->digest_all_calc,
                    (interval_ms > 0)? "reschedule" : "reload",
                    op_version,
                    crm_element_value(xml_op, XML_ATTR_TRANSITION_MAGIC));
        data->rc = RSC_DIGEST_ALL;
    }
    return data;
}

/*!
 * \internal
 * \brief Create an unfencing summary for use in special node attribute
 *
 * Create a string combining a fence device's resource ID, agent type, and
 * parameter digest (whether for all parameters or just non-private parameters).
 * This can be stored in a special node attribute, allowing us to detect changes
 * in either the agent type or parameters, to know whether unfencing must be
 * redone or can be safely skipped when the device's history is cleaned.
 *
 * \param[in] rsc_id        Fence device resource ID
 * \param[in] agent_type    Fence device agent
 * \param[in] param_digest  Fence device parameter digest
 *
 * \return Newly allocated string with unfencing digest
 * \note The caller is responsible for freeing the result.
 */
static inline char *
create_unfencing_summary(const char *rsc_id, const char *agent_type,
                         const char *param_digest)
{
    return crm_strdup_printf("%s:%s:%s", rsc_id, agent_type, param_digest);
}

/*!
 * \internal
 * \brief Check whether a node can skip unfencing
 *
 * Check whether a fence device's current definition matches a node's
 * stored summary of when it was last unfenced by the device.
 *
 * \param[in] rsc_id        Fence device's resource ID
 * \param[in] agent         Fence device's agent type
 * \param[in] digest_calc   Fence device's current parameter digest
 * \param[in] node_summary  Value of node's special unfencing node attribute
 *                          (a comma-separated list of unfencing summaries for
 *                          all devices that have unfenced this node)
 *
 * \return TRUE if digest matches, FALSE otherwise
 */
static bool
unfencing_digest_matches(const char *rsc_id, const char *agent,
                         const char *digest_calc, const char *node_summary)
{
    bool matches = FALSE;

    if (rsc_id && agent && digest_calc && node_summary) {
        char *search_secure = create_unfencing_summary(rsc_id, agent,
                                                       digest_calc);

        /* The digest was calculated including the device ID and agent,
         * so there is no risk of collision using strstr().
         */
        matches = (strstr(node_summary, search_secure) != NULL);
        crm_trace("Calculated unfencing digest '%s' %sfound in '%s'",
                  search_secure, matches? "" : "not ", node_summary);
        free(search_secure);
    }
    return matches;
}

/* Magic string to use as action name for digest cache entries used for
 * unfencing checks. This is not a real action name (i.e. "on"), so
 * pcmk__check_action_config() won't confuse these entries with real actions.
 */
#define STONITH_DIGEST_TASK "stonith-on"

/*!
 * \internal
 * \brief Calculate fence device digests and digest comparison result
 *
 * \param[in] rsc       Fence device resource
 * \param[in] agent     Fence device's agent type
 * \param[in] node      Node with digest cache to use
 * \param[in] data_set  Cluster working set
 *
 * \return Node's digest cache entry
 */
op_digest_cache_t *
pe__compare_fencing_digest(pe_resource_t *rsc, const char *agent,
                           pe_node_t *node, pe_working_set_t *data_set)
{
    const char *node_summary = NULL;

    // Calculate device's current parameter digests
    op_digest_cache_t *data = rsc_action_digest(rsc, STONITH_DIGEST_TASK, 0U,
                                                node, NULL, TRUE, data_set);

    // Check whether node has special unfencing summary node attribute
    node_summary = pe_node_attribute_raw(node, CRM_ATTR_DIGESTS_ALL);
    if (node_summary == NULL) {
        data->rc = RSC_DIGEST_UNKNOWN;
        return data;
    }

    // Check whether full parameter digest matches
    if (unfencing_digest_matches(rsc->id, agent, data->digest_all_calc,
                                 node_summary)) {
        data->rc = RSC_DIGEST_MATCH;
        return data;
    }

    // Check whether secure parameter digest matches
    node_summary = pe_node_attribute_raw(node, CRM_ATTR_DIGESTS_SECURE);
    if (unfencing_digest_matches(rsc->id, agent, data->digest_secure_calc,
                                 node_summary)) {
        data->rc = RSC_DIGEST_MATCH;
        if (!pcmk__is_daemon && data_set->priv != NULL) {
            pcmk__output_t *out = data_set->priv;
            out->info(out, "Only 'private' parameters to %s "
                      "for unfencing %s changed", rsc->id,
                      node->details->uname);
        }
        return data;
    }

    // Parameters don't match
    data->rc = RSC_DIGEST_ALL;
    if (pcmk_is_set(data_set->flags, pe_flag_sanitized) && data->digest_secure_calc) {
        if (data_set->priv != NULL) {
            pcmk__output_t *out = data_set->priv;
            char *digest = create_unfencing_summary(rsc->id, agent,
                                                    data->digest_secure_calc);

            out->info(out, "Parameters to %s for unfencing "
                      "%s changed, try '%s'", rsc->id,
                      node->details->uname, digest);
            free(digest);
        } else if (!pcmk__is_daemon) {
            char *digest = create_unfencing_summary(rsc->id, agent,
                                                    data->digest_secure_calc);

            printf("Parameters to %s for unfencing %s changed, try '%s'\n",
                   rsc->id, node->details->uname, digest);
            free(digest);
        }
    }
    return data;
}
