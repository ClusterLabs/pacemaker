/*
 * Copyright 2004-2025 the Pacemaker project contributors
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
#include <crm/common/xml.h>
#include <crm/pengine/internal.h>
#include "pe_status_private.h"

/*!
 * \internal
 * \brief Free an operation digest cache entry
 *
 * \param[in,out] ptr  Pointer to cache entry to free
 *
 * \note The argument is a gpointer so this can be used as a hash table
 *       free function.
 */
void
pe__free_digests(gpointer ptr)
{
    pcmk__op_digest_t *data = ptr;

    if (data != NULL) {
        pcmk__xml_free(data->params_all);
        pcmk__xml_free(data->params_secure);
        pcmk__xml_free(data->params_restart);

        free(data->digest_all_calc);
        free(data->digest_restart_calc);
        free(data->digest_secure_calc);

        free(data);
    }
}

// Return true if XML attribute name is an element of a given gchar ** array
static bool
attr_in_strv(const xmlAttr *a, void *user_data)
{
    const char *name = (const char *) a->name;
    gchar **strv = user_data;

    return pcmk__g_strv_contains(strv, name);
}

// Return true if XML attribute name is not an element of a given gchar ** array
static bool
attr_not_in_strv(const xmlAttr *a, void *user_data)
{
    return !attr_in_strv(a, user_data);
}

/*!
 * \internal
 * \brief Add digest of all parameters to a digest cache entry
 *
 * \param[out]    data         Digest cache entry to modify
 * \param[in,out] rsc          Resource that action was for
 * \param[in]     node         Node action was performed on
 * \param[in]     params       Resource parameters evaluated for node
 * \param[in]     task         Name of action performed
 * \param[in,out] interval_ms  Action's interval (will be reset if in overrides)
 * \param[in]     xml_op       Unused
 * \param[in]     op_version   CRM feature set to use for digest calculation
 * \param[in]     overrides    Key/value table to override resource parameters
 * \param[in,out] scheduler    Scheduler data
 */
static void
calculate_main_digest(pcmk__op_digest_t *data, pcmk_resource_t *rsc,
                      const pcmk_node_t *node, GHashTable *params,
                      const char *task, guint *interval_ms,
                      const xmlNode *xml_op, const char *op_version,
                      GHashTable *overrides, pcmk_scheduler_t *scheduler)
{
    xmlNode *action_config = NULL;

    data->params_all = pcmk__xe_create(NULL, PCMK_XE_PARAMETERS);

    /* REMOTE_CONTAINER_HACK: Allow Pacemaker Remote nodes to run containers
     * that themselves are Pacemaker Remote nodes
     */
    (void) pe__add_bundle_remote_name(rsc, data->params_all,
                                      PCMK_REMOTE_RA_ADDR);

    if (overrides != NULL) {
        // If interval was overridden, reset it
        const char *meta_name = CRM_META "_" PCMK_META_INTERVAL;
        const char *interval_s = g_hash_table_lookup(overrides, meta_name);

        if (interval_s != NULL) {
            long long value_ll;

            if ((pcmk__scan_ll(interval_s, &value_ll, 0LL) == pcmk_rc_ok)
                && (value_ll >= 0) && (value_ll <= G_MAXUINT)) {
                *interval_ms = (guint) value_ll;
            }
        }

        // Add overrides to list of all parameters
        g_hash_table_foreach(overrides, hash2field, data->params_all);
    }

    // Add provided instance parameters
    g_hash_table_foreach(params, hash2field, data->params_all);

    // Find action configuration XML in CIB
    action_config = pcmk__find_action_config(rsc, task, *interval_ms, true);

    /* Add action-specific resource instance attributes to the digest list.
     *
     * If this is a one-time action with action-specific instance attributes,
     * enforce a restart instead of reload-agent in case the main digest doesn't
     * match, even if the restart digest does. This ensures any changes of the
     * action-specific parameters get applied for this specific action, and
     * digests calculated for the resulting history will be correct. Default the
     * result to RSC_DIGEST_RESTART for the case where the main digest doesn't
     * match.
     */
    params = pcmk__unpack_action_rsc_params(action_config, node->priv->attrs,
                                            scheduler);
    if ((*interval_ms == 0) && (g_hash_table_size(params) > 0)) {
        data->rc = pcmk__digest_restart;
    }
    g_hash_table_foreach(params, hash2field, data->params_all);
    g_hash_table_destroy(params);

    // Add action meta-attributes
    params = pcmk__unpack_action_meta(rsc, node, task, *interval_ms,
                                      action_config);
    g_hash_table_foreach(params, hash2metafield, data->params_all);
    g_hash_table_destroy(params);

    pcmk__filter_op_for_digest(data->params_all);

    data->digest_all_calc = pcmk__digest_op_params(data->params_all);
}

// Return true if XML attribute name is a Pacemaker-defined fencing parameter
static bool
is_fence_param(const xmlAttr *attr, void *user_data)
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
calculate_secure_digest(pcmk__op_digest_t *data, const pcmk_resource_t *rsc,
                        GHashTable *params, const xmlNode *xml_op,
                        const char *op_version, GHashTable *overrides)
{
    /* @COMPAT CRM_FEATURE_SET was bumped to 3.16.0 in Pacemaker 2.1.5. When we
     * no longer support rolling upgrades from 2.1.4 and below, we can drop the
     * old_version code.
     */
    const char *class = pcmk__xe_get(rsc->priv->xml, PCMK_XA_CLASS);
    const char *secure_list = NULL;
    bool old_version = (pcmk__compare_versions(op_version, "3.16.0") < 0);

    if (xml_op == NULL) {
        secure_list = " passwd password user ";
    } else {
        secure_list = pcmk__xe_get(xml_op, PCMK__XA_OP_SECURE_PARAMS);
    }

    if (old_version) {
        data->params_secure = pcmk__xe_create(NULL, PCMK_XE_PARAMETERS);
        if (overrides != NULL) {
            g_hash_table_foreach(overrides, hash2field, data->params_secure);
        }

        g_hash_table_foreach(params, hash2field, data->params_secure);

    } else {
        // Start with a copy of all parameters
        data->params_secure = pcmk__xml_copy(NULL, data->params_all);
    }

    if (secure_list != NULL) {
        gchar **secure_params = g_strsplit(secure_list, " ", 0);

        pcmk__xe_remove_matching_attrs(data->params_secure, false, attr_in_strv,
                                       secure_params);
        g_strfreev(secure_params);
    }

    if (old_version
        && pcmk__is_set(pcmk_get_ra_caps(class),
                        pcmk_ra_cap_fence_params)) {
        /* For fencing resources, Pacemaker adds special parameters, but these
         * are not listed in fence agent meta-data, so with older versions of
         * DC, the controller will not hash them. That means we have to filter
         * them out before calculating our hash for comparison.
         */
        pcmk__xe_remove_matching_attrs(data->params_secure, false,
                                       is_fence_param, NULL);
    }
    pcmk__filter_op_for_digest(data->params_secure);

    /* CRM_meta_timeout *should* be part of a digest for recurring operations.
     * However, with older versions of DC, the controller does not add timeout
     * to secure digests, because it only includes parameters declared by the
     * resource agent.
     * Remove any timeout that made it this far, to match.
     */
    if (old_version) {
        pcmk__xe_remove_attr(data->params_secure,
                             CRM_META "_" PCMK_META_TIMEOUT);
    }

    data->digest_secure_calc = pcmk__digest_op_params(data->params_secure);
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
calculate_restart_digest(pcmk__op_digest_t *data, const xmlNode *xml_op,
                         const char *op_version)
{
    const char *value = NULL;

    // We must have XML of resource operation history
    if (xml_op == NULL) {
        return;
    }

    // And the history must have a restart digest to compare against
    if (pcmk__xe_get(xml_op, PCMK__XA_OP_RESTART_DIGEST) == NULL) {
        return;
    }

    // Start with a copy of all parameters
    data->params_restart = pcmk__xml_copy(NULL, data->params_all);

    // Then filter out reloadable parameters, if any
    value = pcmk__xe_get(xml_op, PCMK__XA_OP_FORCE_RESTART);
    if (value != NULL) {
        gchar **restart_params = g_strsplit(value, " ", 0);

        pcmk__xe_remove_matching_attrs(data->params_restart, false,
                                       attr_not_in_strv, restart_params);
        g_strfreev(restart_params);
    }

    data->digest_restart_calc = pcmk__digest_op_params(data->params_restart);
}

/*!
 * \internal
 * \brief Create a new digest cache entry with calculated digests
 *
 * \param[in,out] rsc          Resource that action was for
 * \param[in]     task         Name of action performed
 * \param[in,out] interval_ms  Action's interval (will be reset if in overrides)
 * \param[in]     node         Node action was performed on
 * \param[in]     xml_op       XML of operation in CIB status (if available)
 * \param[in]     overrides    Key/value table to override resource parameters
 * \param[in]     calc_secure  Whether to calculate secure digest
 * \param[in,out] scheduler    Scheduler data
 *
 * \return Pointer to new digest cache entry (or NULL on memory error)
 * \note It is the caller's responsibility to free the result using
 *       pe__free_digests().
 */
pcmk__op_digest_t *
pe__calculate_digests(pcmk_resource_t *rsc, const char *task,
                      guint *interval_ms, const pcmk_node_t *node,
                      const xmlNode *xml_op, GHashTable *overrides,
                      bool calc_secure, pcmk_scheduler_t *scheduler)
{
    pcmk__op_digest_t *data = NULL;
    const char *op_version = NULL;
    GHashTable *params = NULL;

    CRM_CHECK(scheduler != NULL, return NULL);

    data = calloc(1, sizeof(pcmk__op_digest_t));
    if (data == NULL) {
        pcmk__sched_err(scheduler,
                        "Could not allocate memory for operation digest");
        return NULL;
    }

    data->rc = pcmk__digest_match;

    if (xml_op != NULL) {
        op_version = pcmk__xe_get(xml_op, PCMK_XA_CRM_FEATURE_SET);
    }

    if ((op_version == NULL) && (scheduler->input != NULL)) {
        op_version = pcmk__xe_get(scheduler->input, PCMK_XA_CRM_FEATURE_SET);
    }

    if (op_version == NULL) {
        op_version = CRM_FEATURE_SET;
    }

    params = pe_rsc_params(rsc, node, scheduler);
    calculate_main_digest(data, rsc, node, params, task, interval_ms, xml_op,
                          op_version, overrides, scheduler);
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
 * \param[in,out] rsc          Resource that action was for
 * \param[in]     task         Name of action performed
 * \param[in]     interval_ms  Action's interval
 * \param[in,out] node         Node action was performed on
 * \param[in]     xml_op       XML of operation in CIB status (if available)
 * \param[in]     calc_secure  Whether to calculate secure digest
 * \param[in,out] scheduler    Scheduler data
 *
 * \return Pointer to node's digest cache entry
 */
static pcmk__op_digest_t *
rsc_action_digest(pcmk_resource_t *rsc, const char *task, guint interval_ms,
                  pcmk_node_t *node, const xmlNode *xml_op,
                  bool calc_secure, pcmk_scheduler_t *scheduler)
{
    pcmk__op_digest_t *data = NULL;
    char *key = pcmk__op_key(rsc->id, task, interval_ms);

    data = g_hash_table_lookup(node->priv->digest_cache, key);
    if (data == NULL) {
        data = pe__calculate_digests(rsc, task, &interval_ms, node, xml_op,
                                     NULL, calc_secure, scheduler);
        pcmk__assert(data != NULL);
        g_hash_table_insert(node->priv->digest_cache, strdup(key), data);
    }
    free(key);
    return data;
}

/*!
 * \internal
 * \brief Calculate operation digests and compare against an XML history entry
 *
 * \param[in,out] rsc        Resource to check
 * \param[in]     xml_op     Resource history XML
 * \param[in,out] node       Node to use for digest calculation
 * \param[in,out] scheduler  Scheduler data
 *
 * \return Pointer to node's digest cache entry, with comparison result set
 */
pcmk__op_digest_t *
rsc_action_digest_cmp(pcmk_resource_t *rsc, const xmlNode *xml_op,
                      pcmk_node_t *node, pcmk_scheduler_t *scheduler)
{
    pcmk__op_digest_t *data = NULL;
    guint interval_ms = 0;

    const char *op_version;
    const char *task = pcmk__xe_get(xml_op, PCMK_XA_OPERATION);
    const char *digest_all;
    const char *digest_restart;

    pcmk__assert(node != NULL);

    op_version = pcmk__xe_get(xml_op, PCMK_XA_CRM_FEATURE_SET);
    digest_all = pcmk__xe_get(xml_op, PCMK__XA_OP_DIGEST);
    digest_restart = pcmk__xe_get(xml_op, PCMK__XA_OP_RESTART_DIGEST);

    pcmk__xe_get_guint(xml_op, PCMK_META_INTERVAL, &interval_ms);
    data = rsc_action_digest(rsc, task, interval_ms, node, xml_op,
                             pcmk__is_set(scheduler->flags,
                                          pcmk__sched_sanitized),
                             scheduler);

    if (!pcmk__str_eq(data->digest_restart_calc, digest_restart,
                      pcmk__str_null_matches)) {
        pcmk__rsc_info(rsc,
                       "Parameter change for %s-interval %s of %s on %s "
                       "requires restart (hash now %s vs. %s "
                       "with op feature set %s for transition %s)",
                       pcmk__readable_interval(interval_ms), task, rsc->id,
                       pcmk__node_name(node), data->digest_restart_calc,
                       pcmk__s(digest_restart, "missing"), op_version,
                       pcmk__xe_get(xml_op, PCMK__XA_TRANSITION_MAGIC));
        data->rc = pcmk__digest_restart;

    } else if (digest_all == NULL) {
        /* it is unknown what the previous op digest was */
        data->rc = pcmk__digest_unknown;

    } else if (strcmp(digest_all, data->digest_all_calc) != 0) {
        /* Given a non-recurring operation with extra parameters configured,
         * in case that the main digest doesn't match, even if the restart
         * digest matches, enforce a restart rather than a reload-agent anyway.
         * So that it ensures any changes of the extra parameters get applied
         * for this specific operation, and the digests calculated for the
         * resulting PCMK__XE_LRM_RSC_OP will be correct.
         * Preserve the implied rc pcmk__digest_restart for the case that the
         * main digest doesn't match.
         */
        if ((interval_ms == 0) && (data->rc == pcmk__digest_restart)) {
            pcmk__rsc_info(rsc,
                           "Parameters containing extra ones to %ums-interval"
                           " %s action for %s on %s "
                           "changed: hash was %s vs. now %s (restart:%s) %s",
                           interval_ms, task, rsc->id, pcmk__node_name(node),
                           pcmk__s(digest_all, "missing"),
                           data->digest_all_calc, op_version,
                           pcmk__xe_get(xml_op, PCMK__XA_TRANSITION_MAGIC));

        } else {
            pcmk__rsc_info(rsc,
                           "Parameters to %ums-interval %s action for %s on %s "
                           "changed: hash was %s vs. now %s (%s:%s) %s",
                           interval_ms, task, rsc->id, pcmk__node_name(node),
                           pcmk__s(digest_all, "missing"),
                           data->digest_all_calc,
                           (interval_ms > 0)? "reschedule" : "reload",
                           op_version,
                           pcmk__xe_get(xml_op, PCMK__XA_TRANSITION_MAGIC));
            data->rc = pcmk__digest_mismatch;
        }

    } else {
        data->rc = pcmk__digest_match;
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
    return pcmk__assert_asprintf("%s:%s:%s", rsc_id, agent_type, param_digest);
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
        pcmk__trace("Calculated unfencing digest '%s' %sfound in '%s'",
                    search_secure, (matches? "" : "not "), node_summary);
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
 * \param[in,out] rsc        Fence device resource
 * \param[in]     agent      Fence device's agent type
 * \param[in,out] node       Node with digest cache to use
 * \param[in,out] scheduler  Scheduler data
 *
 * \return Node's digest cache entry
 */
pcmk__op_digest_t *
pe__compare_fencing_digest(pcmk_resource_t *rsc, const char *agent,
                           pcmk_node_t *node, pcmk_scheduler_t *scheduler)
{
    const char *node_summary = NULL;

    // Calculate device's current parameter digests
    pcmk__op_digest_t *data = rsc_action_digest(rsc, STONITH_DIGEST_TASK, 0U,
                                                node, NULL, TRUE, scheduler);

    // Check whether node has special unfencing summary node attribute
    node_summary = pcmk__node_attr(node, CRM_ATTR_DIGESTS_ALL, NULL,
                                   pcmk__rsc_node_current);
    if (node_summary == NULL) {
        data->rc = pcmk__digest_unknown;
        return data;
    }

    // Check whether full parameter digest matches
    if (unfencing_digest_matches(rsc->id, agent, data->digest_all_calc,
                                 node_summary)) {
        data->rc = pcmk__digest_match;
        return data;
    }

    // Check whether secure parameter digest matches
    node_summary = pcmk__node_attr(node, CRM_ATTR_DIGESTS_SECURE, NULL,
                                   pcmk__rsc_node_current);
    if (unfencing_digest_matches(rsc->id, agent, data->digest_secure_calc,
                                 node_summary)) {
        data->rc = pcmk__digest_match;
        if (!pcmk__is_daemon && (scheduler->priv->out != NULL)) {
            pcmk__output_t *out = scheduler->priv->out;

            out->info(out, "Only 'private' parameters to %s "
                      "for unfencing %s changed", rsc->id,
                      pcmk__node_name(node));
        }
        return data;
    }

    // Parameters don't match
    data->rc = pcmk__digest_mismatch;
    if (pcmk__is_set(scheduler->flags, pcmk__sched_sanitized)
        && (data->digest_secure_calc != NULL)) {

        if (scheduler->priv->out != NULL) {
            pcmk__output_t *out = scheduler->priv->out;
            char *digest = create_unfencing_summary(rsc->id, agent,
                                                    data->digest_secure_calc);

            out->info(out, "Parameters to %s for unfencing "
                      "%s changed, try '%s'", rsc->id,
                      pcmk__node_name(node), digest);
            free(digest);
        } else if (!pcmk__is_daemon) {
            char *digest = create_unfencing_summary(rsc->id, agent,
                                                    data->digest_secure_calc);

            printf("Parameters to %s for unfencing %s changed, try '%s'\n",
                   rsc->id, pcmk__node_name(node), digest);
            free(digest);
        }
    }
    return data;
}
