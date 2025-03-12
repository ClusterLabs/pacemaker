/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdint.h>

#include <crm/common/output.h>
#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>
#include <crm/pengine/complex.h>
#include <crm/pengine/internal.h>
#include <crm/common/xml.h>
#include <pe_status_private.h>

#ifdef PCMK__COMPAT_2_0
#define PROVIDER_SEP "::"
#else
#define PROVIDER_SEP ":"
#endif

/*!
 * \internal
 * \brief Check whether a resource is active on multiple nodes
 */
static bool
is_multiply_active(const pcmk_resource_t *rsc)
{
    unsigned int count = 0;

    if (pcmk__is_primitive(rsc)) {
        pe__find_active_requires(rsc, &count);
    }
    return count > 1;
}

static void
native_priority_to_node(pcmk_resource_t *rsc, pcmk_node_t *node,
                        gboolean failed)
{
    int priority = 0;

    if ((rsc->priority == 0) || (failed == TRUE)) {
        return;
    }

    if (rsc->role == pcmk_role_promoted) {
        // Promoted instance takes base priority + 1
        priority = rsc->priority + 1;

    } else {
        priority = rsc->priority;
    }

    node->details->priority += priority;
    pcmk__rsc_trace(rsc, "%s now has priority %d with %s'%s' (priority: %d%s)",
                    pcmk__node_name(node), node->details->priority,
                    (rsc->role == pcmk_role_promoted)? "promoted " : "",
                    rsc->id, rsc->priority,
                    (rsc->role == pcmk_role_promoted)? " + 1" : "");

    /* Priority of a resource running on a guest node is added to the cluster
     * node as well. */
    if (node->details->remote_rsc
        && node->details->remote_rsc->container) {
        GList *gIter = node->details->remote_rsc->container->running_on;

        for (; gIter != NULL; gIter = gIter->next) {
            pcmk_node_t *a_node = gIter->data;

            a_node->details->priority += priority;
            pcmk__rsc_trace(rsc,
                            "%s now has priority %d with %s'%s' "
                            "(priority: %d%s) from guest node %s",
                            pcmk__node_name(a_node), a_node->details->priority,
                            (rsc->role == pcmk_role_promoted)? "promoted " : "",
                            rsc->id, rsc->priority,
                            (rsc->role == pcmk_role_promoted)? " + 1" : "",
                            pcmk__node_name(node));
        }
    }
}

void
native_add_running(pcmk_resource_t *rsc, pcmk_node_t *node,
                   pcmk_scheduler_t *scheduler, gboolean failed)
{
    GList *gIter = rsc->running_on;

    CRM_CHECK(node != NULL, return);
    for (; gIter != NULL; gIter = gIter->next) {
        pcmk_node_t *a_node = (pcmk_node_t *) gIter->data;

        CRM_CHECK(a_node != NULL, return);
        if (pcmk__str_eq(a_node->details->id, node->details->id, pcmk__str_casei)) {
            return;
        }
    }

    pcmk__rsc_trace(rsc, "Adding %s to %s %s", rsc->id, pcmk__node_name(node),
                    pcmk_is_set(rsc->flags, pcmk_rsc_managed)? "" : "(unmanaged)");

    rsc->running_on = g_list_append(rsc->running_on, node);
    if (pcmk__is_primitive(rsc)) {
        node->details->running_rsc = g_list_append(node->details->running_rsc, rsc);
        native_priority_to_node(rsc, node, failed);
        if (node->details->maintenance) {
            pcmk__clear_rsc_flags(rsc, pcmk_rsc_managed);
            pcmk__set_rsc_flags(rsc, pcmk_rsc_maintenance);
        }
    }

    if (!pcmk_is_set(rsc->flags, pcmk_rsc_managed)) {
        pcmk_resource_t *p = rsc->parent;

        pcmk__rsc_info(rsc, "resource %s isn't managed", rsc->id);
        resource_location(rsc, node, PCMK_SCORE_INFINITY,
                          "not_managed_default", scheduler);

        while(p) {
            /* add without the additional location constraint */
            p->running_on = g_list_append(p->running_on, node);
            p = p->parent;
        }
        return;
    }

    if (is_multiply_active(rsc)) {
        switch (rsc->recovery_type) {
            case pcmk_multiply_active_stop:
                {
                    GHashTableIter gIter;
                    pcmk_node_t *local_node = NULL;

                    /* make sure it doesn't come up again */
                    if (rsc->allowed_nodes != NULL) {
                        g_hash_table_destroy(rsc->allowed_nodes);
                    }
                    rsc->allowed_nodes = pe__node_list2table(scheduler->nodes);
                    g_hash_table_iter_init(&gIter, rsc->allowed_nodes);
                    while (g_hash_table_iter_next(&gIter, NULL, (void **)&local_node)) {
                        local_node->weight = -PCMK_SCORE_INFINITY;
                    }
                }
                break;
            case pcmk_multiply_active_block:
                pcmk__clear_rsc_flags(rsc, pcmk_rsc_managed);
                pcmk__set_rsc_flags(rsc, pcmk_rsc_blocked);

                /* If the resource belongs to a group or bundle configured with
                 * PCMK_META_MULTIPLE_ACTIVE=PCMK_VALUE_BLOCK, block the entire
                 * entity.
                 */
                if ((pcmk__is_group(rsc->parent)
                     || pcmk__is_bundle(rsc->parent))
                    && (rsc->parent->recovery_type == pcmk_multiply_active_block)) {
                    GList *gIter = rsc->parent->children;

                    for (; gIter != NULL; gIter = gIter->next) {
                        pcmk_resource_t *child = gIter->data;

                        pcmk__clear_rsc_flags(child, pcmk_rsc_managed);
                        pcmk__set_rsc_flags(child, pcmk_rsc_blocked);
                    }
                }
                break;

            // pcmk_multiply_active_restart, pcmk_multiply_active_unexpected
            default:
                /* The scheduler will do the right thing because the relevant
                 * variables and flags are set when unpacking the history.
                 */
                break;
        }
        crm_debug("%s is active on multiple nodes including %s: %s",
                  rsc->id, pcmk__node_name(node),
                  pcmk__multiply_active_text(rsc->recovery_type));

    } else {
        pcmk__rsc_trace(rsc, "Resource %s is active on %s",
                        rsc->id, pcmk__node_name(node));
    }

    if (rsc->parent != NULL) {
        native_add_running(rsc->parent, node, scheduler, FALSE);
    }
}

static void
recursive_clear_unique(pcmk_resource_t *rsc, gpointer user_data)
{
    pcmk__clear_rsc_flags(rsc, pcmk_rsc_unique);
    pcmk__insert_meta(rsc, PCMK_META_GLOBALLY_UNIQUE, PCMK_VALUE_FALSE);
    g_list_foreach(rsc->children, (GFunc) recursive_clear_unique, NULL);
}

gboolean
native_unpack(pcmk_resource_t *rsc, pcmk_scheduler_t *scheduler)
{
    pcmk_resource_t *parent = uber_parent(rsc);
    const char *standard = crm_element_value(rsc->xml, PCMK_XA_CLASS);
    uint32_t ra_caps = pcmk_get_ra_caps(standard);

    pcmk__rsc_trace(rsc, "Processing resource %s...", rsc->id);

    // Only some agent standards support unique and promotable clones
    if (!pcmk_is_set(ra_caps, pcmk_ra_cap_unique)
        && pcmk_is_set(rsc->flags, pcmk_rsc_unique)
        && pcmk__is_clone(parent)) {

        /* @COMPAT We should probably reject this situation as an error (as we
         * do for promotable below) rather than warn and convert, but that would
         * be a backward-incompatible change that we should probably do with a
         * transform at a schema major version bump.
         */
        pe__force_anon(standard, parent, rsc->id, scheduler);

        /* Clear PCMK_META_GLOBALLY_UNIQUE on the parent and all its descendants
         * unpacked so far (clearing the parent should make any future children
         * unpacking correct). We have to clear this resource explicitly because
         * it isn't hooked into the parent's children yet.
         */
        recursive_clear_unique(parent, NULL);
        recursive_clear_unique(rsc, NULL);
    }
    if (!pcmk_is_set(ra_caps, pcmk_ra_cap_promotable)
        && pcmk_is_set(parent->flags, pcmk_rsc_promotable)) {

        pcmk__config_err("Resource %s is of type %s and therefore "
                         "cannot be used as a promotable clone resource",
                         rsc->id, standard);
        return FALSE;
    }
    return TRUE;
}

static bool
rsc_is_on_node(pcmk_resource_t *rsc, const pcmk_node_t *node, int flags)
{
    pcmk__rsc_trace(rsc, "Checking whether %s is on %s",
                    rsc->id, pcmk__node_name(node));

    if (pcmk_is_set(flags, pcmk_rsc_match_current_node)
        && (rsc->running_on != NULL)) {

        for (GList *iter = rsc->running_on; iter; iter = iter->next) {
            if (pcmk__same_node((pcmk_node_t *) iter->data, node)) {
                return true;
            }
        }

    } else if (pcmk_is_set(flags, pe_find_inactive) // @COMPAT deprecated
               && (rsc->running_on == NULL)) {
        return true;

    } else if (!pcmk_is_set(flags, pcmk_rsc_match_current_node)
               && (rsc->allocated_to != NULL)
               && pcmk__same_node(rsc->allocated_to, node)) {
        return true;
    }
    return false;
}

pcmk_resource_t *
native_find_rsc(pcmk_resource_t *rsc, const char *id,
                const pcmk_node_t *on_node, int flags)
{
    bool match = false;
    pcmk_resource_t *result = NULL;

    CRM_CHECK(id && rsc && rsc->id, return NULL);

    if (pcmk_is_set(flags, pcmk_rsc_match_clone_only)) {
        const char *rid = pcmk__xe_id(rsc->xml);

        if (!pcmk__is_clone(pe__const_top_resource(rsc, false))) {
            match = false;

        } else if (!strcmp(id, rsc->id) || pcmk__str_eq(id, rid, pcmk__str_none)) {
            match = true;
        }

    } else if (!strcmp(id, rsc->id)) {
        match = true;

    } else if (pcmk_is_set(flags, pcmk_rsc_match_history)
               && rsc->clone_name && strcmp(rsc->clone_name, id) == 0) {
        match = true;

    } else if (pcmk_is_set(flags, pcmk_rsc_match_basename)
               || (pcmk_is_set(flags, pcmk_rsc_match_anon_basename)
                   && !pcmk_is_set(rsc->flags, pcmk_rsc_unique))) {
        match = pe_base_name_eq(rsc, id);
    }

    if (match && on_node) {
        if (!rsc_is_on_node(rsc, on_node, flags)) {
            match = false;
        }
    }

    if (match) {
        return rsc;
    }

    for (GList *gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        pcmk_resource_t *child = (pcmk_resource_t *) gIter->data;

        result = rsc->fns->find_rsc(child, id, on_node, flags);
        if (result) {
            return result;
        }
    }
    return NULL;
}

// create is ignored
char *
native_parameter(pcmk_resource_t *rsc, pcmk_node_t *node, gboolean create,
                 const char *name, pcmk_scheduler_t *scheduler)
{
    const char *value = NULL;
    GHashTable *params = NULL;

    CRM_CHECK(rsc != NULL, return NULL);
    CRM_CHECK(name != NULL && strlen(name) != 0, return NULL);

    pcmk__rsc_trace(rsc, "Looking up %s in %s", name, rsc->id);
    params = pe_rsc_params(rsc, node, scheduler);
    value = g_hash_table_lookup(params, name);
    if (value == NULL) {
        /* try meta attributes instead */
        value = g_hash_table_lookup(rsc->meta, name);
    }
    return pcmk__str_copy(value);
}

gboolean
native_active(pcmk_resource_t * rsc, gboolean all)
{
    for (GList *gIter = rsc->running_on; gIter != NULL; gIter = gIter->next) {
        pcmk_node_t *a_node = (pcmk_node_t *) gIter->data;

        if (a_node->details->unclean) {
            pcmk__rsc_trace(rsc, "Resource %s: %s is unclean",
                            rsc->id, pcmk__node_name(a_node));
            return TRUE;
        } else if (!a_node->details->online
                   && pcmk_is_set(rsc->flags, pcmk_rsc_managed)) {
            pcmk__rsc_trace(rsc, "Resource %s: %s is offline",
                            rsc->id, pcmk__node_name(a_node));
        } else {
            pcmk__rsc_trace(rsc, "Resource %s active on %s",
                            rsc->id, pcmk__node_name(a_node));
            return TRUE;
        }
    }
    return FALSE;
}

struct print_data_s {
    long options;
    void *print_data;
};

static const char *
native_pending_state(const pcmk_resource_t *rsc)
{
    const char *pending_state = NULL;

    if (pcmk__str_eq(rsc->pending_task, PCMK_ACTION_START, pcmk__str_casei)) {
        pending_state = "Starting";

    } else if (pcmk__str_eq(rsc->pending_task, PCMK_ACTION_STOP,
                            pcmk__str_casei)) {
        pending_state = "Stopping";

    } else if (pcmk__str_eq(rsc->pending_task, PCMK_ACTION_MIGRATE_TO,
                            pcmk__str_casei)) {
        pending_state = "Migrating";

    } else if (pcmk__str_eq(rsc->pending_task, PCMK_ACTION_MIGRATE_FROM,
                            pcmk__str_casei)) {
       /* Work might be done in here. */
        pending_state = "Migrating";

    } else if (pcmk__str_eq(rsc->pending_task, PCMK_ACTION_PROMOTE,
                            pcmk__str_casei)) {
        pending_state = "Promoting";

    } else if (pcmk__str_eq(rsc->pending_task, PCMK_ACTION_DEMOTE,
                            pcmk__str_casei)) {
        pending_state = "Demoting";
    }

    return pending_state;
}

static const char *
native_pending_task(const pcmk_resource_t *rsc)
{
    const char *pending_task = NULL;

    if (pcmk__str_eq(rsc->pending_task, PCMK_ACTION_MONITOR, pcmk__str_casei)) {
        pending_task = "Monitoring";

    /* Pending probes are not printed, even if pending
     * operations are requested. If someone ever requests that
     * behavior, uncomment this and the corresponding part of
     * unpack.c:unpack_rsc_op().
     */
    /*
    } else if (pcmk__str_eq(rsc->pending_task, "probe", pcmk__str_casei)) {
        pending_task = "Checking";
    */
    }

    return pending_task;
}

static enum rsc_role_e
native_displayable_role(const pcmk_resource_t *rsc)
{
    enum rsc_role_e role = rsc->role;

    if ((role == pcmk_role_started)
        && pcmk_is_set(pe__const_top_resource(rsc, false)->flags,
                       pcmk_rsc_promotable)) {

        role = pcmk_role_unpromoted;
    }
    return role;
}

static const char *
native_displayable_state(const pcmk_resource_t *rsc, bool print_pending)
{
    const char *rsc_state = NULL;

    if (print_pending) {
        rsc_state = native_pending_state(rsc);
    }
    if (rsc_state == NULL) {
        rsc_state = pcmk_role_text(native_displayable_role(rsc));
    }
    return rsc_state;
}

/*!
 * \internal
 * \deprecated This function will be removed in a future release
 */
static void
native_print_xml(pcmk_resource_t *rsc, const char *pre_text, long options,
                 void *print_data)
{
    const char *class = crm_element_value(rsc->xml, PCMK_XA_CLASS);
    const char *prov = crm_element_value(rsc->xml, PCMK_XA_PROVIDER);
    const char *rsc_state = native_displayable_state(rsc, pcmk_is_set(options, pe_print_pending));
    const char *target_role = NULL;

    /* resource information. */
    status_print("%s<resource ", pre_text);
    status_print(PCMK_XA_ID "=\"%s\" ", rsc_printable_id(rsc));
    status_print("resource_agent=\"%s%s%s:%s\" ", class,
                 ((prov == NULL)? "" : PROVIDER_SEP),
                 ((prov == NULL)? "" : prov),
                 crm_element_value(rsc->xml, PCMK_XA_TYPE));

    status_print("role=\"%s\" ", rsc_state);
    if (rsc->meta) {
        target_role = g_hash_table_lookup(rsc->meta, PCMK_META_TARGET_ROLE);
    }
    if (target_role) {
        status_print("target_role=\"%s\" ", target_role);
    }
    status_print("active=\"%s\" ", pcmk__btoa(rsc->fns->active(rsc, TRUE)));
    status_print("orphaned=\"%s\" ",
                 pcmk__flag_text(rsc->flags, pcmk_rsc_removed));
    status_print("blocked=\"%s\" ",
                 pcmk__flag_text(rsc->flags, pcmk_rsc_blocked));
    status_print("managed=\"%s\" ",
                 pcmk__flag_text(rsc->flags, pcmk_rsc_managed));
    status_print("failed=\"%s\" ",
                 pcmk__flag_text(rsc->flags, pcmk_rsc_failed));
    status_print("failure_ignored=\"%s\" ",
                 pcmk__flag_text(rsc->flags, pcmk_rsc_ignore_failure));
    status_print("nodes_running_on=\"%d\" ", g_list_length(rsc->running_on));

    if (options & pe_print_pending) {
        const char *pending_task = native_pending_task(rsc);

        if (pending_task) {
            status_print("pending=\"%s\" ", pending_task);
        }
    }

    /* print out the nodes this resource is running on */
    if (options & pe_print_rsconly) {
        status_print("/>\n");
        /* do nothing */
    } else if (rsc->running_on != NULL) {
        GList *gIter = rsc->running_on;

        status_print(">\n");
        for (; gIter != NULL; gIter = gIter->next) {
            pcmk_node_t *node = (pcmk_node_t *) gIter->data;

            status_print("%s    <node " PCMK_XA_NAME "=\"%s\" "
                         PCMK_XA_ID "=\"%s\" cached=\"%s\"/>\n",
                         pre_text, pcmk__s(node->details->uname, ""),
                         node->details->id, pcmk__btoa(!node->details->online));
        }
        status_print("%s</resource>\n", pre_text);
    } else {
        status_print("/>\n");
    }
}

// Append a flag to resource description string's flags list
static bool
add_output_flag(GString *s, const char *flag_desc, bool have_flags)
{
    g_string_append(s, (have_flags? ", " : " ("));
    g_string_append(s, flag_desc);
    return true;
}

// Append a node name to resource description string's node list
static bool
add_output_node(GString *s, const char *node, bool have_nodes)
{
    g_string_append(s, (have_nodes? " " : " [ "));
    g_string_append(s, node);
    return true;
}

/*!
 * \internal
 * \brief Create a string description of a resource
 *
 * \param[in] rsc          Resource to describe
 * \param[in] name         Desired identifier for the resource
 * \param[in] node         If not NULL, node that resource is "on"
 * \param[in] show_opts    Bitmask of pcmk_show_opt_e.
 * \param[in] target_role  Resource's target role
 * \param[in] show_nodes   Whether to display nodes when multiply active
 *
 * \return Newly allocated string description of resource
 * \note Caller must free the result with g_free().
 */
gchar *
pcmk__native_output_string(const pcmk_resource_t *rsc, const char *name,
                           const pcmk_node_t *node, uint32_t show_opts,
                           const char *target_role, bool show_nodes)
{
    const char *class = crm_element_value(rsc->xml, PCMK_XA_CLASS);
    const char *provider = NULL;
    const char *kind = crm_element_value(rsc->xml, PCMK_XA_TYPE);
    GString *outstr = NULL;
    bool have_flags = false;

    if (!pcmk__is_primitive(rsc)) {
        return NULL;
    }

    CRM_CHECK(name != NULL, name = "unknown");
    CRM_CHECK(kind != NULL, kind = "unknown");
    CRM_CHECK(class != NULL, class = "unknown");

    if (pcmk_is_set(pcmk_get_ra_caps(class), pcmk_ra_cap_provider)) {
        provider = crm_element_value(rsc->xml, PCMK_XA_PROVIDER);
    }

    if ((node == NULL) && (rsc->lock_node != NULL)) {
        node = rsc->lock_node;
    }
    if (pcmk_any_flags_set(show_opts, pcmk_show_rsc_only)
        || pcmk__list_of_multiple(rsc->running_on)) {
        node = NULL;
    }

    outstr = g_string_sized_new(128);

    // Resource name and agent
    pcmk__g_strcat(outstr,
                   name, "\t(", class, ((provider == NULL)? "" : PROVIDER_SEP),
                   pcmk__s(provider, ""), ":", kind, "):\t", NULL);

    // State on node
    if (pcmk_is_set(rsc->flags, pcmk_rsc_removed)) {
        g_string_append(outstr, " ORPHANED");
    }
    if (pcmk_is_set(rsc->flags, pcmk_rsc_failed)) {
        enum rsc_role_e role = native_displayable_role(rsc);

        g_string_append(outstr, " FAILED");
        if (role > pcmk_role_unpromoted) {
            pcmk__add_word(&outstr, 0, pcmk_role_text(role));
        }
    } else {
        bool show_pending = pcmk_is_set(show_opts, pcmk_show_pending);

        pcmk__add_word(&outstr, 0, native_displayable_state(rsc, show_pending));
    }
    if (node) {
        pcmk__add_word(&outstr, 0, pcmk__node_name(node));
    }

    // Failed probe operation
    if (native_displayable_role(rsc) == pcmk_role_stopped) {
        xmlNode *probe_op = pe__failed_probe_for_rsc(rsc, node ? node->details->uname : NULL);
        if (probe_op != NULL) {
            int rc;

            pcmk__scan_min_int(crm_element_value(probe_op, PCMK__XA_RC_CODE),
                               &rc, 0);
            pcmk__g_strcat(outstr, " (", services_ocf_exitcode_str(rc), ") ",
                           NULL);
        }
    }

    // Flags, as: (<flag> [...])
    if (node && !(node->details->online) && node->details->unclean) {
        have_flags = add_output_flag(outstr, "UNCLEAN", have_flags);
    }
    if (node && (node == rsc->lock_node)) {
        have_flags = add_output_flag(outstr, "LOCKED", have_flags);
    }
    if (pcmk_is_set(show_opts, pcmk_show_pending)) {
        const char *pending_task = native_pending_task(rsc);

        if (pending_task) {
            have_flags = add_output_flag(outstr, pending_task, have_flags);
        }
    }
    if (target_role != NULL) {
        switch (pcmk_parse_role(target_role)) {
            case pcmk_role_unknown:
                pcmk__config_err("Invalid " PCMK_META_TARGET_ROLE
                                 " %s for resource %s", target_role, rsc->id);
                break;

            case pcmk_role_stopped:
                have_flags = add_output_flag(outstr, "disabled", have_flags);
                break;

            case pcmk_role_unpromoted:
                if (pcmk_is_set(pe__const_top_resource(rsc, false)->flags,
                                pcmk_rsc_promotable)) {
                    have_flags = add_output_flag(outstr,
                                                 PCMK_META_TARGET_ROLE ":",
                                                 have_flags);
                    g_string_append(outstr, target_role);
                }
                break;

            default:
                /* Only show target role if it limits our abilities (i.e. ignore
                 * Started, as it is the default anyways, and doesn't prevent
                 * the resource from becoming promoted).
                 */
                break;
        }
    }

    // Blocked or maintenance implies unmanaged
    if (pcmk_any_flags_set(rsc->flags,
                           pcmk_rsc_blocked|pcmk_rsc_maintenance)) {
        if (pcmk_is_set(rsc->flags, pcmk_rsc_blocked)) {
            have_flags = add_output_flag(outstr, "blocked", have_flags);

        } else if (pcmk_is_set(rsc->flags, pcmk_rsc_maintenance)) {
            have_flags = add_output_flag(outstr, "maintenance", have_flags);
        }
    } else if (!pcmk_is_set(rsc->flags, pcmk_rsc_managed)) {
        have_flags = add_output_flag(outstr, "unmanaged", have_flags);
    }

    if (pcmk_is_set(rsc->flags, pcmk_rsc_ignore_failure)) {
        have_flags = add_output_flag(outstr, "failure ignored", have_flags);
    }


    if (have_flags) {
        g_string_append_c(outstr, ')');
    }

    // User-supplied description
    if (pcmk_any_flags_set(show_opts, pcmk_show_rsc_only|pcmk_show_description)
        || pcmk__list_of_multiple(rsc->running_on)) {
        const char *desc = crm_element_value(rsc->xml, PCMK_XA_DESCRIPTION);

        if (desc) {
            g_string_append(outstr, " (");
            g_string_append(outstr, desc);
            g_string_append(outstr, ")");

        }
    }

    if (show_nodes && !pcmk_is_set(show_opts, pcmk_show_rsc_only)
        && pcmk__list_of_multiple(rsc->running_on)) {
        bool have_nodes = false;

        for (GList *iter = rsc->running_on; iter != NULL; iter = iter->next) {
            pcmk_node_t *n = (pcmk_node_t *) iter->data;

            have_nodes = add_output_node(outstr, n->details->uname, have_nodes);
        }
        if (have_nodes) {
            g_string_append(outstr, " ]");
        }
    }

    return g_string_free(outstr, FALSE);
}

int
pe__common_output_html(pcmk__output_t *out, const pcmk_resource_t *rsc,
                       const char *name, const pcmk_node_t *node,
                       uint32_t show_opts)
{
    const char *kind = crm_element_value(rsc->xml, PCMK_XA_TYPE);
    const char *target_role = NULL;
    const char *cl = NULL;

    xmlNode *child = NULL;
    gchar *content = NULL;

    pcmk__assert((kind != NULL) && pcmk__is_primitive(rsc));

    if (rsc->meta) {
        const char *is_internal = g_hash_table_lookup(rsc->meta,
                                                      PCMK__META_INTERNAL_RSC);

        if (crm_is_true(is_internal)
            && !pcmk_is_set(show_opts, pcmk_show_implicit_rscs)) {

            crm_trace("skipping print of internal resource %s", rsc->id);
            return pcmk_rc_no_output;
        }
        target_role = g_hash_table_lookup(rsc->meta, PCMK_META_TARGET_ROLE);
    }

    if (!pcmk_is_set(rsc->flags, pcmk_rsc_managed)) {
        cl = PCMK__VALUE_RSC_MANAGED;

    } else if (pcmk_is_set(rsc->flags, pcmk_rsc_failed)) {
        cl = PCMK__VALUE_RSC_FAILED;

    } else if (pcmk__is_primitive(rsc) && (rsc->running_on == NULL)) {
        cl = PCMK__VALUE_RSC_FAILED;

    } else if (pcmk__list_of_multiple(rsc->running_on)) {
        cl = PCMK__VALUE_RSC_MULTIPLE;

    } else if (pcmk_is_set(rsc->flags, pcmk_rsc_ignore_failure)) {
        cl = PCMK__VALUE_RSC_FAILURE_IGNORED;

    } else {
        cl = PCMK__VALUE_RSC_OK;
    }

    child = pcmk__output_create_html_node(out, "li", NULL, NULL, NULL);
    child = pcmk__html_create(child, PCMK__XE_SPAN, NULL, cl);
    content = pcmk__native_output_string(rsc, name, node, show_opts,
                                         target_role, true);
    pcmk__xe_set_content(child, "%s", content);
    g_free(content);

    return pcmk_rc_ok;
}

int
pe__common_output_text(pcmk__output_t *out, const pcmk_resource_t *rsc,
                       const char *name, const pcmk_node_t *node,
                       uint32_t show_opts)
{
    const char *target_role = NULL;

    pcmk__assert(pcmk__is_primitive(rsc));

    if (rsc->meta) {
        const char *is_internal = g_hash_table_lookup(rsc->meta,
                                                      PCMK__META_INTERNAL_RSC);

        if (crm_is_true(is_internal)
            && !pcmk_is_set(show_opts, pcmk_show_implicit_rscs)) {

            crm_trace("skipping print of internal resource %s", rsc->id);
            return pcmk_rc_no_output;
        }
        target_role = g_hash_table_lookup(rsc->meta, PCMK_META_TARGET_ROLE);
    }

    {
        gchar *s = pcmk__native_output_string(rsc, name, node, show_opts,
                                              target_role, true);

        out->list_item(out, NULL, "%s", s);
        g_free(s);
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \deprecated This function will be removed in a future release
 */
void
common_print(pcmk_resource_t *rsc, const char *pre_text, const char *name,
             const pcmk_node_t *node, long options, void *print_data)
{
    const char *target_role = NULL;

    pcmk__assert(pcmk__is_primitive(rsc));

    if (rsc->meta) {
        const char *is_internal = g_hash_table_lookup(rsc->meta,
                                                      PCMK__META_INTERNAL_RSC);

        if (crm_is_true(is_internal)
            && !pcmk_is_set(options, pe_print_implicit)) {

            crm_trace("skipping print of internal resource %s", rsc->id);
            return;
        }
        target_role = g_hash_table_lookup(rsc->meta, PCMK_META_TARGET_ROLE);
    }

    if (options & pe_print_xml) {
        native_print_xml(rsc, pre_text, options, print_data);
        return;
    }

    if ((pre_text == NULL) && (options & pe_print_printf)) {
        pre_text = " ";
    }

    if (options & pe_print_html) {
        if (!pcmk_is_set(rsc->flags, pcmk_rsc_managed)) {
            status_print("<font color=\"yellow\">");

        } else if (pcmk_is_set(rsc->flags, pcmk_rsc_failed)) {
            status_print("<font color=\"red\">");

        } else if (rsc->running_on == NULL) {
            status_print("<font color=\"red\">");

        } else if (pcmk__list_of_multiple(rsc->running_on)) {
            status_print("<font color=\"orange\">");

        } else if (pcmk_is_set(rsc->flags, pcmk_rsc_ignore_failure)) {
            status_print("<font color=\"yellow\">");

        } else {
            status_print("<font color=\"green\">");
        }
    }

    {
        gchar *resource_s = pcmk__native_output_string(rsc, name, node, options,
                                                       target_role, false);
        status_print("%s%s", (pre_text? pre_text : ""), resource_s);
        g_free(resource_s);
    }

    if (pcmk_is_set(options, pe_print_html)) {
        status_print(" </font> ");
    }

    if (!pcmk_is_set(options, pe_print_rsconly)
        && pcmk__list_of_multiple(rsc->running_on)) {

        GList *gIter = rsc->running_on;
        int counter = 0;

        if (options & pe_print_html) {
            status_print("<ul>\n");
        } else if ((options & pe_print_printf)
                   || (options & pe_print_ncurses)) {
            status_print("[");
        }

        for (; gIter != NULL; gIter = gIter->next) {
            pcmk_node_t *n = (pcmk_node_t *) gIter->data;

            counter++;

            if (options & pe_print_html) {
                status_print("<li>\n%s", pcmk__node_name(n));

            } else if ((options & pe_print_printf)
                       || (options & pe_print_ncurses)) {
                status_print(" %s", pcmk__node_name(n));

            } else if ((options & pe_print_log)) {
                status_print("\t%d : %s", counter, pcmk__node_name(n));

            } else {
                status_print("%s", pcmk__node_name(n));
            }
            if (options & pe_print_html) {
                status_print("</li>\n");

            }
        }

        if (options & pe_print_html) {
            status_print("</ul>\n");
        } else if ((options & pe_print_printf)
                   || (options & pe_print_ncurses)) {
            status_print(" ]");
        }
    }

    if (options & pe_print_html) {
        status_print("<br/>\n");
    } else if (options & pe_print_suppres_nl) {
        /* nothing */
    } else if ((options & pe_print_printf) || (options & pe_print_ncurses)) {
        status_print("\n");
    }
}

/*!
 * \internal
 * \deprecated This function will be removed in a future release
 */
void
native_print(pcmk_resource_t *rsc, const char *pre_text, long options,
             void *print_data)
{
    const pcmk_node_t *node = NULL;

    pcmk__assert(pcmk__is_primitive(rsc));

    if (options & pe_print_xml) {
        native_print_xml(rsc, pre_text, options, print_data);
        return;
    }

    node = pcmk__current_node(rsc);

    if (node == NULL) {
        // This is set only if a non-probe action is pending on this node
        node = rsc->pending_node;
    }

    common_print(rsc, pre_text, rsc_printable_id(rsc), node, options, print_data);
}

PCMK__OUTPUT_ARGS("primitive", "uint32_t", "pcmk_resource_t *", "GList *",
                  "GList *")
int
pe__resource_xml(pcmk__output_t *out, va_list args)
{
    uint32_t show_opts = va_arg(args, uint32_t);
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    GList *only_node G_GNUC_UNUSED = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    int rc = pcmk_rc_no_output;
    bool print_pending = pcmk_is_set(show_opts, pcmk_show_pending);
    const char *class = crm_element_value(rsc->xml, PCMK_XA_CLASS);
    const char *prov = crm_element_value(rsc->xml, PCMK_XA_PROVIDER);

    char ra_name[LINE_MAX];
    const char *rsc_state = native_displayable_state(rsc, print_pending);
    const char *target_role = NULL;
    const char *active = pcmk__btoa(rsc->fns->active(rsc, TRUE));
    const char *orphaned = pcmk__flag_text(rsc->flags, pcmk_rsc_removed);
    const char *blocked = pcmk__flag_text(rsc->flags, pcmk_rsc_blocked);
    const char *maintenance = pcmk__flag_text(rsc->flags, pcmk_rsc_maintenance);
    const char *managed = pcmk__flag_text(rsc->flags, pcmk_rsc_managed);
    const char *failed = pcmk__flag_text(rsc->flags, pcmk_rsc_failed);
    const char *ignored = pcmk__flag_text(rsc->flags, pcmk_rsc_ignore_failure);
    char *nodes_running_on = NULL;
    const char *pending = print_pending? native_pending_task(rsc) : NULL;
    const char *locked_to = NULL;
    const char *desc = pe__resource_description(rsc, show_opts);

    pcmk__assert(pcmk__is_primitive(rsc));

    if (rsc->fns->is_filtered(rsc, only_rsc, TRUE)) {
        return pcmk_rc_no_output;
    }

    // Resource information
    snprintf(ra_name, LINE_MAX, "%s%s%s:%s", class,
            ((prov == NULL)? "" : PROVIDER_SEP), ((prov == NULL)? "" : prov),
            crm_element_value(rsc->xml, PCMK_XA_TYPE));

    if (rsc->meta != NULL) {
        target_role = g_hash_table_lookup(rsc->meta, PCMK_META_TARGET_ROLE);
    }

    nodes_running_on = pcmk__itoa(g_list_length(rsc->running_on));

    if (rsc->lock_node != NULL) {
        locked_to = rsc->lock_node->details->uname;
    }

    rc = pe__name_and_nvpairs_xml(out, true, PCMK_XE_RESOURCE,
                                  PCMK_XA_ID, rsc_printable_id(rsc),
                                  PCMK_XA_RESOURCE_AGENT, ra_name,
                                  PCMK_XA_ROLE, rsc_state,
                                  PCMK_XA_TARGET_ROLE, target_role,
                                  PCMK_XA_ACTIVE, active,
                                  PCMK_XA_ORPHANED, orphaned,
                                  PCMK_XA_BLOCKED, blocked,
                                  PCMK_XA_MAINTENANCE, maintenance,
                                  PCMK_XA_MANAGED, managed,
                                  PCMK_XA_FAILED, failed,
                                  PCMK_XA_FAILURE_IGNORED, ignored,
                                  PCMK_XA_NODES_RUNNING_ON, nodes_running_on,
                                  PCMK_XA_PENDING, pending,
                                  PCMK_XA_LOCKED_TO, locked_to,
                                  PCMK_XA_DESCRIPTION, desc,
                                  NULL);
    free(nodes_running_on);

    pcmk__assert(rc == pcmk_rc_ok);

    if (rsc->running_on != NULL) {
        GList *gIter = rsc->running_on;

        for (; gIter != NULL; gIter = gIter->next) {
            pcmk_node_t *node = (pcmk_node_t *) gIter->data;
            const char *cached = pcmk__btoa(node->details->online);

            rc = pe__name_and_nvpairs_xml(out, false, PCMK_XE_NODE,
                                          PCMK_XA_NAME, node->details->uname,
                                          PCMK_XA_ID, node->details->id,
                                          PCMK_XA_CACHED, cached,
                                          NULL);
            pcmk__assert(rc == pcmk_rc_ok);
        }
    }

    pcmk__output_xml_pop_parent(out);
    return rc;
}

PCMK__OUTPUT_ARGS("primitive", "uint32_t", "pcmk_resource_t *", "GList *",
                  "GList *")
int
pe__resource_html(pcmk__output_t *out, va_list args)
{
    uint32_t show_opts = va_arg(args, uint32_t);
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    GList *only_node G_GNUC_UNUSED = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    const pcmk_node_t *node = pcmk__current_node(rsc);

    if (rsc->fns->is_filtered(rsc, only_rsc, TRUE)) {
        return pcmk_rc_no_output;
    }

    pcmk__assert(pcmk__is_primitive(rsc));

    if (node == NULL) {
        // This is set only if a non-probe action is pending on this node
        node = rsc->pending_node;
    }
    return pe__common_output_html(out, rsc, rsc_printable_id(rsc), node, show_opts);
}

PCMK__OUTPUT_ARGS("primitive", "uint32_t", "pcmk_resource_t *", "GList *",
                  "GList *")
int
pe__resource_text(pcmk__output_t *out, va_list args)
{
    uint32_t show_opts = va_arg(args, uint32_t);
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    GList *only_node G_GNUC_UNUSED = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    const pcmk_node_t *node = pcmk__current_node(rsc);

    pcmk__assert(pcmk__is_primitive(rsc));

    if (rsc->fns->is_filtered(rsc, only_rsc, TRUE)) {
        return pcmk_rc_no_output;
    }

    if (node == NULL) {
        // This is set only if a non-probe action is pending on this node
        node = rsc->pending_node;
    }
    return pe__common_output_text(out, rsc, rsc_printable_id(rsc), node, show_opts);
}

void
native_free(pcmk_resource_t * rsc)
{
    pcmk__rsc_trace(rsc, "Freeing resource action list (not the data)");
    common_free(rsc);
}

enum rsc_role_e
native_resource_state(const pcmk_resource_t * rsc, gboolean current)
{
    enum rsc_role_e role = rsc->next_role;

    if (current) {
        role = rsc->role;
    }
    pcmk__rsc_trace(rsc, "%s state: %s", rsc->id, pcmk_role_text(role));
    return role;
}

/*!
 * \internal
 * \brief List nodes where a resource (or any of its children) is
 *
 * \param[in]  rsc      Resource to check
 * \param[out] list     List to add result to
 * \param[in]  current  0 = where allocated, 1 = where running,
 *                      2 = where running or pending
 *
 * \return If list contains only one node, that node, or NULL otherwise
 */
pcmk_node_t *
native_location(const pcmk_resource_t *rsc, GList **list, int current)
{
    // @COMPAT: Accept a pcmk__rsc_node argument instead of int current
    pcmk_node_t *one = NULL;
    GList *result = NULL;

    if (rsc->children) {
        GList *gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            pcmk_resource_t *child = (pcmk_resource_t *) gIter->data;

            child->fns->location(child, &result, current);
        }

    } else if (current) {

        if (rsc->running_on) {
            result = g_list_copy(rsc->running_on);
        }
        if ((current == 2) && rsc->pending_node
            && !pe_find_node_id(result, rsc->pending_node->details->id)) {
                result = g_list_append(result, rsc->pending_node);
        }

    } else if (current == FALSE && rsc->allocated_to) {
        result = g_list_append(NULL, rsc->allocated_to);
    }

    if (result && (result->next == NULL)) {
        one = result->data;
    }

    if (list) {
        GList *gIter = result;

        for (; gIter != NULL; gIter = gIter->next) {
            pcmk_node_t *node = (pcmk_node_t *) gIter->data;

            if (*list == NULL || pe_find_node_id(*list, node->details->id) == NULL) {
                *list = g_list_append(*list, node);
            }
        }
    }

    g_list_free(result);
    return one;
}

static void
get_rscs_brief(GList *rsc_list, GHashTable * rsc_table, GHashTable * active_table)
{
    GList *gIter = rsc_list;

    for (; gIter != NULL; gIter = gIter->next) {
        pcmk_resource_t *rsc = (pcmk_resource_t *) gIter->data;

        const char *class = crm_element_value(rsc->xml, PCMK_XA_CLASS);
        const char *kind = crm_element_value(rsc->xml, PCMK_XA_TYPE);

        int offset = 0;
        char buffer[LINE_MAX];

        int *rsc_counter = NULL;
        int *active_counter = NULL;

        if (!pcmk__is_primitive(rsc)) {
            continue;
        }

        offset += snprintf(buffer + offset, LINE_MAX - offset, "%s", class);
        if (pcmk_is_set(pcmk_get_ra_caps(class), pcmk_ra_cap_provider)) {
            const char *prov = crm_element_value(rsc->xml, PCMK_XA_PROVIDER);

            if (prov != NULL) {
                offset += snprintf(buffer + offset, LINE_MAX - offset,
                                   PROVIDER_SEP "%s", prov);
            }
        }
        offset += snprintf(buffer + offset, LINE_MAX - offset, ":%s", kind);
        CRM_LOG_ASSERT(offset > 0);

        if (rsc_table) {
            rsc_counter = g_hash_table_lookup(rsc_table, buffer);
            if (rsc_counter == NULL) {
                rsc_counter = pcmk__assert_alloc(1, sizeof(int));
                *rsc_counter = 0;
                g_hash_table_insert(rsc_table, strdup(buffer), rsc_counter);
            }
            (*rsc_counter)++;
        }

        if (active_table) {
            GList *gIter2 = rsc->running_on;

            for (; gIter2 != NULL; gIter2 = gIter2->next) {
                pcmk_node_t *node = (pcmk_node_t *) gIter2->data;
                GHashTable *node_table = NULL;

                if (node->details->unclean == FALSE && node->details->online == FALSE &&
                    pcmk_is_set(rsc->flags, pcmk_rsc_managed)) {
                    continue;
                }

                node_table = g_hash_table_lookup(active_table, node->details->uname);
                if (node_table == NULL) {
                    node_table = pcmk__strkey_table(free, free);
                    g_hash_table_insert(active_table, strdup(node->details->uname), node_table);
                }

                active_counter = g_hash_table_lookup(node_table, buffer);
                if (active_counter == NULL) {
                    active_counter = pcmk__assert_alloc(1, sizeof(int));
                    *active_counter = 0;
                    g_hash_table_insert(node_table, strdup(buffer), active_counter);
                }
                (*active_counter)++;
            }
        }
    }
}

static void
destroy_node_table(gpointer data)
{
    GHashTable *node_table = data;

    if (node_table) {
        g_hash_table_destroy(node_table);
    }
}

/*!
 * \internal
 * \deprecated This function will be removed in a future release
 */
void
print_rscs_brief(GList *rsc_list, const char *pre_text, long options,
                 void *print_data, gboolean print_all)
{
    GHashTable *rsc_table = pcmk__strkey_table(free, free);
    GHashTable *active_table = pcmk__strkey_table(free, destroy_node_table);
    GHashTableIter hash_iter;
    char *type = NULL;
    int *rsc_counter = NULL;

    get_rscs_brief(rsc_list, rsc_table, active_table);

    g_hash_table_iter_init(&hash_iter, rsc_table);
    while (g_hash_table_iter_next(&hash_iter, (gpointer *)&type, (gpointer *)&rsc_counter)) {
        GHashTableIter hash_iter2;
        char *node_name = NULL;
        GHashTable *node_table = NULL;
        int active_counter_all = 0;

        g_hash_table_iter_init(&hash_iter2, active_table);
        while (g_hash_table_iter_next(&hash_iter2, (gpointer *)&node_name, (gpointer *)&node_table)) {
            int *active_counter = g_hash_table_lookup(node_table, type);

            if (active_counter == NULL || *active_counter == 0) {
                continue;

            } else {
                active_counter_all += *active_counter;
            }

            if (options & pe_print_rsconly) {
                node_name = NULL;
            }

            if (options & pe_print_html) {
                status_print("<li>\n");
            }

            if (print_all) {
                status_print("%s%d/%d\t(%s):\tActive %s\n", pre_text ? pre_text : "",
                             active_counter ? *active_counter : 0,
                             rsc_counter ? *rsc_counter : 0, type,
                             active_counter && (*active_counter > 0) && node_name ? node_name : "");
            } else {
                status_print("%s%d\t(%s):\tActive %s\n", pre_text ? pre_text : "",
                             active_counter ? *active_counter : 0, type,
                             active_counter && (*active_counter > 0) && node_name ? node_name : "");
            }

            if (options & pe_print_html) {
                status_print("</li>\n");
            }
        }

        if (print_all && active_counter_all == 0) {
            if (options & pe_print_html) {
                status_print("<li>\n");
            }

            status_print("%s%d/%d\t(%s):\tActive\n", pre_text ? pre_text : "",
                         active_counter_all,
                         rsc_counter ? *rsc_counter : 0, type);

            if (options & pe_print_html) {
                status_print("</li>\n");
            }
        }
    }

    if (rsc_table) {
        g_hash_table_destroy(rsc_table);
        rsc_table = NULL;
    }
    if (active_table) {
        g_hash_table_destroy(active_table);
        active_table = NULL;
    }
}

int
pe__rscs_brief_output(pcmk__output_t *out, GList *rsc_list, uint32_t show_opts)
{
    GHashTable *rsc_table = pcmk__strkey_table(free, free);
    GHashTable *active_table = pcmk__strkey_table(free, destroy_node_table);
    GList *sorted_rscs;
    int rc = pcmk_rc_no_output;

    get_rscs_brief(rsc_list, rsc_table, active_table);

    /* Make a list of the rsc_table keys so that it can be sorted.  This is to make sure
     * output order stays consistent between systems.
     */
    sorted_rscs = g_hash_table_get_keys(rsc_table);
    sorted_rscs = g_list_sort(sorted_rscs, (GCompareFunc) strcmp);

    for (GList *gIter = sorted_rscs; gIter; gIter = gIter->next) {
        char *type = (char *) gIter->data;
        int *rsc_counter = g_hash_table_lookup(rsc_table, type);

        GList *sorted_nodes = NULL;
        int active_counter_all = 0;

        /* Also make a list of the active_table keys so it can be sorted.  If there's
         * more than one instance of a type of resource running, we need the nodes to
         * be sorted to make sure output order stays consistent between systems.
         */
        sorted_nodes = g_hash_table_get_keys(active_table);
        sorted_nodes = g_list_sort(sorted_nodes, (GCompareFunc) pcmk__numeric_strcasecmp);

        for (GList *gIter2 = sorted_nodes; gIter2; gIter2 = gIter2->next) {
            char *node_name = (char *) gIter2->data;
            GHashTable *node_table = g_hash_table_lookup(active_table, node_name);
            int *active_counter = NULL;

            if (node_table == NULL) {
                continue;
            }

            active_counter = g_hash_table_lookup(node_table, type);

            if (active_counter == NULL || *active_counter == 0) {
                continue;

            } else {
                active_counter_all += *active_counter;
            }

            if (pcmk_is_set(show_opts, pcmk_show_rsc_only)) {
                node_name = NULL;
            }

            if (pcmk_is_set(show_opts, pcmk_show_inactive_rscs)) {
                out->list_item(out, NULL, "%d/%d\t(%s):\tActive %s",
                               *active_counter,
                               rsc_counter ? *rsc_counter : 0, type,
                               (*active_counter > 0) && node_name ? node_name : "");
            } else {
                out->list_item(out, NULL, "%d\t(%s):\tActive %s",
                               *active_counter, type,
                               (*active_counter > 0) && node_name ? node_name : "");
            }

            rc = pcmk_rc_ok;
        }

        if (pcmk_is_set(show_opts, pcmk_show_inactive_rscs) && active_counter_all == 0) {
            out->list_item(out, NULL, "%d/%d\t(%s):\tActive",
                           active_counter_all,
                           rsc_counter ? *rsc_counter : 0, type);
            rc = pcmk_rc_ok;
        }

        if (sorted_nodes) {
            g_list_free(sorted_nodes);
        }
    }

    if (rsc_table) {
        g_hash_table_destroy(rsc_table);
        rsc_table = NULL;
    }
    if (active_table) {
        g_hash_table_destroy(active_table);
        active_table = NULL;
    }
    if (sorted_rscs) {
        g_list_free(sorted_rscs);
    }

    return rc;
}

gboolean
pe__native_is_filtered(const pcmk_resource_t *rsc, GList *only_rsc,
                       gboolean check_parent)
{
    if (pcmk__str_in_list(rsc_printable_id(rsc), only_rsc, pcmk__str_star_matches) ||
        pcmk__str_in_list(rsc->id, only_rsc, pcmk__str_star_matches)) {
        return FALSE;
    } else if (check_parent && rsc->parent) {
        const pcmk_resource_t *up = pe__const_top_resource(rsc, true);

        return up->fns->is_filtered(up, only_rsc, FALSE);
    }

    return TRUE;
}

/*!
 * \internal
 * \brief Get maximum primitive resource instances per node
 *
 * \param[in] rsc  Primitive resource to check
 *
 * \return Maximum number of \p rsc instances that can be active on one node
 */
unsigned int
pe__primitive_max_per_node(const pcmk_resource_t *rsc)
{
    pcmk__assert(pcmk__is_primitive(rsc));
    return 1U;
}
