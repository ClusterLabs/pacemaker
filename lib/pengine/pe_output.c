/*
 * Copyright 2019-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdint.h>

#include <glib.h>                           // g_strchomp()
#include <libxml/tree.h>                    // xmlNode

#include <crm/common/output.h>
#include <crm/cib/util.h>
#include <crm/common/xml.h>
#include <crm/pengine/internal.h>

const char *
pe__resource_description(const pcmk_resource_t *rsc, uint32_t show_opts)
{
    const char * desc = NULL;

    // User-supplied description
    if (pcmk__any_flags_set(show_opts,
                            pcmk_show_rsc_only|pcmk_show_description)) {
        desc = pcmk__xe_get(rsc->priv->xml, PCMK_XA_DESCRIPTION);
    }
    return desc;
}

/* Never display node attributes whose name starts with one of these prefixes */
#define FILTER_STR { PCMK__FAIL_COUNT_PREFIX, PCMK__LAST_FAILURE_PREFIX,    \
                     PCMK__NODE_ATTR_SHUTDOWN, PCMK_NODE_ATTR_TERMINATE,    \
                     PCMK_NODE_ATTR_STANDBY, "#", NULL }

static int
compare_attribute(gconstpointer a, gconstpointer b)
{
    int rc;

    rc = strcmp((const char *)a, (const char *)b);

    return rc;
}

/*!
 * \internal
 * \brief Determine whether extended information about an attribute should be added.
 *
 * \param[in]     node            Node that ran this resource
 * \param[in,out] rsc_list        List of resources for this node
 * \param[in,out] scheduler       Scheduler data
 * \param[in]     attrname        Attribute to find
 * \param[out]    expected_score  Expected value for this attribute
 *
 * \return true if extended information should be printed, false otherwise
 * \note Currently, extended information is only supported for ping/pingd
 *       resources, for which a message will be printed if connectivity is lost
 *       or degraded.
 */
static bool
add_extra_info(const pcmk_node_t *node, GList *rsc_list,
               pcmk_scheduler_t *scheduler, const char *attrname,
               int *expected_score)
{
    GList *gIter = NULL;

    for (gIter = rsc_list; gIter != NULL; gIter = gIter->next) {
        pcmk_resource_t *rsc = (pcmk_resource_t *) gIter->data;
        const char *type = g_hash_table_lookup(rsc->priv->meta,
                                               PCMK_XA_TYPE);
        const char *name = NULL;
        GHashTable *params = NULL;

        if (rsc->priv->children != NULL) {
            if (add_extra_info(node, rsc->priv->children, scheduler,
                               attrname, expected_score)) {
                return true;
            }
        }

        if (!pcmk__strcase_any_of(type, "ping", "pingd", NULL)) {
            continue;
        }

        params = pe_rsc_params(rsc, node, scheduler);
        name = g_hash_table_lookup(params, PCMK_XA_NAME);

        if (name == NULL) {
            name = "pingd";
        }

        /* To identify the resource with the attribute name. */
        if (pcmk__str_eq(name, attrname, pcmk__str_casei)) {
            int host_list_num = 0;
            const char *hosts = g_hash_table_lookup(params, "host_list");
            const char *multiplier = g_hash_table_lookup(params, "multiplier");
            int multiplier_i;

            if (hosts) {
                char **host_list = g_strsplit(hosts, " ", 0);
                host_list_num = g_strv_length(host_list);
                g_strfreev(host_list);
            }

            if ((multiplier == NULL)
                || (pcmk__scan_min_int(multiplier, &multiplier_i,
                                       INT_MIN) != pcmk_rc_ok)) {
                /* The ocf:pacemaker:ping resource agent defaults multiplier to
                 * 1. The agent currently does not handle invalid text, but it
                 * should, and this would be a reasonable choice ...
                 */
                multiplier_i = 1;
            }
            *expected_score = host_list_num * multiplier_i;

            return true;
        }
    }
    return false;
}

static GList *
filter_attr_list(GList *attr_list, char *name)
{
    int i;
    const char *filt_str[] = FILTER_STR;

    CRM_CHECK(name != NULL, return attr_list);

    /* filtering automatic attributes */
    for (i = 0; filt_str[i] != NULL; i++) {
        if (g_str_has_prefix(name, filt_str[i])) {
            return attr_list;
        }
    }

    return g_list_insert_sorted(attr_list, name, compare_attribute);
}

static GList *
get_operation_list(xmlNode *rsc_entry) {
    GList *op_list = NULL;
    xmlNode *rsc_op = NULL;

    for (rsc_op = pcmk__xe_first_child(rsc_entry, PCMK__XE_LRM_RSC_OP, NULL,
                                       NULL);
         rsc_op != NULL; rsc_op = pcmk__xe_next(rsc_op, PCMK__XE_LRM_RSC_OP)) {

        const char *task = pcmk__xe_get(rsc_op, PCMK_XA_OPERATION);

        if (pcmk__str_eq(task, PCMK_ACTION_NOTIFY, pcmk__str_none)) {
            continue; // Ignore notify actions
        } else {
            int exit_status;

            pcmk__scan_min_int(pcmk__xe_get(rsc_op, PCMK__XA_RC_CODE),
                               &exit_status, 0);
            if ((exit_status == CRM_EX_NOT_RUNNING)
                && pcmk__str_eq(task, PCMK_ACTION_MONITOR, pcmk__str_none)
                && pcmk__str_eq(pcmk__xe_get(rsc_op, PCMK_META_INTERVAL), "0",
                                pcmk__str_null_matches)) {
                continue; // Ignore probes that found the resource not running
            }
        }

        op_list = g_list_append(op_list, rsc_op);
    }

    op_list = g_list_sort(op_list, sort_op_by_callid);
    return op_list;
}

static void
add_dump_node(gpointer key, gpointer value, gpointer user_data)
{
    xmlNodePtr node = user_data;

    node = pcmk__xe_create(node, (const char *) key);
    pcmk__xe_set_content(node, "%s", (const char *) value);
}

static void
append_dump_text(gpointer key, gpointer value, gpointer user_data)
{
    char **dump_text = user_data;
    char *new_text = pcmk__assert_asprintf("%s %s=%s",
                                           *dump_text, (const char *) key,
                                           (const char *)value);

    free(*dump_text);
    *dump_text = new_text;
}

#define XPATH_STACK "//" PCMK_XE_NVPAIR     \
                    "[@" PCMK_XA_NAME "='"  \
                        PCMK_OPT_CLUSTER_INFRASTRUCTURE "']"

static const char *
get_cluster_stack(pcmk_scheduler_t *scheduler)
{
    xmlNode *stack = pcmk__xpath_find_one(scheduler->input->doc, XPATH_STACK,
                                          LOG_DEBUG);

    if (stack != NULL) {
        return pcmk__xe_get(stack, PCMK_XA_VALUE);
    }
    return PCMK_VALUE_UNKNOWN;
}

static char *
last_changed_string(const char *last_written, const char *user,
                    const char *client, const char *origin) {
    if (last_written != NULL || user != NULL || client != NULL || origin != NULL) {
        return pcmk__assert_asprintf("%s%s%s%s%s%s%s",
                                     pcmk__s(last_written, ""),
                                     ((user != NULL)? " by " : ""),
                                     pcmk__s(user, ""),
                                     ((client != NULL) ? " via " : ""),
                                     pcmk__s(client, ""),
                                     ((origin != NULL)? " on " : ""),
                                     pcmk__s(origin, ""));
    } else {
        return strdup("");
    }
}

static char *
op_history_string(xmlNode *xml_op, const char *task, const char *interval_ms_s,
                  int rc, bool print_timing) {
    const char *call = pcmk__xe_get(xml_op, PCMK__XA_CALL_ID);
    char *interval_str = NULL;
    char *buf = NULL;

    if (interval_ms_s && !pcmk__str_eq(interval_ms_s, "0", pcmk__str_casei)) {
        char *pair = pcmk__format_nvpair(PCMK_XA_INTERVAL, interval_ms_s, "ms");
        interval_str = pcmk__assert_asprintf(" %s", pair);
        free(pair);
    }

    if (print_timing) {
        char *last_change_str = NULL;
        char *exec_str = NULL;
        char *queue_str = NULL;

        const char *value = NULL;

        time_t epoch = 0;

        pcmk__xe_get_time(xml_op, PCMK_XA_LAST_RC_CHANGE, &epoch);
        if (epoch > 0) {
            char *epoch_str = pcmk__epoch2str(&epoch, 0);

            last_change_str = pcmk__assert_asprintf(" %s=\"%s\"",
                                                    PCMK_XA_LAST_RC_CHANGE,
                                                    pcmk__s(epoch_str, ""));
            free(epoch_str);
        }

        value = pcmk__xe_get(xml_op, PCMK_XA_EXEC_TIME);
        if (value) {
            char *pair = pcmk__format_nvpair(PCMK_XA_EXEC_TIME, value, "ms");
            exec_str = pcmk__assert_asprintf(" %s", pair);
            free(pair);
        }

        value = pcmk__xe_get(xml_op, PCMK_XA_QUEUE_TIME);
        if (value) {
            char *pair = pcmk__format_nvpair(PCMK_XA_QUEUE_TIME, value, "ms");
            queue_str = pcmk__assert_asprintf(" %s", pair);
            free(pair);
        }

        buf = pcmk__assert_asprintf("(%s) %s:%s%s%s%s rc=%d (%s)", call, task,
                                    pcmk__s(interval_str, ""),
                                    pcmk__s(last_change_str, ""),
                                    pcmk__s(exec_str, ""),
                                    pcmk__s(queue_str, ""),
                                    rc, crm_exit_str(rc));

        if (last_change_str) {
            free(last_change_str);
        }

        if (exec_str) {
            free(exec_str);
        }

        if (queue_str) {
            free(queue_str);
        }
    } else {
        buf = pcmk__assert_asprintf("(%s) %s%s%s", call, task,
                                    ((interval_str != NULL)? ":" : ""),
                                    pcmk__s(interval_str, ""));
    }

    if (interval_str) {
        free(interval_str);
    }

    return buf;
}

static char *
resource_history_string(pcmk_resource_t *rsc, const char *rsc_id, bool all,
                        int failcount, time_t last_failure) {
    char *buf = NULL;

    if (rsc == NULL) {
        /* @COMPAT "orphan" is deprecated since 3.0.2. Replace with "removed" at
         * a compatibility break.
         */
        buf = pcmk__assert_asprintf("%s: orphan", rsc_id);
    } else if (all || failcount || last_failure > 0) {
        char *failcount_s = NULL;
        char *lastfail_s = NULL;

        if (failcount > 0) {
            failcount_s = pcmk__assert_asprintf(" " PCMK_XA_FAIL_COUNT "=%d",
                                                failcount);
        } else {
            failcount_s = strdup("");
        }
        if (last_failure > 0) {
            buf = pcmk__epoch2str(&last_failure, 0);
            lastfail_s = pcmk__assert_asprintf(" " PCMK_XA_LAST_FAILURE "='%s'",
                                               buf);
            free(buf);
        }

        buf = pcmk__assert_asprintf("%s: " PCMK_META_MIGRATION_THRESHOLD
                                    "=%d%s%s",
                                    rsc_id, rsc->priv->ban_after_failures,
                                    failcount_s, pcmk__s(lastfail_s, ""));
        free(failcount_s);
        free(lastfail_s);
    } else {
        buf = pcmk__assert_asprintf("%s:", rsc_id);
    }

    return buf;
}

/*!
 * \internal
 * \brief Get a node's feature set for status display purposes
 *
 * \param[in] node  Node to check
 *
 * \return String representation of feature set if the node is fully up (using
 *         "<3.15.1" for older nodes that don't set the #feature-set attribute),
 *         otherwise NULL
 */
static const char *
get_node_feature_set(const pcmk_node_t *node)
{
    if (node->details->online
        && pcmk__is_set(node->priv->flags, pcmk__node_expected_up)
        && !pcmk__is_pacemaker_remote_node(node)) {

        const char *feature_set = g_hash_table_lookup(node->priv->attrs,
                                                      CRM_ATTR_FEATURE_SET);

        /* The feature set attribute is present since 3.15.1. If it is missing,
         * then the node must be running an earlier version.
         */
        return pcmk__s(feature_set, "<3.15.1");
    }
    return NULL;
}

static bool
is_mixed_version(pcmk_scheduler_t *scheduler)
{
    const char *feature_set = NULL;
    for (GList *gIter = scheduler->nodes; gIter != NULL; gIter = gIter->next) {
        pcmk_node_t *node = gIter->data;
        const char *node_feature_set = get_node_feature_set(node);
        if (node_feature_set != NULL) {
            if (feature_set == NULL) {
                feature_set = node_feature_set;
            } else if (strcmp(feature_set, node_feature_set) != 0) {
                return true;
            }
        }
    }
    return false;
}

static void
formatted_xml_buf(const pcmk_resource_t *rsc, GString *xml_buf, bool raw)
{
    if (raw && (rsc->priv->orig_xml != NULL)) {
        pcmk__xml_string(rsc->priv->orig_xml, pcmk__xml_fmt_pretty, xml_buf,
                         0);
    } else {
        pcmk__xml_string(rsc->priv->xml, pcmk__xml_fmt_pretty, xml_buf, 0);
    }
}

#define XPATH_DC_VERSION "//" PCMK_XE_NVPAIR    \
                         "[@" PCMK_XA_NAME "='" PCMK_OPT_DC_VERSION "']"

PCMK__OUTPUT_ARGS("cluster-summary", "pcmk_scheduler_t *",
                  "enum pcmk_pacemakerd_state", "uint32_t", "uint32_t")
static int
cluster_summary(pcmk__output_t *out, va_list args) {
    pcmk_scheduler_t *scheduler = va_arg(args, pcmk_scheduler_t *);
    enum pcmk_pacemakerd_state pcmkd_state =
        (enum pcmk_pacemakerd_state) va_arg(args, int);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);

    int rc = pcmk_rc_no_output;
    const char *stack_s = get_cluster_stack(scheduler);

    if (pcmk__is_set(section_opts, pcmk_section_stack)) {
        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Cluster Summary");
        out->message(out, "cluster-stack", stack_s, pcmkd_state);
    }

    if (pcmk__is_set(section_opts, pcmk_section_dc)) {
        xmlNode *dc_version = pcmk__xpath_find_one(scheduler->input->doc,
                                                   XPATH_DC_VERSION, LOG_DEBUG);
        const char *dc_version_s = dc_version?
                                   pcmk__xe_get(dc_version, PCMK_XA_VALUE)
                                   : NULL;
        const char *quorum = pcmk__xe_get(scheduler->input,
                                          PCMK_XA_HAVE_QUORUM);
        char *dc_name = NULL;
        const bool mixed_version = is_mixed_version(scheduler);

        if (scheduler->dc_node != NULL) {
            dc_name = pe__node_display_name(scheduler->dc_node,
                                            pcmk__is_set(show_opts,
                                                         pcmk_show_node_id));
        }

        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Cluster Summary");
        out->message(out, "cluster-dc", scheduler->dc_node, quorum,
                     dc_version_s, dc_name, mixed_version);
        free(dc_name);
    }

    if (pcmk__is_set(section_opts, pcmk_section_times)) {
        const char *last_written = pcmk__xe_get(scheduler->input,
                                                PCMK_XA_CIB_LAST_WRITTEN);
        const char *user = pcmk__xe_get(scheduler->input, PCMK_XA_UPDATE_USER);
        const char *client = pcmk__xe_get(scheduler->input,
                                          PCMK_XA_UPDATE_CLIENT);
        const char *origin = pcmk__xe_get(scheduler->input,
                                               PCMK_XA_UPDATE_ORIGIN);

        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Cluster Summary");
        out->message(out, "cluster-times", scheduler->priv->local_node_name,
                     last_written, user, client, origin);
    }

    if (pcmk__is_set(section_opts, pcmk_section_counts)) {
        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Cluster Summary");
        out->message(out, "cluster-counts", g_list_length(scheduler->nodes),
                     scheduler->priv->ninstances,
                     scheduler->priv->disabled_resources,
                     scheduler->priv->blocked_resources);
    }

    if (pcmk__is_set(section_opts, pcmk_section_options)) {
        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Cluster Summary");
        out->message(out, "cluster-options", scheduler);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);

    if (pcmk__is_set(section_opts, pcmk_section_maint_mode)) {
        if (out->message(out, "maint-mode", scheduler->flags) == pcmk_rc_ok) {
            rc = pcmk_rc_ok;
        }
    }

    return rc;
}

PCMK__OUTPUT_ARGS("cluster-summary", "pcmk_scheduler_t *",
                  "enum pcmk_pacemakerd_state", "uint32_t", "uint32_t")
static int
cluster_summary_html(pcmk__output_t *out, va_list args) {
    pcmk_scheduler_t *scheduler = va_arg(args, pcmk_scheduler_t *);
    enum pcmk_pacemakerd_state pcmkd_state =
        (enum pcmk_pacemakerd_state) va_arg(args, int);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);

    int rc = pcmk_rc_no_output;
    const char *stack_s = get_cluster_stack(scheduler);

    if (pcmk__is_set(section_opts, pcmk_section_stack)) {
        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Cluster Summary");
        out->message(out, "cluster-stack", stack_s, pcmkd_state);
    }

    /* Always print DC if none, even if not requested */
    if ((scheduler->dc_node == NULL)
        || pcmk__is_set(section_opts, pcmk_section_dc)) {
        xmlNode *dc_version = pcmk__xpath_find_one(scheduler->input->doc,
                                                   XPATH_DC_VERSION, LOG_DEBUG);
        const char *dc_version_s = dc_version?
                                   pcmk__xe_get(dc_version, PCMK_XA_VALUE)
                                   : NULL;
        const char *quorum = pcmk__xe_get(scheduler->input,
                                          PCMK_XA_HAVE_QUORUM);
        char *dc_name = NULL;
        const bool mixed_version = is_mixed_version(scheduler);

        if (scheduler->dc_node != NULL) {
            dc_name = pe__node_display_name(scheduler->dc_node,
                                            pcmk__is_set(show_opts,
                                                         pcmk_show_node_id));
        }

        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Cluster Summary");
        out->message(out, "cluster-dc", scheduler->dc_node, quorum,
                     dc_version_s, dc_name, mixed_version);
        free(dc_name);
    }

    if (pcmk__is_set(section_opts, pcmk_section_times)) {
        const char *last_written = pcmk__xe_get(scheduler->input,
                                                PCMK_XA_CIB_LAST_WRITTEN);
        const char *user = pcmk__xe_get(scheduler->input, PCMK_XA_UPDATE_USER);
        const char *client = pcmk__xe_get(scheduler->input,
                                          PCMK_XA_UPDATE_CLIENT);
        const char *origin = pcmk__xe_get(scheduler->input,
                                          PCMK_XA_UPDATE_ORIGIN);

        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Cluster Summary");
        out->message(out, "cluster-times", scheduler->priv->local_node_name,
                     last_written, user, client, origin);
    }

    if (pcmk__is_set(section_opts, pcmk_section_counts)) {
        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Cluster Summary");
        out->message(out, "cluster-counts", g_list_length(scheduler->nodes),
                     scheduler->priv->ninstances,
                     scheduler->priv->disabled_resources,
                     scheduler->priv->blocked_resources);
    }

    if (pcmk__is_set(section_opts, pcmk_section_options)) {
        /* Kind of a hack - close the list we may have opened earlier in this
         * function so we can put all the options into their own list.  We
         * only want to do this on HTML output, though.
         */
        PCMK__OUTPUT_LIST_FOOTER(out, rc);

        out->begin_list(out, NULL, NULL, "Config Options");
        out->message(out, "cluster-options", scheduler);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);

    if (pcmk__is_set(section_opts, pcmk_section_maint_mode)) {
        if (out->message(out, "maint-mode", scheduler->flags) == pcmk_rc_ok) {
            rc = pcmk_rc_ok;
        }
    }

    return rc;
}

char *
pe__node_display_name(pcmk_node_t *node, bool print_detail)
{
    char *node_name;
    const char *node_host = NULL;
    const char *node_id = NULL;
    int name_len;

    pcmk__assert((node != NULL) && (node->priv->name != NULL));

    /* Host is displayed only if this is a guest node and detail is requested */
    if (print_detail && pcmk__is_guest_or_bundle_node(node)) {
        const pcmk_resource_t *launcher = NULL;
        const pcmk_node_t *host_node = NULL;

        launcher = node->priv->remote->priv->launcher;
        host_node = pcmk__current_node(launcher);

        if (host_node && host_node->details) {
            node_host = host_node->priv->name;
        }
        if (node_host == NULL) {
            node_host = ""; /* so we at least get "uname@" to indicate guest */
        }
    }

    /* Node ID is displayed if different from uname and detail is requested */
    if (print_detail
        && !pcmk__str_eq(node->priv->name, node->priv->id,
                         pcmk__str_casei)) {
        node_id = node->priv->id;
    }

    /* Determine name length */
    name_len = strlen(node->priv->name) + 1;
    if (node_host) {
        name_len += strlen(node_host) + 1; /* "@node_host" */
    }
    if (node_id) {
        name_len += strlen(node_id) + 3; /* + " (node_id)" */
    }

    /* Allocate and populate display name */
    node_name = pcmk__assert_alloc(name_len, sizeof(char));
    strcpy(node_name, node->priv->name);
    if (node_host) {
        strcat(node_name, "@");
        strcat(node_name, node_host);
    }
    if (node_id) {
        strcat(node_name, " (");
        strcat(node_name, node_id);
        strcat(node_name, ")");
    }
    return node_name;
}

static const char *
role_desc(enum rsc_role_e role)
{
    if (role == pcmk_role_promoted) {
        return "in " PCMK_ROLE_PROMOTED " role ";
    }
    return "";
}

PCMK__OUTPUT_ARGS("ban", "pcmk_node_t *", "pcmk__location_t *", "uint32_t")
static int
ban_html(pcmk__output_t *out, va_list args) {
    pcmk_node_t *pe_node = va_arg(args, pcmk_node_t *);
    pcmk__location_t *location = va_arg(args, pcmk__location_t *);
    uint32_t show_opts = va_arg(args, uint32_t);

    char *node_name = pe__node_display_name(pe_node,
                                            pcmk__is_set(show_opts,
                                                         pcmk_show_node_id));
    char *buf = pcmk__assert_asprintf("%s\tprevents %s from running %son %s",
                                      location->id, location->rsc->id,
                                      role_desc(location->role_filter),
                                      node_name);

    pcmk__output_create_html_node(out, "li", NULL, NULL, buf);

    free(node_name);
    free(buf);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ban", "pcmk_node_t *", "pcmk__location_t *", "uint32_t")
static int
ban_text(pcmk__output_t *out, va_list args) {
    pcmk_node_t *pe_node = va_arg(args, pcmk_node_t *);
    pcmk__location_t *location = va_arg(args, pcmk__location_t *);
    uint32_t show_opts = va_arg(args, uint32_t);

    char *node_name = pe__node_display_name(pe_node,
                                            pcmk__is_set(show_opts,
                                                         pcmk_show_node_id));
    out->list_item(out, NULL, "%s\tprevents %s from running %son %s",
                   location->id, location->rsc->id,
                   role_desc(location->role_filter), node_name);

    free(node_name);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ban", "pcmk_node_t *", "pcmk__location_t *", "uint32_t")
static int
ban_xml(pcmk__output_t *out, va_list args) {
    pcmk_node_t *pe_node = va_arg(args, pcmk_node_t *);
    pcmk__location_t *location = va_arg(args, pcmk__location_t *);
    uint32_t show_opts G_GNUC_UNUSED = va_arg(args, uint32_t);

    const bool promoted_only = location->role_filter == pcmk_role_promoted;
    xmlNode *xml = NULL;

    xml = pcmk__output_create_xml_node(out, PCMK_XE_BAN);
    pcmk__xe_set(xml, PCMK_XA_ID, location->id);
    pcmk__xe_set(xml, PCMK_XA_RESOURCE, location->rsc->id);
    pcmk__xe_set(xml, PCMK_XA_NODE, pe_node->priv->name);
    pcmk__xe_set_int(xml, PCMK_XA_WEIGHT, pe_node->assign->score);
    pcmk__xe_set_bool(xml, PCMK_XA_PROMOTED_ONLY, promoted_only);

    /* @COMPAT This is a deprecated alias for promoted_only. Removing it will
     * break backward compatibility of the API schema, which will require an API
     * schema major version bump.
     */
    pcmk__xe_set_bool(xml, PCMK__XA_PROMOTED_ONLY_LEGACY, promoted_only);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ban-list", "pcmk_scheduler_t *", "const char *", "GList *",
                  "uint32_t", "bool")
static int
ban_list(pcmk__output_t *out, va_list args) {
    pcmk_scheduler_t *scheduler = va_arg(args, pcmk_scheduler_t *);
    const char *prefix = va_arg(args, const char *);
    GList *only_rsc = va_arg(args, GList *);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool print_spacer = va_arg(args, int);

    GList *gIter, *gIter2;
    int rc = pcmk_rc_no_output;

    /* Print each ban */
    for (gIter = scheduler->priv->location_constraints;
         gIter != NULL; gIter = gIter->next) {
        pcmk__location_t *location = gIter->data;
        const pcmk_resource_t *rsc = location->rsc;

        if (prefix != NULL && !g_str_has_prefix(location->id, prefix)) {
            continue;
        }

        if (!pcmk__str_in_list(rsc_printable_id(rsc), only_rsc,
                               pcmk__str_star_matches)
            && !pcmk__str_in_list(rsc_printable_id(pe__const_top_resource(rsc, false)),
                                  only_rsc, pcmk__str_star_matches)) {
            continue;
        }

        for (gIter2 = location->nodes; gIter2 != NULL; gIter2 = gIter2->next) {
            pcmk_node_t *node = (pcmk_node_t *) gIter2->data;

            if (node->assign->score < 0) {
                PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Negative Location Constraints");
                out->message(out, "ban", node, location, show_opts);
            }
        }
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("cluster-counts", "unsigned int", "int", "int", "int")
static int
cluster_counts_html(pcmk__output_t *out, va_list args) {
    unsigned int nnodes = va_arg(args, unsigned int);
    int nresources = va_arg(args, int);
    int ndisabled = va_arg(args, int);
    int nblocked = va_arg(args, int);

    xmlNode *nodes_xml = pcmk__output_create_xml_node(out, "li");
    xmlNode *resources_xml = pcmk__output_create_xml_node(out, "li");
    xmlNode *child = NULL;

    child = pcmk__html_create(nodes_xml, PCMK__XE_SPAN, NULL, NULL);
    pcmk__xe_set_content(child, "%d node%s configured",
                         nnodes, pcmk__plural_s(nnodes));

    if (ndisabled && nblocked) {
        child = pcmk__html_create(resources_xml, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child, "%d resource instance%s configured (%d ",
                             nresources, pcmk__plural_s(nresources), ndisabled);

        child = pcmk__html_create(resources_xml, PCMK__XE_SPAN, NULL,
                                  PCMK__VALUE_BOLD);
        pcmk__xe_set_content(child, "DISABLED");

        child = pcmk__html_create(resources_xml, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child, ", %d ", nblocked);

        child = pcmk__html_create(resources_xml, PCMK__XE_SPAN, NULL,
                                  PCMK__VALUE_BOLD);
        pcmk__xe_set_content(child, "BLOCKED");

        child = pcmk__html_create(resources_xml, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child, " from further action due to failure)");

    } else if (ndisabled && !nblocked) {
        child = pcmk__html_create(resources_xml, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child, "%d resource instance%s configured (%d ",
                             nresources, pcmk__plural_s(nresources),
                             ndisabled);

        child = pcmk__html_create(resources_xml, PCMK__XE_SPAN, NULL,
                                  PCMK__VALUE_BOLD);
        pcmk__xe_set_content(child, "DISABLED");

        child = pcmk__html_create(resources_xml, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child, ")");

    } else if (!ndisabled && nblocked) {
        child = pcmk__html_create(resources_xml, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child, "%d resource instance%s configured (%d ",
                             nresources, pcmk__plural_s(nresources),
                             nblocked);

        child = pcmk__html_create(resources_xml, PCMK__XE_SPAN, NULL,
                                  PCMK__VALUE_BOLD);
        pcmk__xe_set_content(child, "BLOCKED");

        child = pcmk__html_create(resources_xml, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child, " from further action due to failure)");

    } else {
        child = pcmk__html_create(resources_xml, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child, "%d resource instance%s configured",
                             nresources, pcmk__plural_s(nresources));
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("cluster-counts", "unsigned int", "int", "int", "int")
static int
cluster_counts_text(pcmk__output_t *out, va_list args) {
    unsigned int nnodes = va_arg(args, unsigned int);
    int nresources = va_arg(args, int);
    int ndisabled = va_arg(args, int);
    int nblocked = va_arg(args, int);

    out->list_item(out, NULL, "%d node%s configured",
                   nnodes, pcmk__plural_s(nnodes));

    if (ndisabled && nblocked) {
        out->list_item(out, NULL, "%d resource instance%s configured "
                                  "(%d DISABLED, %d BLOCKED from "
                                  "further action due to failure)",
                       nresources, pcmk__plural_s(nresources), ndisabled,
                       nblocked);
    } else if (ndisabled && !nblocked) {
        out->list_item(out, NULL, "%d resource instance%s configured "
                                  "(%d DISABLED)",
                       nresources, pcmk__plural_s(nresources), ndisabled);
    } else if (!ndisabled && nblocked) {
        out->list_item(out, NULL, "%d resource instance%s configured "
                                  "(%d BLOCKED from further action "
                                  "due to failure)",
                       nresources, pcmk__plural_s(nresources), nblocked);
    } else {
        out->list_item(out, NULL, "%d resource instance%s configured",
                       nresources, pcmk__plural_s(nresources));
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("cluster-counts", "unsigned int", "int", "int", "int")
static int
cluster_counts_xml(pcmk__output_t *out, va_list args) {
    unsigned int nnodes = va_arg(args, unsigned int);
    int nresources = va_arg(args, int);
    int ndisabled = va_arg(args, int);
    int nblocked = va_arg(args, int);

    xmlNode *xml = NULL;

    xml = pcmk__output_create_xml_node(out, PCMK_XE_NODES_CONFIGURED);
    pcmk__xe_set_int(xml, PCMK_XA_NUMBER, nnodes);

    xml = pcmk__output_create_xml_node(out, PCMK_XE_RESOURCES_CONFIGURED);
    pcmk__xe_set_int(xml, PCMK_XA_NUMBER, nresources);
    pcmk__xe_set_int(xml, PCMK_XA_DISABLED, ndisabled);
    pcmk__xe_set_int(xml, PCMK_XA_BLOCKED, nblocked);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("cluster-dc", "pcmk_node_t *", "const char *", "const char *",
                  "char *", "int")
static int
cluster_dc_html(pcmk__output_t *out, va_list args) {
    pcmk_node_t *dc = va_arg(args, pcmk_node_t *);
    const char *quorum = va_arg(args, const char *);
    const char *dc_version_s = va_arg(args, const char *);
    char *dc_name = va_arg(args, char *);
    bool mixed_version = va_arg(args, int);

    xmlNode *xml = pcmk__output_create_xml_node(out, "li");
    xmlNode *child = NULL;

    child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL, PCMK__VALUE_BOLD);
    pcmk__xe_set_content(child, "Current DC: ");

    if (dc) {
        child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child, "%s (version %s) -",
                             dc_name, pcmk__s(dc_version_s, "unknown"));

        if (mixed_version) {
            child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL,
                                      PCMK__VALUE_WARNING);
            pcmk__xe_set_content(child, " MIXED-VERSION");
        }

        child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child, " partition");

        if (pcmk__is_true(quorum)) {
            child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL, NULL);
            pcmk__xe_set_content(child, " with");

        } else {
            child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL,
                                      PCMK__VALUE_WARNING);
            pcmk__xe_set_content(child, " WITHOUT");
        }

        child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child, " quorum");

    } else {
        child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL,
                                  PCMK__VALUE_WARNING);
        pcmk__xe_set_content(child, "NONE");
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("cluster-dc", "pcmk_node_t *", "const char *", "const char *",
                  "char *", "int")
static int
cluster_dc_text(pcmk__output_t *out, va_list args) {
    pcmk_node_t *dc = va_arg(args, pcmk_node_t *);
    const char *quorum = va_arg(args, const char *);
    const char *dc_version_s = va_arg(args, const char *);
    char *dc_name = va_arg(args, char *);
    bool mixed_version = va_arg(args, int);

    if (dc) {
        out->list_item(out, "Current DC",
                       "%s (version %s) - %spartition %s quorum",
                       dc_name, dc_version_s ? dc_version_s : "unknown",
                       mixed_version ? "MIXED-VERSION " : "",
                       pcmk__is_true(quorum) ? "with" : "WITHOUT");
    } else {
        out->list_item(out, "Current DC", "NONE");
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("cluster-dc", "pcmk_node_t *", "const char *", "const char *",
                  "char *", "int")
static int
cluster_dc_xml(pcmk__output_t *out, va_list args) {
    pcmk_node_t *dc = va_arg(args, pcmk_node_t *);
    const char *quorum = va_arg(args, const char *);
    const char *dc_version_s = va_arg(args, const char *);
    char *dc_name G_GNUC_UNUSED = va_arg(args, char *);
    bool mixed_version = va_arg(args, int);

    xmlNode *xml = pcmk__output_create_xml_node(out, PCMK_XE_CURRENT_DC);

    if (dc == NULL) {
        pcmk__xe_set(xml, PCMK_XA_PRESENT, PCMK_VALUE_FALSE);
        return pcmk_rc_ok;
    }

    pcmk__xe_set(xml, PCMK_XA_PRESENT, PCMK_VALUE_TRUE);
    pcmk__xe_set(xml, PCMK_XA_VERSION, pcmk__s(dc_version_s, ""));
    pcmk__xe_set(xml, PCMK_XA_NAME, dc->priv->name);
    pcmk__xe_set(xml, PCMK_XA_ID, dc->priv->id);
    pcmk__xe_set_bool(xml, PCMK_XA_WITH_QUORUM, pcmk__is_true(quorum)),
    pcmk__xe_set_bool(xml, PCMK_XA_MIXED_VERSION, mixed_version);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("maint-mode", "uint64_t")
static int
cluster_maint_mode_text(pcmk__output_t *out, va_list args) {
    uint64_t flags = va_arg(args, uint64_t);

    if (pcmk__is_set(flags, pcmk__sched_in_maintenance)) {
        pcmk__formatted_printf(out, "\n              *** Resource management is DISABLED ***\n");
        pcmk__formatted_printf(out, "  The cluster will not attempt to start, stop or recover services\n");
        return pcmk_rc_ok;
    } else if (pcmk__is_set(flags, pcmk__sched_stop_all)) {
        pcmk__formatted_printf(out, "\n    *** Resource management is DISABLED ***\n");
        pcmk__formatted_printf(out, "  The cluster will keep all resources stopped\n");
        return pcmk_rc_ok;
    } else {
        return pcmk_rc_no_output;
    }
}

PCMK__OUTPUT_ARGS("cluster-options", "pcmk_scheduler_t *")
static int
cluster_options_html(pcmk__output_t *out, va_list args) {
    pcmk_scheduler_t *scheduler = va_arg(args, pcmk_scheduler_t *);

    if (pcmk__is_set(scheduler->flags, pcmk__sched_fencing_enabled)) {
        out->list_item(out, NULL, "Fencing of failed nodes enabled");
    } else {
        out->list_item(out, NULL, "Fencing of failed nodes disabled");
    }

    if (pcmk__is_set(scheduler->flags, pcmk__sched_symmetric_cluster)) {
        out->list_item(out, NULL, "Cluster is symmetric");
    } else {
        out->list_item(out, NULL, "Cluster is asymmetric");
    }

    switch (scheduler->no_quorum_policy) {
        /* @COMPAT These should say something like "resources that require
         * quorum" since resources with requires="nothing" are unaffected, but
         * it would be a good idea to investigate whether any major projects
         * search for this text first
         */
        case pcmk_no_quorum_freeze:
            out->list_item(out, NULL, "No quorum policy: Freeze resources");
            break;

        case pcmk_no_quorum_stop:
            out->list_item(out, NULL, "No quorum policy: Stop ALL resources");
            break;

        case pcmk_no_quorum_demote:
            out->list_item(out, NULL, "No quorum policy: Demote promotable "
                           "resources and stop all other resources");
            break;

        case pcmk_no_quorum_ignore:
            out->list_item(out, NULL, "No quorum policy: Ignore");
            break;

        case pcmk_no_quorum_fence:
            out->list_item(out, NULL,
                           "No quorum policy: Fence nodes in partition");
            break;
    }

    if (pcmk__is_set(scheduler->flags, pcmk__sched_in_maintenance)) {
        xmlNode *xml = pcmk__output_create_xml_node(out, "li");
        xmlNode *child = NULL;

        child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child, "Resource management: ");

        child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL, PCMK__VALUE_BOLD);
        pcmk__xe_set_content(child, "DISABLED");

        child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child,
                             " (the cluster will not attempt to start, stop,"
                             " or recover services)");

    } else if (pcmk__is_set(scheduler->flags, pcmk__sched_stop_all)) {
        xmlNode *xml = pcmk__output_create_xml_node(out, "li");
        xmlNode *child = NULL;

        child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child, "Resource management: ");

        child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL, PCMK__VALUE_BOLD);
        pcmk__xe_set_content(child, "STOPPED");

        child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child,
                             " (the cluster will keep all resources stopped)");

    } else {
        out->list_item(out, NULL, "Resource management: enabled");
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("cluster-options", "pcmk_scheduler_t *")
static int
cluster_options_log(pcmk__output_t *out, va_list args) {
    pcmk_scheduler_t *scheduler = va_arg(args, pcmk_scheduler_t *);

    if (pcmk__is_set(scheduler->flags, pcmk__sched_in_maintenance)) {
        return out->info(out, "Resource management is DISABLED.  The cluster will not attempt to start, stop or recover services.");
    } else if (pcmk__is_set(scheduler->flags, pcmk__sched_stop_all)) {
        return out->info(out, "Resource management is DISABLED.  The cluster has stopped all resources.");
    } else {
        return pcmk_rc_no_output;
    }
}

PCMK__OUTPUT_ARGS("cluster-options", "pcmk_scheduler_t *")
static int
cluster_options_text(pcmk__output_t *out, va_list args) {
    pcmk_scheduler_t *scheduler = va_arg(args, pcmk_scheduler_t *);

    if (pcmk__is_set(scheduler->flags, pcmk__sched_fencing_enabled)) {
        out->list_item(out, NULL, "Fencing of failed nodes enabled");
    } else {
        out->list_item(out, NULL, "Fencing of failed nodes disabled");
    }

    if (pcmk__is_set(scheduler->flags, pcmk__sched_symmetric_cluster)) {
        out->list_item(out, NULL, "Cluster is symmetric");
    } else {
        out->list_item(out, NULL, "Cluster is asymmetric");
    }

    switch (scheduler->no_quorum_policy) {
        case pcmk_no_quorum_freeze:
            out->list_item(out, NULL, "No quorum policy: Freeze resources");
            break;

        case pcmk_no_quorum_stop:
            out->list_item(out, NULL, "No quorum policy: Stop ALL resources");
            break;

        case pcmk_no_quorum_demote:
            out->list_item(out, NULL, "No quorum policy: Demote promotable "
                           "resources and stop all other resources");
            break;

        case pcmk_no_quorum_ignore:
            out->list_item(out, NULL, "No quorum policy: Ignore");
            break;

        case pcmk_no_quorum_fence:
            out->list_item(out, NULL,
                           "No quorum policy: Fence nodes in partition");
            break;
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Get readable string representation of a no-quorum policy
 *
 * \param[in] policy  No-quorum policy
 *
 * \return String representation of \p policy
 */
static const char *
no_quorum_policy_text(enum pe_quorum_policy policy)
{
    switch (policy) {
        case pcmk_no_quorum_freeze:
            return PCMK_VALUE_FREEZE;

        case pcmk_no_quorum_stop:
            return PCMK_VALUE_STOP;

        case pcmk_no_quorum_demote:
            return PCMK_VALUE_DEMOTE;

        case pcmk_no_quorum_ignore:
            return PCMK_VALUE_IGNORE;

        case pcmk_no_quorum_fence:
            return PCMK_VALUE_FENCE;

        default:
            return PCMK_VALUE_UNKNOWN;
    }
}

PCMK__OUTPUT_ARGS("cluster-options", "pcmk_scheduler_t *")
static int
cluster_options_xml(pcmk__output_t *out, va_list args) {
    pcmk_scheduler_t *scheduler = va_arg(args, pcmk_scheduler_t *);

    const char *fencing_enabled = pcmk__flag_text(scheduler->flags,
                                                  pcmk__sched_fencing_enabled);
    const char *symmetric_cluster =
        pcmk__flag_text(scheduler->flags, pcmk__sched_symmetric_cluster);
    const char *no_quorum_policy =
        no_quorum_policy_text(scheduler->no_quorum_policy);
    const char *maintenance_mode = pcmk__flag_text(scheduler->flags,
                                                   pcmk__sched_in_maintenance);
    const char *stop_all_resources = pcmk__flag_text(scheduler->flags,
                                                     pcmk__sched_stop_all);

    xmlNode *xml = pcmk__output_create_xml_node(out, PCMK_XE_CLUSTER_OPTIONS);

    pcmk__xe_set(xml, PCMK_XA_FENCING_ENABLED, fencing_enabled);
    pcmk__xe_set_guint(xml, PCMK_XA_FENCING_TIMEOUT_MS,
                       scheduler->priv->fence_timeout_ms);
    pcmk__xe_set(xml, PCMK_XA_SYMMETRIC_CLUSTER, symmetric_cluster);
    pcmk__xe_set(xml, PCMK_XA_NO_QUORUM_POLICY, no_quorum_policy);
    pcmk__xe_set(xml, PCMK_XA_MAINTENANCE_MODE, maintenance_mode);
    pcmk__xe_set(xml, PCMK_XA_STOP_ALL_RESOURCES, stop_all_resources);
    pcmk__xe_set_guint(xml, PCMK_XA_PRIORITY_FENCING_DELAY_MS,
                       scheduler->priv->priority_fencing_ms);

    /* @COMPAT PCMK_XA_STONITH_ENABLED and PCMK_XA_STONITH_TIMEOUT_MS are
     * deprecated since 3.0.2
     */
    pcmk__xe_set(xml, PCMK_XA_STONITH_ENABLED, fencing_enabled);
    pcmk__xe_set_guint(xml, PCMK_XA_STONITH_TIMEOUT_MS,
                       scheduler->priv->fence_timeout_ms);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("cluster-stack", "const char *", "enum pcmk_pacemakerd_state")
static int
cluster_stack_html(pcmk__output_t *out, va_list args) {
    const char *stack_s = va_arg(args, const char *);
    enum pcmk_pacemakerd_state pcmkd_state =
        (enum pcmk_pacemakerd_state) va_arg(args, int);

    xmlNode *xml = pcmk__output_create_xml_node(out, "li");
    xmlNode *child = NULL;

    child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL, PCMK__VALUE_BOLD);
    pcmk__xe_set_content(child, "Stack: ");

    child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL, NULL);
    pcmk__xe_set_content(child, "%s", stack_s);

    if (pcmkd_state != pcmk_pacemakerd_state_invalid) {
        child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child, " (");

        child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child, "%s",
                             pcmk__pcmkd_state_enum2friendly(pcmkd_state));

        child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child, ")");
    }
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("cluster-stack", "const char *", "enum pcmk_pacemakerd_state")
static int
cluster_stack_text(pcmk__output_t *out, va_list args) {
    const char *stack_s = va_arg(args, const char *);
    enum pcmk_pacemakerd_state pcmkd_state =
        (enum pcmk_pacemakerd_state) va_arg(args, int);

    if (pcmkd_state != pcmk_pacemakerd_state_invalid) {
        out->list_item(out, "Stack", "%s (%s)",
                       stack_s, pcmk__pcmkd_state_enum2friendly(pcmkd_state));
    } else {
        out->list_item(out, "Stack", "%s", stack_s);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("cluster-stack", "const char *", "enum pcmk_pacemakerd_state")
static int
cluster_stack_xml(pcmk__output_t *out, va_list args) {
    const char *stack_s = va_arg(args, const char *);
    enum pcmk_pacemakerd_state pcmkd_state =
        (enum pcmk_pacemakerd_state) va_arg(args, int);

    xmlNode *xml = NULL;
    const char *state_s = NULL;

    if (pcmkd_state != pcmk_pacemakerd_state_invalid) {
        state_s = pcmk_pacemakerd_api_daemon_state_enum2text(pcmkd_state);
    }

    xml = pcmk__output_create_xml_node(out, PCMK_XE_STACK);
    pcmk__xe_set(xml, PCMK_XA_TYPE, stack_s);
    pcmk__xe_set(xml, PCMK_XA_PACEMAKERD_STATE, state_s);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("cluster-times", "const char *", "const char *",
                  "const char *", "const char *", "const char *")
static int
cluster_times_html(pcmk__output_t *out, va_list args) {
    const char *our_nodename = va_arg(args, const char *);
    const char *last_written = va_arg(args, const char *);
    const char *user = va_arg(args, const char *);
    const char *client = va_arg(args, const char *);
    const char *origin = va_arg(args, const char *);

    xmlNode *updated = pcmk__output_create_xml_node(out, "li");
    xmlNode *changed = pcmk__output_create_xml_node(out, "li");
    xmlNode *child = NULL;

    char *time_s = NULL;

    child = pcmk__html_create(updated, PCMK__XE_SPAN, NULL, PCMK__VALUE_BOLD);
    pcmk__xe_set_content(child, "Last updated: ");

    child = pcmk__html_create(updated, PCMK__XE_SPAN, NULL, NULL);
    time_s = pcmk__epoch2str(NULL, 0);
    pcmk__xe_set_content(child, "%s", time_s);
    free(time_s);

    if (our_nodename != NULL) {
        child = pcmk__html_create(updated, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child, " on ");

        child = pcmk__html_create(updated, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child, "%s", our_nodename);
    }

    child = pcmk__html_create(changed, PCMK__XE_SPAN, NULL, PCMK__VALUE_BOLD);
    pcmk__xe_set_content(child, "Last change: ");

    child = pcmk__html_create(changed, PCMK__XE_SPAN, NULL, NULL);
    time_s = last_changed_string(last_written, user, client, origin);
    pcmk__xe_set_content(child, "%s", time_s);
    free(time_s);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("cluster-times", "const char *", "const char *",
                  "const char *", "const char *", "const char *")
static int
cluster_times_xml(pcmk__output_t *out, va_list args) {
    const char *our_nodename = va_arg(args, const char *);
    const char *last_written = va_arg(args, const char *);
    const char *user = va_arg(args, const char *);
    const char *client = va_arg(args, const char *);
    const char *origin = va_arg(args, const char *);

    xmlNode *xml = NULL;
    char *time_s = pcmk__epoch2str(NULL, 0);

    xml = pcmk__output_create_xml_node(out, PCMK_XE_LAST_UPDATE);
    pcmk__xe_set(xml, PCMK_XA_TIME, time_s);
    pcmk__xe_set(xml, PCMK_XA_ORIGIN, our_nodename);

    xml = pcmk__output_create_xml_node(out, PCMK_XE_LAST_CHANGE);
    pcmk__xe_set(xml, PCMK_XA_TIME, pcmk__s(last_written, ""));
    pcmk__xe_set(xml, PCMK_XA_USER, pcmk__s(user, ""));
    pcmk__xe_set(xml, PCMK_XA_CLIENT, pcmk__s(client, ""));
    pcmk__xe_set(xml, PCMK_XA_ORIGIN, pcmk__s(origin, ""));

    free(time_s);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("cluster-times", "const char *", "const char *",
                  "const char *", "const char *", "const char *")
static int
cluster_times_text(pcmk__output_t *out, va_list args) {
    const char *our_nodename = va_arg(args, const char *);
    const char *last_written = va_arg(args, const char *);
    const char *user = va_arg(args, const char *);
    const char *client = va_arg(args, const char *);
    const char *origin = va_arg(args, const char *);

    char *time_s = pcmk__epoch2str(NULL, 0);

    out->list_item(out, "Last updated", "%s%s%s",
                   time_s, (our_nodename != NULL)? " on " : "",
                   pcmk__s(our_nodename, ""));

    free(time_s);
    time_s = last_changed_string(last_written, user, client, origin);

    out->list_item(out, "Last change", " %s", time_s);

    free(time_s);
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Display a failed action in less-technical natural language
 *
 * \param[in,out] out          Output object to use for display
 * \param[in]     xml_op       XML containing failed action
 * \param[in]     op_key       Operation key of failed action
 * \param[in]     node_name    Where failed action occurred
 * \param[in]     rc           OCF exit code of failed action
 * \param[in]     status       Execution status of failed action
 * \param[in]     exit_reason  Exit reason given for failed action
 * \param[in]     exec_time    String containing execution time in milliseconds
 */
static void
failed_action_friendly(pcmk__output_t *out, const xmlNode *xml_op,
                       const char *op_key, const char *node_name, int rc,
                       int status, const char *exit_reason,
                       const char *exec_time)
{
    char *rsc_id = NULL;
    char *task = NULL;
    guint interval_ms = 0;
    time_t last_change_epoch = 0;
    GString *str = NULL;

    if (pcmk__str_empty(op_key)
        || !parse_op_key(op_key, &rsc_id, &task, &interval_ms)) {

        pcmk__str_update(&rsc_id, "unknown resource");
        pcmk__str_update(&task, "unknown action");
        interval_ms = 0;
    }
    pcmk__assert((rsc_id != NULL) && (task != NULL));

    str = g_string_sized_new(256); // Should be sufficient for most messages

    pcmk__g_strcat(str, rsc_id, " ", NULL);

    if (interval_ms != 0) {
        pcmk__g_strcat(str, pcmk__readable_interval(interval_ms), "-interval ",
                       NULL);
    }
    pcmk__g_strcat(str, pcmk__readable_action(task, interval_ms), " on ",
                   node_name, NULL);

    if (status == PCMK_EXEC_DONE) {
        pcmk__g_strcat(str, " returned '", crm_exit_str(rc), "'", NULL);
        if (!pcmk__str_empty(exit_reason)) {
            pcmk__g_strcat(str, " (", exit_reason, ")", NULL);
        }

    } else {
        pcmk__g_strcat(str, " could not be executed (",
                       pcmk_exec_status_str(status), NULL);
        if (!pcmk__str_empty(exit_reason)) {
            pcmk__g_strcat(str, ": ", exit_reason, NULL);
        }
        g_string_append_c(str, ')');
    }


    if (pcmk__xe_get_time(xml_op, PCMK_XA_LAST_RC_CHANGE,
                          &last_change_epoch) == pcmk_rc_ok) {
        char *s = pcmk__epoch2str(&last_change_epoch, 0);

        pcmk__g_strcat(str, " at ", s, NULL);
        free(s);
    }
    if (!pcmk__str_empty(exec_time)) {
        int exec_time_ms = 0;

        if ((pcmk__scan_min_int(exec_time, &exec_time_ms, 0) == pcmk_rc_ok)
            && (exec_time_ms > 0)) {

            pcmk__g_strcat(str, " after ",
                           pcmk__readable_interval(exec_time_ms), NULL);
        }
    }

    out->list_item(out, NULL, "%s", str->str);
    g_string_free(str, TRUE);
    free(rsc_id);
    free(task);
}

/*!
 * \internal
 * \brief Display a failed action with technical details
 *
 * \param[in,out] out          Output object to use for display
 * \param[in]     xml_op       XML containing failed action
 * \param[in]     op_key       Operation key of failed action
 * \param[in]     node_name    Where failed action occurred
 * \param[in]     rc           OCF exit code of failed action
 * \param[in]     status       Execution status of failed action
 * \param[in]     exit_reason  Exit reason given for failed action
 * \param[in]     exec_time    String containing execution time in milliseconds
 */
static void
failed_action_technical(pcmk__output_t *out, const xmlNode *xml_op,
                        const char *op_key, const char *node_name, int rc,
                        int status, const char *exit_reason,
                        const char *exec_time)
{
    const char *call_id = pcmk__xe_get(xml_op, PCMK__XA_CALL_ID);
    const char *queue_time = pcmk__xe_get(xml_op, PCMK_XA_QUEUE_TIME);
    const char *exit_status = crm_exit_str(rc);
    const char *lrm_status = pcmk_exec_status_str(status);
    time_t last_change_epoch = 0;
    GString *str = NULL;

    if (pcmk__str_empty(op_key)) {
        op_key = "unknown operation";
    }
    if (pcmk__str_empty(exit_status)) {
        exit_status = "unknown exit status";
    }
    if (pcmk__str_empty(call_id)) {
        call_id = "unknown";
    }

    str = g_string_sized_new(256);

    g_string_append_printf(str, "%s on %s '%s' (%d): call=%s, status='%s'",
                           op_key, node_name, exit_status, rc, call_id,
                           lrm_status);

    if (!pcmk__str_empty(exit_reason)) {
        pcmk__g_strcat(str, ", exitreason='", exit_reason, "'", NULL);
    }

    if (pcmk__xe_get_time(xml_op, PCMK_XA_LAST_RC_CHANGE,
                          &last_change_epoch) == pcmk_rc_ok) {
        char *last_change_str = pcmk__epoch2str(&last_change_epoch, 0);

        pcmk__g_strcat(str,
                       ", " PCMK_XA_LAST_RC_CHANGE "="
                       "'", last_change_str, "'", NULL);
        free(last_change_str);
    }
    if (!pcmk__str_empty(queue_time)) {
        pcmk__g_strcat(str, ", queued=", queue_time, "ms", NULL);
    }
    if (!pcmk__str_empty(exec_time)) {
        pcmk__g_strcat(str, ", exec=", exec_time, "ms", NULL);
    }

    out->list_item(out, NULL, "%s", str->str);
    g_string_free(str, TRUE);
}

PCMK__OUTPUT_ARGS("failed-action", "xmlNode *", "uint32_t")
static int
failed_action_default(pcmk__output_t *out, va_list args)
{
    xmlNodePtr xml_op = va_arg(args, xmlNodePtr);
    uint32_t show_opts = va_arg(args, uint32_t);

    const char *op_key = pcmk__xe_history_key(xml_op);
    const char *node_name = pcmk__xe_get(xml_op, PCMK_XA_UNAME);
    const char *exit_reason = pcmk__xe_get(xml_op, PCMK_XA_EXIT_REASON);
    const char *exec_time = pcmk__xe_get(xml_op, PCMK_XA_EXEC_TIME);

    int rc;
    int status;

    pcmk__scan_min_int(pcmk__xe_get(xml_op, PCMK__XA_RC_CODE), &rc, 0);
    pcmk__scan_min_int(pcmk__xe_get(xml_op, PCMK__XA_OP_STATUS), &status, 0);

    if (pcmk__str_empty(node_name)) {
        node_name = "unknown node";
    }

    if (pcmk__is_set(show_opts, pcmk_show_failed_detail)) {
        failed_action_technical(out, xml_op, op_key, node_name, rc, status,
                                exit_reason, exec_time);
    } else {
        failed_action_friendly(out, xml_op, op_key, node_name, rc, status,
                               exit_reason, exec_time);
    }
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("failed-action", "xmlNode *", "uint32_t")
static int
failed_action_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr xml_op = va_arg(args, xmlNodePtr);
    uint32_t show_opts G_GNUC_UNUSED = va_arg(args, uint32_t);

    const char *op_key = pcmk__xe_history_key(xml_op);
    const char *op_key_name = PCMK_XA_OP_KEY;
    int rc;
    int status;
    const char *uname = pcmk__xe_get(xml_op, PCMK_XA_UNAME);
    const char *call_id = pcmk__xe_get(xml_op, PCMK__XA_CALL_ID);
    const char *exit_reason = pcmk__s(pcmk__xe_get(xml_op, PCMK_XA_EXIT_REASON),
                                      "none");

    time_t epoch = 0;
    xmlNode *xml = NULL;
    gchar *exit_reason_esc = pcmk__xml_escape(exit_reason,
                                              pcmk__xml_escape_attr);

    pcmk__scan_min_int(pcmk__xe_get(xml_op, PCMK__XA_RC_CODE), &rc, 0);
    pcmk__scan_min_int(pcmk__xe_get(xml_op, PCMK__XA_OP_STATUS), &status, 0);

    if (pcmk__xe_get(xml_op, PCMK__XA_OPERATION_KEY) == NULL) {
        op_key_name = PCMK_XA_ID;
    }

    xml = pcmk__output_create_xml_node(out, PCMK_XE_FAILURE);
    pcmk__xe_set(xml, op_key_name, op_key);
    pcmk__xe_set(xml, PCMK_XA_NODE, uname);
    pcmk__xe_set(xml, PCMK_XA_EXITSTATUS, crm_exit_str(rc));
    pcmk__xe_set(xml, PCMK_XA_EXITREASON, exit_reason_esc);
    pcmk__xe_set_int(xml, PCMK_XA_EXITCODE, rc);
    pcmk__xe_set(xml, PCMK_XA_CALL, call_id);
    pcmk__xe_set(xml, PCMK_XA_STATUS, pcmk_exec_status_str(status));

    pcmk__xe_get_time(xml_op, PCMK_XA_LAST_RC_CHANGE, &epoch);
    if (epoch > 0) {
        const char *queue_time = pcmk__xe_get(xml_op, PCMK_XA_QUEUE_TIME);
        const char *exec = pcmk__xe_get(xml_op, PCMK_XA_EXEC_TIME);
        const char *task = pcmk__xe_get(xml_op, PCMK_XA_OPERATION);
        guint interval_ms = 0;
        char *rc_change = pcmk__epoch2str(&epoch,
                                          crm_time_log_date
                                          |crm_time_log_timeofday
                                          |crm_time_log_with_timezone);

        pcmk__xe_get_guint(xml_op, PCMK_META_INTERVAL, &interval_ms);

        pcmk__xe_set(xml, PCMK_XA_LAST_RC_CHANGE, rc_change);
        pcmk__xe_set(xml, PCMK_XA_QUEUED, queue_time);
        pcmk__xe_set(xml, PCMK_XA_EXEC, exec);
        pcmk__xe_set_guint(xml, PCMK_XA_INTERVAL, interval_ms);
        pcmk__xe_set(xml, PCMK_XA_TASK, task);

        free(rc_change);
    }

    g_free(exit_reason_esc);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("failed-action-list", "pcmk_scheduler_t *", "GList *",
                  "GList *", "uint32_t", "bool")
static int
failed_action_list(pcmk__output_t *out, va_list args) {
    pcmk_scheduler_t *scheduler = va_arg(args, pcmk_scheduler_t *);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool print_spacer = va_arg(args, int);

    xmlNode *xml_op = NULL;
    int rc = pcmk_rc_no_output;

    if (xmlChildElementCount(scheduler->priv->failed) == 0) {
        return rc;
    }

    for (xml_op = pcmk__xe_first_child(scheduler->priv->failed, NULL, NULL,
                                       NULL);
         xml_op != NULL; xml_op = pcmk__xe_next(xml_op, NULL)) {

        char *rsc = NULL;

        if (!pcmk__str_in_list(pcmk__xe_get(xml_op, PCMK_XA_UNAME), only_node,
                               pcmk__str_star_matches|pcmk__str_casei)) {
            continue;
        }

        if (pcmk_xe_mask_probe_failure(xml_op)) {
            continue;
        }

        if (!parse_op_key(pcmk__xe_history_key(xml_op), &rsc, NULL, NULL)) {
            continue;
        }

        if (!pcmk__str_in_list(rsc, only_rsc, pcmk__str_star_matches)) {
            free(rsc);
            continue;
        }

        free(rsc);

        PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Failed Resource Actions");
        out->message(out, "failed-action", xml_op, show_opts);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

static void
status_node(pcmk_node_t *node, xmlNodePtr parent, uint32_t show_opts)
{
    int health = pe__node_health(node);
    xmlNode *child = NULL;

    // Cluster membership
    if (node->details->online) {
        child = pcmk__html_create(parent, PCMK__XE_SPAN, NULL,
                                  PCMK_VALUE_ONLINE);
        pcmk__xe_set_content(child, " online");

    } else {
        child = pcmk__html_create(parent, PCMK__XE_SPAN, NULL,
                                  PCMK_VALUE_OFFLINE);
        pcmk__xe_set_content(child, " OFFLINE");
    }

    // Standby mode
    if (pcmk__is_set(node->priv->flags, pcmk__node_fail_standby)) {
        child = pcmk__html_create(parent, PCMK__XE_SPAN, NULL,
                                  PCMK_VALUE_STANDBY);
        if (node->details->running_rsc == NULL) {
            pcmk__xe_set_content(child,
                                 " (in standby due to " PCMK_META_ON_FAIL ")");
        } else {
            pcmk__xe_set_content(child,
                                 " (in standby due to " PCMK_META_ON_FAIL ","
                                 " with active resources)");
        }

    } else if (pcmk__is_set(node->priv->flags, pcmk__node_standby)) {
        child = pcmk__html_create(parent, PCMK__XE_SPAN, NULL,
                                  PCMK_VALUE_STANDBY);
        if (node->details->running_rsc == NULL) {
            pcmk__xe_set_content(child, " (in standby)");
        } else {
            pcmk__xe_set_content(child, " (in standby, with active resources)");
        }
    }

    // Maintenance mode
    if (node->details->maintenance) {
        child = pcmk__html_create(parent, PCMK__XE_SPAN, NULL,
                                  PCMK__VALUE_MAINT);
        pcmk__xe_set_content(child, " (in maintenance mode)");
    }

    // Node health
    if (health < 0) {
        child = pcmk__html_create(parent, PCMK__XE_SPAN, NULL,
                                  PCMK__VALUE_HEALTH_RED);
        pcmk__xe_set_content(child, " (health is RED)");

    } else if (health == 0) {
        child = pcmk__html_create(parent, PCMK__XE_SPAN, NULL,
                                  PCMK__VALUE_HEALTH_YELLOW);
        pcmk__xe_set_content(child, " (health is YELLOW)");
    }

    // Feature set
    if (pcmk__is_set(show_opts, pcmk_show_feature_set)) {
        const char *feature_set = get_node_feature_set(node);
        if (feature_set != NULL) {
            child = pcmk__html_create(parent, PCMK__XE_SPAN, NULL, NULL);
            pcmk__xe_set_content(child, ", feature set %s", feature_set);
        }
    }
}

PCMK__OUTPUT_ARGS("node", "pcmk_node_t *", "uint32_t", "bool",
                  "GList *", "GList *")
static int
node_html(pcmk__output_t *out, va_list args) {
    pcmk_node_t *node = va_arg(args, pcmk_node_t *);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool full = va_arg(args, int);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    char *node_name = pe__node_display_name(node,
                                            pcmk__is_set(show_opts,
                                                         pcmk_show_node_id));

    if (full) {
        xmlNode *item_node = NULL;
        xmlNode *child = NULL;

        if (pcmk__all_flags_set(show_opts,
                                pcmk_show_brief|pcmk_show_rscs_by_node)) {
            GList *rscs = pe__filter_rsc_list(node->details->running_rsc, only_rsc);

            out->begin_list(out, NULL, NULL, "%s:", node_name);
            item_node = pcmk__output_xml_create_parent(out, "li");
            child = pcmk__html_create(item_node, PCMK__XE_SPAN, NULL, NULL);
            pcmk__xe_set_content(child, "Status:");
            status_node(node, item_node, show_opts);

            if (rscs != NULL) {
                uint32_t new_show_opts = (show_opts | pcmk_show_rsc_only) & ~pcmk_show_inactive_rscs;
                out->begin_list(out, NULL, NULL, "Resources");
                pe__rscs_brief_output(out, rscs, new_show_opts);
                out->end_list(out);
            }

            pcmk__output_xml_pop_parent(out);
            out->end_list(out);

        } else if (pcmk__is_set(show_opts, pcmk_show_rscs_by_node)) {
            GList *lpc2 = NULL;
            int rc = pcmk_rc_no_output;

            out->begin_list(out, NULL, NULL, "%s:", node_name);
            item_node = pcmk__output_xml_create_parent(out, "li");
            child = pcmk__html_create(item_node, PCMK__XE_SPAN, NULL, NULL);
            pcmk__xe_set_content(child, "Status:");
            status_node(node, item_node, show_opts);

            for (lpc2 = node->details->running_rsc; lpc2 != NULL; lpc2 = lpc2->next) {
                pcmk_resource_t *rsc = (pcmk_resource_t *) lpc2->data;

                PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Resources");

                show_opts |= pcmk_show_rsc_only;
                out->message(out, (const char *) rsc->priv->xml->name,
                             show_opts, rsc, only_node, only_rsc);
            }

            PCMK__OUTPUT_LIST_FOOTER(out, rc);
            pcmk__output_xml_pop_parent(out);
            out->end_list(out);

        } else {
            item_node = pcmk__output_create_xml_node(out, "li");
            child = pcmk__html_create(item_node, PCMK__XE_SPAN, NULL,
                                      PCMK__VALUE_BOLD);
            pcmk__xe_set_content(child, "%s:", node_name);
            status_node(node, item_node, show_opts);
        }
    } else {
        out->begin_list(out, NULL, NULL, "%s:", node_name);
    }

    free(node_name);
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Get a human-friendly textual description of a node's status
 *
 * \param[in] node  Node to check
 *
 * \return String representation of node's status
 */
static const char *
node_text_status(const pcmk_node_t *node)
{
    if (node->details->unclean) {
        if (node->details->online) {
            return "UNCLEAN (online)";

        } else if (node->details->pending) {
            return "UNCLEAN (pending)";

        } else {
            return "UNCLEAN (offline)";
        }

    } else if (node->details->pending) {
        return "pending";

    } else if (pcmk__is_set(node->priv->flags, pcmk__node_fail_standby)
               && node->details->online) {
        return "standby (" PCMK_META_ON_FAIL ")";

    } else if (pcmk__is_set(node->priv->flags, pcmk__node_standby)) {
        if (!node->details->online) {
            return "OFFLINE (standby)";
        } else if (node->details->running_rsc == NULL) {
            return "standby";
        } else {
            return "standby (with active resources)";
        }

    } else if (node->details->maintenance) {
        if (node->details->online) {
            return "maintenance";
        } else {
            return "OFFLINE (maintenance)";
        }

    } else if (node->details->online) {
        return "online";
    }

    return "OFFLINE";
}

PCMK__OUTPUT_ARGS("node", "pcmk_node_t *", "uint32_t", "bool", "GList *",
                  "GList *")
static int
node_text(pcmk__output_t *out, va_list args) {
    pcmk_node_t *node = va_arg(args, pcmk_node_t *);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool full = va_arg(args, int);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    if (full) {
        char *node_name =
            pe__node_display_name(node,
                                  pcmk__is_set(show_opts, pcmk_show_node_id));
        GString *str = g_string_sized_new(64);
        int health = pe__node_health(node);

        // Create a summary line with node type, name, and status
        if (pcmk__is_guest_or_bundle_node(node)) {
            g_string_append(str, "GuestNode");
        } else if (pcmk__is_remote_node(node)) {
            g_string_append(str, "RemoteNode");
        } else {
            g_string_append(str, "Node");
        }
        pcmk__g_strcat(str, " ", node_name, ": ", node_text_status(node), NULL);

        if (health < 0) {
            g_string_append(str, " (health is RED)");
        } else if (health == 0) {
            g_string_append(str, " (health is YELLOW)");
        }
        if (pcmk__is_set(show_opts, pcmk_show_feature_set)) {
            const char *feature_set = get_node_feature_set(node);
            if (feature_set != NULL) {
                pcmk__g_strcat(str, ", feature set ", feature_set, NULL);
            }
        }

        /* If we're grouping by node, print its resources */
        if (pcmk__is_set(show_opts, pcmk_show_rscs_by_node)) {
            if (pcmk__is_set(show_opts, pcmk_show_brief)) {
                GList *rscs = pe__filter_rsc_list(node->details->running_rsc, only_rsc);

                if (rscs != NULL) {
                    uint32_t new_show_opts = (show_opts | pcmk_show_rsc_only) & ~pcmk_show_inactive_rscs;
                    out->begin_list(out, NULL, NULL, "%s", str->str);
                    out->begin_list(out, NULL, NULL, "Resources");

                    pe__rscs_brief_output(out, rscs, new_show_opts);

                    out->end_list(out);
                    out->end_list(out);

                    g_list_free(rscs);
                }

            } else {
                GList *gIter2 = NULL;

                out->begin_list(out, NULL, NULL, "%s", str->str);
                out->begin_list(out, NULL, NULL, "Resources");

                for (gIter2 = node->details->running_rsc; gIter2 != NULL; gIter2 = gIter2->next) {
                    pcmk_resource_t *rsc = (pcmk_resource_t *) gIter2->data;

                    show_opts |= pcmk_show_rsc_only;
                    out->message(out, (const char *) rsc->priv->xml->name,
                                 show_opts, rsc, only_node, only_rsc);
                }

                out->end_list(out);
                out->end_list(out);
            }
        } else {
            out->list_item(out, NULL, "%s", str->str);
        }

        g_string_free(str, TRUE);
        free(node_name);
    } else {
        char *node_name =
            pe__node_display_name(node,
                                  pcmk__is_set(show_opts, pcmk_show_node_id));

        out->begin_list(out, NULL, NULL, "Node: %s", node_name);
        free(node_name);
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Convert an integer health value to a string representation
 *
 * \param[in] health  Integer health value
 *
 * \retval \c PCMK_VALUE_RED if \p health is less than 0
 * \retval \c PCMK_VALUE_YELLOW if \p health is equal to 0
 * \retval \c PCMK_VALUE_GREEN if \p health is greater than 0
 */
static const char *
health_text(int health)
{
    if (health < 0) {
        return PCMK_VALUE_RED;
    } else if (health == 0) {
        return PCMK_VALUE_YELLOW;
    } else {
        return PCMK_VALUE_GREEN;
    }
}

/*!
 * \internal
 * \brief Convert a node variant to a string representation
 *
 * \param[in] variant  Node variant
 *
 * \retval \c PCMK_VALUE_MEMBER if \p node_type is \c pcmk__node_variant_cluster
 * \retval \c PCMK_VALUE_REMOTE if \p node_type is \c pcmk__node_variant_remote
 * \retval \c PCMK_VALUE_UNKNOWN otherwise
 */
static const char *
node_variant_text(enum pcmk__node_variant variant)
{
    switch (variant) {
        case pcmk__node_variant_cluster:
            return PCMK_VALUE_MEMBER;
        case pcmk__node_variant_remote:
            return PCMK_VALUE_REMOTE;
        default:
            return PCMK_VALUE_UNKNOWN;
    }
}

PCMK__OUTPUT_ARGS("node", "pcmk_node_t *", "uint32_t", "bool", "GList *",
                  "GList *")
static int
node_xml(pcmk__output_t *out, va_list args) {
    pcmk_node_t *node = va_arg(args, pcmk_node_t *);
    uint32_t show_opts G_GNUC_UNUSED = va_arg(args, uint32_t);
    bool full = va_arg(args, int);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    if (full) {
        xmlNode *xml = NULL;
        const char *standby = pcmk__flag_text(node->priv->flags,
                                              pcmk__node_standby);
        const char *standby_onfail = pcmk__flag_text(node->priv->flags,
                                                     pcmk__node_fail_standby);
        const char *health = health_text(pe__node_health(node));
        const char *feature_set = get_node_feature_set(node);
        const char *expected_up = pcmk__flag_text(node->priv->flags,
                                                  pcmk__node_expected_up);
        const bool is_dc = pcmk__same_node(node,
                                           node->priv->scheduler->dc_node);
        const char *node_type = node_variant_text(node->priv->variant);

        xml = pcmk__output_xml_create_parent(out, PCMK_XE_NODE);
        pcmk__xe_set(xml, PCMK_XA_NAME, node->priv->name);
        pcmk__xe_set(xml, PCMK_XA_ID, node->priv->id);
        pcmk__xe_set_bool(xml, PCMK_XA_ONLINE, node->details->online);
        pcmk__xe_set(xml, PCMK_XA_STANDBY, standby);
        pcmk__xe_set(xml, PCMK_XA_STANDBY_ONFAIL, standby_onfail);
        pcmk__xe_set_bool(xml, PCMK_XA_MAINTENANCE, node->details->maintenance);
        pcmk__xe_set_bool(xml, PCMK_XA_PENDING, node->details->pending);
        pcmk__xe_set_bool(xml, PCMK_XA_UNCLEAN, node->details->unclean);
        pcmk__xe_set(xml, PCMK_XA_HEALTH, health);
        pcmk__xe_set(xml, PCMK_XA_FEATURE_SET, feature_set);
        pcmk__xe_set_bool(xml, PCMK_XA_SHUTDOWN, node->details->shutdown);
        pcmk__xe_set(xml, PCMK_XA_EXPECTED_UP, expected_up);
        pcmk__xe_set_bool(xml, PCMK_XA_IS_DC, is_dc);
        pcmk__xe_set_int(xml, PCMK_XA_RESOURCES_RUNNING,
                         g_list_length(node->details->running_rsc));
        pcmk__xe_set(xml, PCMK_XA_TYPE, node_type);

        if (pcmk__is_guest_or_bundle_node(node)) {
            xmlNodePtr xml_node = pcmk__output_xml_peek_parent(out);
            pcmk__xe_set(xml_node, PCMK_XA_ID_AS_RESOURCE,
                         node->priv->remote->priv->launcher->id);
        }

        if (pcmk__is_set(show_opts, pcmk_show_rscs_by_node)) {
            GList *lpc = NULL;

            for (lpc = node->details->running_rsc; lpc != NULL; lpc = lpc->next) {
                pcmk_resource_t *rsc = (pcmk_resource_t *) lpc->data;

                show_opts |= pcmk_show_rsc_only;
                out->message(out, (const char *) rsc->priv->xml->name,
                             show_opts, rsc, only_node, only_rsc);
            }
        }

        out->end_list(out);

    } else {
        xmlNode *xml = pcmk__output_xml_create_parent(out, PCMK_XE_NODE);

        pcmk__xe_set(xml, PCMK_XA_NAME, node->priv->name);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-attribute", "const char *", "const char *", "bool", "int")
static int
node_attribute_text(pcmk__output_t *out, va_list args) {
    const char *name = va_arg(args, const char *);
    const char *value = va_arg(args, const char *);
    bool add_extra = va_arg(args, int);
    int expected_score = va_arg(args, int);

    if (add_extra) {
        int v;

        if (value == NULL) {
            v = 0;
        } else {
            pcmk__scan_min_int(value, &v, INT_MIN);
        }
        if (v <= 0) {
            out->list_item(out, NULL, "%-32s\t: %-10s\t: Connectivity is lost", name, value);
        } else if (v < expected_score) {
            out->list_item(out, NULL, "%-32s\t: %-10s\t: Connectivity is degraded (Expected=%d)", name, value, expected_score);
        } else {
            out->list_item(out, NULL, "%-32s\t: %-10s", name, value);
        }
    } else {
        out->list_item(out, NULL, "%-32s\t: %-10s", name, value);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-attribute", "const char *", "const char *", "bool", "int")
static int
node_attribute_html(pcmk__output_t *out, va_list args) {
    const char *name = va_arg(args, const char *);
    const char *value = va_arg(args, const char *);
    bool add_extra = va_arg(args, int);
    int expected_score = va_arg(args, int);

    if (add_extra) {
        int v = 0;
        xmlNode *xml = pcmk__output_create_xml_node(out, "li");
        xmlNode *child = NULL;

        if (value != NULL) {
            pcmk__scan_min_int(value, &v, INT_MIN);
        }

        child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL, NULL);
        pcmk__xe_set_content(child, "%s: %s", name, value);

        if (v <= 0) {
            child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL,
                                      PCMK__VALUE_BOLD);
            pcmk__xe_set_content(child, "(connectivity is lost)");

        } else if (v < expected_score) {
            child = pcmk__html_create(xml, PCMK__XE_SPAN, NULL,
                                      PCMK__VALUE_BOLD);
            pcmk__xe_set_content(child,
                                 "(connectivity is degraded -- expected %d)",
                                 expected_score);
        }
    } else {
        out->list_item(out, NULL, "%s: %s", name, value);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-and-op", "pcmk_scheduler_t *", "xmlNode *")
static int
node_and_op(pcmk__output_t *out, va_list args) {
    pcmk_scheduler_t *scheduler = va_arg(args, pcmk_scheduler_t *);
    xmlNodePtr xml_op = va_arg(args, xmlNodePtr);

    pcmk_resource_t *rsc = NULL;
    gchar *node_str = NULL;
    char *last_change_str = NULL;

    const char *op_rsc = pcmk__xe_get(xml_op, PCMK_XA_RESOURCE);
    int status;
    time_t last_change = 0;

    pcmk__scan_min_int(pcmk__xe_get(xml_op, PCMK__XA_OP_STATUS), &status,
                       PCMK_EXEC_UNKNOWN);

    rsc = pe_find_resource(scheduler->priv->resources, op_rsc);

    if (rsc) {
        const pcmk_node_t *node = pcmk__current_node(rsc);
        const char *target_role = g_hash_table_lookup(rsc->priv->meta,
                                                      PCMK_META_TARGET_ROLE);
        uint32_t show_opts = pcmk_show_rsc_only | pcmk_show_pending;

        if (node == NULL) {
            node = rsc->priv->pending_node;
        }

        node_str = pcmk__native_output_string(rsc, rsc_printable_id(rsc), node,
                                              show_opts, target_role, false);
    } else {
        node_str = pcmk__assert_asprintf("Unknown resource %s", op_rsc);
    }

    if (pcmk__xe_get_time(xml_op, PCMK_XA_LAST_RC_CHANGE,
                          &last_change) == pcmk_rc_ok) {
        const char *exec_time = pcmk__xe_get(xml_op, PCMK_XA_EXEC_TIME);

        last_change_str = pcmk__assert_asprintf(", %s='%s', exec=%sms",
                                                PCMK_XA_LAST_RC_CHANGE,
                                                g_strchomp(ctime(&last_change)),
                                                exec_time);
    }

    out->list_item(out, NULL, "%s: %s (node=%s, call=%s, rc=%s%s): %s",
                   node_str, pcmk__xe_history_key(xml_op),
                   pcmk__xe_get(xml_op, PCMK_XA_UNAME),
                   pcmk__xe_get(xml_op, PCMK__XA_CALL_ID),
                   pcmk__xe_get(xml_op, PCMK__XA_RC_CODE),
                   last_change_str ? last_change_str : "",
                   pcmk_exec_status_str(status));

    g_free(node_str);
    free(last_change_str);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-and-op", "pcmk_scheduler_t *", "xmlNode *")
static int
node_and_op_xml(pcmk__output_t *out, va_list args) {
    pcmk_scheduler_t *scheduler = va_arg(args, pcmk_scheduler_t *);
    xmlNodePtr xml_op = va_arg(args, xmlNodePtr);

    pcmk_resource_t *rsc = NULL;
    const char *uname = pcmk__xe_get(xml_op, PCMK_XA_UNAME);
    const char *call_id = pcmk__xe_get(xml_op, PCMK__XA_CALL_ID);
    const char *rc_s = pcmk__xe_get(xml_op, PCMK__XA_RC_CODE);
    const char *op_rsc = pcmk__xe_get(xml_op, PCMK_XA_RESOURCE);
    int status;
    time_t last_change = 0;
    xmlNode *operation = NULL;

    pcmk__scan_min_int(pcmk__xe_get(xml_op, PCMK__XA_OP_STATUS), &status,
                       PCMK_EXEC_UNKNOWN);

    operation = pcmk__output_create_xml_node(out, PCMK_XE_OPERATION);
    pcmk__xe_set(operation, PCMK_XA_OP, pcmk__xe_history_key(xml_op));
    pcmk__xe_set(operation, PCMK_XA_NODE, uname);
    pcmk__xe_set(operation, PCMK_XA_CALL, call_id);
    pcmk__xe_set(operation, PCMK_XA_RC, rc_s);
    pcmk__xe_set(operation, PCMK_XA_STATUS, pcmk_exec_status_str(status));

    rsc = pe_find_resource(scheduler->priv->resources, op_rsc);

    if (rsc) {
        const char *class = pcmk__xe_get(rsc->priv->xml, PCMK_XA_CLASS);
        const char *provider = pcmk__xe_get(rsc->priv->xml, PCMK_XA_PROVIDER);
        const char *kind = pcmk__xe_get(rsc->priv->xml, PCMK_XA_TYPE);
        bool has_provider = pcmk__is_set(pcmk_get_ra_caps(class),
                                         pcmk_ra_cap_provider);

        char *agent_tuple = pcmk__assert_asprintf("%s:%s:%s",
                                                  class,
                                                  (has_provider? provider : ""),
                                                  kind);

        pcmk__xe_set(operation, PCMK_XA_RSC, rsc_printable_id(rsc));
        pcmk__xe_set(operation, PCMK_XA_AGENT, agent_tuple);

        free(agent_tuple);
    }

    if (pcmk__xe_get_time(xml_op, PCMK_XA_LAST_RC_CHANGE,
                          &last_change) == pcmk_rc_ok) {
        const char *last_rc_change = g_strchomp(ctime(&last_change));
        const char *exec_time = pcmk__xe_get(xml_op, PCMK_XA_EXEC_TIME);

        pcmk__xe_set(operation, PCMK_XA_LAST_RC_CHANGE, last_rc_change);
        pcmk__xe_set(operation, PCMK_XA_EXEC_TIME, exec_time);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-attribute", "const char *", "const char *", "bool", "int")
static int
node_attribute_xml(pcmk__output_t *out, va_list args) {
    const char *name = va_arg(args, const char *);
    const char *value = va_arg(args, const char *);
    bool add_extra = va_arg(args, int);
    int expected_score = va_arg(args, int);

    xmlNode *xml = pcmk__output_create_xml_node(out, PCMK_XE_ATTRIBUTE);
    pcmk__xe_set(xml, PCMK_XA_NAME, name);
    pcmk__xe_set(xml, PCMK_XA_VALUE, value);

    if (add_extra) {
        pcmk__xe_set_int(xml, PCMK_XA_EXPECTED, expected_score);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-attribute-list", "pcmk_scheduler_t *", "uint32_t",
                  "bool", "GList *", "GList *")
static int
node_attribute_list(pcmk__output_t *out, va_list args) {
    pcmk_scheduler_t *scheduler = va_arg(args, pcmk_scheduler_t *);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool print_spacer = va_arg(args, int);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    int rc = pcmk_rc_no_output;

    /* Display each node's attributes */
    for (GList *gIter = scheduler->nodes; gIter != NULL; gIter = gIter->next) {
        pcmk_node_t *node = gIter->data;

        GList *attr_list = NULL;
        GHashTableIter iter;
        gpointer key;

        if (!node || !node->details || !node->details->online) {
            continue;
        }

        // @TODO Maybe skip filtering for XML output
        g_hash_table_iter_init(&iter, node->priv->attrs);
        while (g_hash_table_iter_next (&iter, &key, NULL)) {
            attr_list = filter_attr_list(attr_list, key);
        }

        if (attr_list == NULL) {
            continue;
        }

        if (!pcmk__str_in_list(node->priv->name, only_node,
                               pcmk__str_star_matches|pcmk__str_casei)) {
            g_list_free(attr_list);
            continue;
        }

        PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Node Attributes");

        out->message(out, "node", node, show_opts, false, only_node, only_rsc);

        for (GList *aIter = attr_list; aIter != NULL; aIter = aIter->next) {
            const char *name = aIter->data;
            const char *value = NULL;
            int expected_score = 0;
            bool add_extra = false;

            value = pcmk__node_attr(node, name, NULL, pcmk__rsc_node_current);

            add_extra = add_extra_info(node, node->details->running_rsc,
                                       scheduler, name, &expected_score);

            /* Print attribute name and value */
            out->message(out, "node-attribute", name, value, add_extra,
                         expected_score);
        }

        g_list_free(attr_list);
        out->end_list(out);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("node-capacity", "const pcmk_node_t *", "const char *")
static int
node_capacity(pcmk__output_t *out, va_list args)
{
    const pcmk_node_t *node = va_arg(args, pcmk_node_t *);
    const char *comment = va_arg(args, const char *);

    char *dump_text = pcmk__assert_asprintf("%s: %s capacity:",
                                            comment, pcmk__node_name(node));

    g_hash_table_foreach(node->priv->utilization, append_dump_text,
                         &dump_text);
    out->list_item(out, NULL, "%s", dump_text);
    free(dump_text);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-capacity", "const pcmk_node_t *", "const char *")
static int
node_capacity_xml(pcmk__output_t *out, va_list args)
{
    const pcmk_node_t *node = va_arg(args, pcmk_node_t *);
    const char *uname = node->priv->name;
    const char *comment = va_arg(args, const char *);

    xmlNode *xml = pcmk__output_create_xml_node(out, PCMK_XE_CAPACITY);

    pcmk__xe_set(xml, PCMK_XA_NODE, uname);
    pcmk__xe_set(xml, PCMK_XA_COMMENT, comment);

    g_hash_table_foreach(node->priv->utilization, add_dump_node, xml);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-history-list", "pcmk_scheduler_t *", "pcmk_node_t *",
                  "xmlNode *", "GList *", "GList *", "uint32_t", "uint32_t")
static int
node_history_list(pcmk__output_t *out, va_list args) {
    pcmk_scheduler_t *scheduler = va_arg(args, pcmk_scheduler_t *);
    pcmk_node_t *node = va_arg(args, pcmk_node_t *);
    xmlNode *node_state = va_arg(args, xmlNode *);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);

    xmlNode *lrm_rsc = NULL;
    xmlNode *rsc_entry = NULL;
    int rc = pcmk_rc_no_output;

    lrm_rsc = pcmk__xe_first_child(node_state, PCMK__XE_LRM, NULL, NULL);
    lrm_rsc = pcmk__xe_first_child(lrm_rsc, PCMK__XE_LRM_RESOURCES, NULL, NULL);

    /* Print history of each of the node's resources */
    for (rsc_entry = pcmk__xe_first_child(lrm_rsc, PCMK__XE_LRM_RESOURCE, NULL,
                                          NULL);
         rsc_entry != NULL;
         rsc_entry = pcmk__xe_next(rsc_entry, PCMK__XE_LRM_RESOURCE)) {

        const char *rsc_id = pcmk__xe_get(rsc_entry, PCMK_XA_ID);
        pcmk_resource_t *rsc = NULL;
        const pcmk_resource_t *parent = NULL;

        if (rsc_id == NULL) {
            continue; // Malformed entry
        }

        rsc = pe_find_resource(scheduler->priv->resources, rsc_id);
        if (rsc == NULL) {
            continue; // Resource was removed from configuration
        }

        /* We can't use is_filtered here to filter group resources.  For is_filtered,
         * we have to decide whether to check the parent or not.  If we check the
         * parent, all elements of a group will always be printed because that's how
         * is_filtered works for groups.  If we do not check the parent, sometimes
         * this will filter everything out.
         *
         * For other resource types, is_filtered is okay.
         */
        parent = pe__const_top_resource(rsc, false);
        if (pcmk__is_group(parent)) {
            if (!pcmk__str_in_list(rsc_printable_id(rsc), only_rsc,
                                   pcmk__str_star_matches)
                && !pcmk__str_in_list(rsc_printable_id(parent), only_rsc,
                                      pcmk__str_star_matches)) {
                continue;
            }
        } else if (rsc->priv->fns->is_filtered(rsc, only_rsc, true)) {
            continue;
        }

        if (!pcmk__is_set(section_opts, pcmk_section_operations)) {
            time_t last_failure = 0;
            int failcount = pe_get_failcount(node, rsc, &last_failure,
                                             pcmk__fc_default, NULL);

            if (failcount <= 0) {
                continue;
            }

            if (rc == pcmk_rc_no_output) {
                rc = pcmk_rc_ok;
                out->message(out, "node", node, show_opts, false, only_node,
                             only_rsc);
            }

            out->message(out, "resource-history", rsc, rsc_id, false,
                         failcount, last_failure, false);
        } else {
            GList *op_list = get_operation_list(rsc_entry);
            pcmk_resource_t *rsc = NULL;

            if (op_list == NULL) {
                continue;
            }

            rsc = pe_find_resource(scheduler->priv->resources,
                                   pcmk__xe_get(rsc_entry, PCMK_XA_ID));

            if (rc == pcmk_rc_no_output) {
                rc = pcmk_rc_ok;
                out->message(out, "node", node, show_opts, false, only_node,
                             only_rsc);
            }

            out->message(out, "resource-operation-list", scheduler, rsc, node,
                         op_list, show_opts);
        }
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("node-list", "GList *", "GList *", "GList *", "uint32_t", "bool")
static int
node_list_html(pcmk__output_t *out, va_list args) {
    GList *nodes = va_arg(args, GList *);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool print_spacer G_GNUC_UNUSED = va_arg(args, int);

    int rc = pcmk_rc_no_output;

    for (GList *gIter = nodes; gIter != NULL; gIter = gIter->next) {
        pcmk_node_t *node = (pcmk_node_t *) gIter->data;

        if (!pcmk__str_in_list(node->priv->name, only_node,
                               pcmk__str_star_matches|pcmk__str_casei)) {
            continue;
        }

        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Node List");

        out->message(out, "node", node, show_opts, true, only_node, only_rsc);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("node-list", "GList *", "GList *", "GList *", "uint32_t", "bool")
static int
node_list_text(pcmk__output_t *out, va_list args) {
    GList *nodes = va_arg(args, GList *);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool print_spacer = va_arg(args, int);

    /* space-separated lists of node names */
    GString *online_nodes = NULL;
    GString *online_remote_nodes = NULL;
    GString *online_guest_nodes = NULL;
    GString *offline_nodes = NULL;
    GString *offline_remote_nodes = NULL;

    int rc = pcmk_rc_no_output;

    for (GList *gIter = nodes; gIter != NULL; gIter = gIter->next) {
        pcmk_node_t *node = (pcmk_node_t *) gIter->data;
        char *node_name =
            pe__node_display_name(node,
                                  pcmk__is_set(show_opts, pcmk_show_node_id));

        if (!pcmk__str_in_list(node->priv->name, only_node,
                               pcmk__str_star_matches|pcmk__str_casei)) {
            free(node_name);
            continue;
        }

        PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Node List");

        // Determine whether to display node individually or in a list
        if (node->details->unclean || node->details->pending
            || (pcmk__is_set(node->priv->flags, pcmk__node_fail_standby)
                && node->details->online)
            || pcmk__is_set(node->priv->flags, pcmk__node_standby)
            || node->details->maintenance
            || pcmk__is_set(show_opts, pcmk_show_rscs_by_node)
            || pcmk__is_set(show_opts, pcmk_show_feature_set)
            || (pe__node_health(node) <= 0)) {
            // Display node individually

        } else if (node->details->online) {
            // Display online node in a list
            if (pcmk__is_guest_or_bundle_node(node)) {
                pcmk__add_word(&online_guest_nodes, 1024, node_name);

            } else if (pcmk__is_remote_node(node)) {
                pcmk__add_word(&online_remote_nodes, 1024, node_name);

            } else {
                pcmk__add_word(&online_nodes, 1024, node_name);
            }
            free(node_name);
            continue;

        } else {
            // Display offline node in a list
            if (pcmk__is_remote_node(node)) {
                pcmk__add_word(&offline_remote_nodes, 1024, node_name);

            } else if (pcmk__is_guest_or_bundle_node(node)) {
                /* ignore offline guest nodes */

            } else {
                pcmk__add_word(&offline_nodes, 1024, node_name);
            }
            free(node_name);
            continue;
        }

        /* If we get here, node is in bad state, or we're grouping by node */
        out->message(out, "node", node, show_opts, true, only_node, only_rsc);
        free(node_name);
    }

    /* If we're not grouping by node, summarize nodes by status */
    if (online_nodes != NULL) {
        out->list_item(out, "Online", "[ %s ]",
                       (const char *) online_nodes->str);
        g_string_free(online_nodes, TRUE);
    }
    if (offline_nodes != NULL) {
        out->list_item(out, "OFFLINE", "[ %s ]",
                       (const char *) offline_nodes->str);
        g_string_free(offline_nodes, TRUE);
    }
    if (online_remote_nodes) {
        out->list_item(out, "RemoteOnline", "[ %s ]",
                       (const char *) online_remote_nodes->str);
        g_string_free(online_remote_nodes, TRUE);
    }
    if (offline_remote_nodes) {
        out->list_item(out, "RemoteOFFLINE", "[ %s ]",
                       (const char *) offline_remote_nodes->str);
        g_string_free(offline_remote_nodes, TRUE);
    }
    if (online_guest_nodes != NULL) {
        out->list_item(out, "GuestOnline", "[ %s ]",
                       (const char *) online_guest_nodes->str);
        g_string_free(online_guest_nodes, TRUE);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("node-list", "GList *", "GList *", "GList *", "uint32_t", "bool")
static int
node_list_xml(pcmk__output_t *out, va_list args) {
    GList *nodes = va_arg(args, GList *);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool print_spacer G_GNUC_UNUSED = va_arg(args, int);

    /* PCMK_XE_NODES acts as the list's element name for CLI tools that use
     * pcmk__output_enable_list_element.  Otherwise PCMK_XE_NODES is the
     * value of the list's PCMK_XA_NAME attribute.
     */
    out->begin_list(out, NULL, NULL, PCMK_XE_NODES);
    for (GList *gIter = nodes; gIter != NULL; gIter = gIter->next) {
        pcmk_node_t *node = (pcmk_node_t *) gIter->data;

        if (!pcmk__str_in_list(node->priv->name, only_node,
                               pcmk__str_star_matches|pcmk__str_casei)) {
            continue;
        }

        out->message(out, "node", node, show_opts, true, only_node, only_rsc);
    }
    out->end_list(out);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-summary", "pcmk_scheduler_t *", "GList *", "GList *",
                  "uint32_t", "uint32_t", "bool")
static int
node_summary(pcmk__output_t *out, va_list args) {
    pcmk_scheduler_t *scheduler = va_arg(args, pcmk_scheduler_t *);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool print_spacer = va_arg(args, int);

    xmlNode *node_state = NULL;
    xmlNode *cib_status = pcmk_find_cib_element(scheduler->input,
                                                PCMK_XE_STATUS);
    int rc = pcmk_rc_no_output;

    if (xmlChildElementCount(cib_status) == 0) {
        return rc;
    }

    for (node_state = pcmk__xe_first_child(cib_status, PCMK__XE_NODE_STATE,
                                           NULL, NULL);
         node_state != NULL;
         node_state = pcmk__xe_next(node_state, PCMK__XE_NODE_STATE)) {

        pcmk_node_t *node = pe_find_node_id(scheduler->nodes,
                                            pcmk__xe_id(node_state));
        const bool operations = pcmk__is_set(section_opts,
                                             pcmk_section_operations);

        if (!node || !node->details || !node->details->online) {
            continue;
        }

        if (!pcmk__str_in_list(node->priv->name, only_node,
                               pcmk__str_star_matches|pcmk__str_casei)) {
            continue;
        }

        if (operations) {
            PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Operations");
        } else {
            PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc,
                                     "Migration Summary");
        }

        out->message(out, "node-history-list", scheduler, node, node_state,
                     only_node, only_rsc, section_opts, show_opts);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("node-weight", "const pcmk_resource_t *", "const char *",
                  "const char *", "const char *")
static int
node_weight(pcmk__output_t *out, va_list args)
{
    const pcmk_resource_t *rsc = va_arg(args, const pcmk_resource_t *);
    const char *prefix = va_arg(args, const char *);
    const char *uname = va_arg(args, const char *);
    const char *score = va_arg(args, const char *);

    if (rsc) {
        out->list_item(out, NULL, "%s: %s allocation score on %s: %s",
                       prefix, rsc->id, uname, score);
    } else {
        out->list_item(out, NULL, "%s: %s = %s", prefix, uname, score);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-weight", "const pcmk_resource_t *", "const char *",
                  "const char *", "const char *")
static int
node_weight_xml(pcmk__output_t *out, va_list args)
{
    const pcmk_resource_t *rsc = va_arg(args, const pcmk_resource_t *);
    const char *prefix = va_arg(args, const char *);
    const char *uname = va_arg(args, const char *);
    const char *score = va_arg(args, const char *);

    xmlNode *xml = pcmk__output_create_xml_node(out, PCMK_XE_NODE_WEIGHT);

    pcmk__xe_set(xml, PCMK_XA_FUNCTION, prefix);
    pcmk__xe_set(xml, PCMK_XA_NODE, uname);
    pcmk__xe_set(xml, PCMK_XA_SCORE, score);

    if (rsc != NULL) {
        pcmk__xe_set(xml, PCMK_XA_ID, rsc->id);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("op-history", "xmlNode *", "const char *", "const char *", "int", "uint32_t")
static int
op_history_text(pcmk__output_t *out, va_list args) {
    xmlNodePtr xml_op = va_arg(args, xmlNodePtr);
    const char *task = va_arg(args, const char *);
    const char *interval_ms_s = va_arg(args, const char *);
    int rc = va_arg(args, int);
    uint32_t show_opts = va_arg(args, uint32_t);

    char *buf = op_history_string(xml_op, task, interval_ms_s, rc,
                                  pcmk__is_set(show_opts, pcmk_show_timing));

    out->list_item(out, NULL, "%s", buf);

    free(buf);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("op-history", "xmlNode *", "const char *", "const char *", "int", "uint32_t")
static int
op_history_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr xml_op = va_arg(args, xmlNodePtr);
    const char *task = va_arg(args, const char *);
    const char *interval_ms_s = va_arg(args, const char *);
    int rc = va_arg(args, int);
    uint32_t show_opts = va_arg(args, uint32_t);

    const char *call_id = pcmk__xe_get(xml_op, PCMK__XA_CALL_ID);

    xmlNode *history = pcmk__output_create_xml_node(out,
                                                    PCMK_XE_OPERATION_HISTORY);
    pcmk__xe_set(history, PCMK_XA_CALL, call_id);
    pcmk__xe_set(history, PCMK_XA_TASK, task);
    pcmk__xe_set_int(history, PCMK_XA_RC, rc);
    pcmk__xe_set(history, PCMK_XA_RC_TEXT, crm_exit_str(rc));

    if (interval_ms_s && !pcmk__str_eq(interval_ms_s, "0", pcmk__str_casei)) {
        char *s = pcmk__assert_asprintf("%sms", interval_ms_s);

        pcmk__xe_set(history, PCMK_XA_INTERVAL, s);
        free(s);
    }

    if (pcmk__is_set(show_opts, pcmk_show_timing)) {
        const char *value = NULL;
        time_t epoch = 0;

        pcmk__xe_get_time(xml_op, PCMK_XA_LAST_RC_CHANGE, &epoch);
        if (epoch > 0) {
            char *s = pcmk__epoch2str(&epoch, 0);

            pcmk__xe_set(history, PCMK_XA_LAST_RC_CHANGE, s);
            free(s);
        }

        value = pcmk__xe_get(xml_op, PCMK_XA_EXEC_TIME);
        if (value) {
            char *s = pcmk__assert_asprintf("%sms", value);

            pcmk__xe_set(history, PCMK_XA_EXEC_TIME, s);
            free(s);
        }
        value = pcmk__xe_get(xml_op, PCMK_XA_QUEUE_TIME);
        if (value) {
            char *s = pcmk__assert_asprintf("%sms", value);

            pcmk__xe_set(history, PCMK_XA_QUEUE_TIME, s);
            free(s);
        }
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("promotion-score", "pcmk_resource_t *", "pcmk_node_t *",
                  "const char *")
static int
promotion_score(pcmk__output_t *out, va_list args)
{
    pcmk_resource_t *child_rsc = va_arg(args, pcmk_resource_t *);
    pcmk_node_t *chosen = va_arg(args, pcmk_node_t *);
    const char *score = va_arg(args, const char *);

    if (chosen == NULL) {
        out->list_item(out, NULL, "%s promotion score (inactive): %s",
                       child_rsc->id, score);
    } else {
        out->list_item(out, NULL, "%s promotion score on %s: %s",
                       child_rsc->id, pcmk__node_name(chosen), score);
    }
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("promotion-score", "pcmk_resource_t *", "pcmk_node_t *",
                  "const char *")
static int
promotion_score_xml(pcmk__output_t *out, va_list args)
{
    pcmk_resource_t *child_rsc = va_arg(args, pcmk_resource_t *);
    pcmk_node_t *chosen = va_arg(args, pcmk_node_t *);
    const char *score = va_arg(args, const char *);

    xmlNode *xml = pcmk__output_create_xml_node(out, PCMK_XE_PROMOTION_SCORE);

    pcmk__xe_set(xml, PCMK_XA_ID, child_rsc->id);
    pcmk__xe_set(xml, PCMK_XA_SCORE, score);

    if (chosen != NULL) {
        pcmk__xe_set(xml, PCMK_XA_NODE, chosen->priv->name);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("resource-config", "const pcmk_resource_t *", "bool")
static int
resource_config(pcmk__output_t *out, va_list args) {
    const pcmk_resource_t *rsc = va_arg(args, const pcmk_resource_t *);
    GString *xml_buf = g_string_sized_new(1024);
    bool raw = va_arg(args, int);

    formatted_xml_buf(rsc, xml_buf, raw);

    out->output_xml(out, PCMK_XE_XML, xml_buf->str);

    g_string_free(xml_buf, TRUE);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("resource-config", "const pcmk_resource_t *", "bool")
static int
resource_config_text(pcmk__output_t *out, va_list args) {
    pcmk__formatted_printf(out, "Resource XML:\n");
    return resource_config(out, args);
}

PCMK__OUTPUT_ARGS("resource-history", "pcmk_resource_t *", "const char *",
                  "bool", "int", "time_t", "bool")
static int
resource_history_text(pcmk__output_t *out, va_list args) {
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    const char *rsc_id = va_arg(args, const char *);
    bool all = va_arg(args, int);
    int failcount = va_arg(args, int);
    time_t last_failure = va_arg(args, time_t);
    bool as_header = va_arg(args, int);

    char *buf = resource_history_string(rsc, rsc_id, all, failcount, last_failure);

    if (as_header) {
        out->begin_list(out, NULL, NULL, "%s", buf);
    } else {
        out->list_item(out, NULL, "%s", buf);
    }

    free(buf);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("resource-history", "pcmk_resource_t *", "const char *",
                  "bool", "int", "time_t", "bool")
static int
resource_history_xml(pcmk__output_t *out, va_list args) {
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    const char *rsc_id = va_arg(args, const char *);
    bool all = va_arg(args, int);
    int failcount = va_arg(args, int);
    time_t last_failure = va_arg(args, time_t);
    bool as_header = va_arg(args, int);
    xmlNode *xml = NULL;

    xml = pcmk__output_xml_create_parent(out, PCMK_XE_RESOURCE_HISTORY);
    pcmk__xe_set(xml, PCMK_XA_ID, rsc_id);

    // @COMPAT PCMK_XA_ORPHAN is deprecated since 3.0.2
    if (rsc == NULL) {
        pcmk__xe_set_bool(xml, PCMK_XA_ORPHAN, true);
        pcmk__xe_set_bool(xml, PCMK_XA_REMOVED, true);

    } else if (all || failcount || last_failure > 0) {
        pcmk__xe_set(xml, PCMK_XA_ORPHAN, PCMK_VALUE_FALSE);
        pcmk__xe_set(xml, PCMK_XA_REMOVED, PCMK_VALUE_FALSE);
        pcmk__xe_set_int(xml, PCMK_META_MIGRATION_THRESHOLD,
                         rsc->priv->ban_after_failures);

        if (failcount > 0) {
            pcmk__xe_set_int(xml, PCMK_XA_FAIL_COUNT, failcount);
        }

        if (last_failure > 0) {
            char *s = pcmk__epoch2str(&last_failure, 0);

            pcmk__xe_set(xml, PCMK_XA_LAST_FAILURE, s);
            free(s);
        }
    }

    if (!as_header) {
        pcmk__output_xml_pop_parent(out);
    }

    return pcmk_rc_ok;
}

static void
print_resource_header(pcmk__output_t *out, uint32_t show_opts)
{
    if (pcmk__is_set(show_opts, pcmk_show_rscs_by_node)) {
        /* Active resources have already been printed by node */
        out->begin_list(out, NULL, NULL, "Inactive Resources");
    } else if (pcmk__is_set(show_opts, pcmk_show_inactive_rscs)) {
        out->begin_list(out, NULL, NULL, "Full List of Resources");
    } else {
        out->begin_list(out, NULL, NULL, "Active Resources");
    }
}


PCMK__OUTPUT_ARGS("resource-list", "pcmk_scheduler_t *", "uint32_t", "bool",
                  "GList *", "GList *", "bool")
static int
resource_list(pcmk__output_t *out, va_list args)
{
    pcmk_scheduler_t *scheduler = va_arg(args, pcmk_scheduler_t *);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool print_summary = va_arg(args, int);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);
    bool print_spacer = va_arg(args, int);

    GList *rsc_iter;
    int rc = pcmk_rc_no_output;
    bool printed_header = false;

    /* If we already showed active resources by node, and
     * we're not showing inactive resources, we have nothing to do
     */
    if (pcmk__is_set(show_opts, pcmk_show_rscs_by_node)
        && !pcmk__is_set(show_opts, pcmk_show_inactive_rscs)) {
        return rc;
    }

    /* If we haven't already printed resources grouped by node,
     * and brief output was requested, print resource summary */
    if (pcmk__is_set(show_opts, pcmk_show_brief)
        && !pcmk__is_set(show_opts, pcmk_show_rscs_by_node)) {
        GList *rscs = pe__filter_rsc_list(scheduler->priv->resources, only_rsc);

        PCMK__OUTPUT_SPACER_IF(out, print_spacer);
        print_resource_header(out, show_opts);
        printed_header = true;

        rc = pe__rscs_brief_output(out, rscs, show_opts);
        g_list_free(rscs);
    }

    /* For each resource, display it if appropriate */
    for (rsc_iter = scheduler->priv->resources;
         rsc_iter != NULL; rsc_iter = rsc_iter->next) {

        pcmk_resource_t *rsc = (pcmk_resource_t *) rsc_iter->data;
        int x;

        /* Complex resources may have some sub-resources active and some inactive */
        bool is_active = rsc->priv->fns->active(rsc, true);
        bool partially_active = rsc->priv->fns->active(rsc, false);

        // Skip inactive removed resources (deleted but still in CIB)
        if (pcmk__is_set(rsc->flags, pcmk__rsc_removed) && !is_active) {
            continue;
        }

        /* Skip active resources if we already displayed them by node */
        if (pcmk__is_set(show_opts, pcmk_show_rscs_by_node)) {
            if (is_active) {
                continue;
            }

        /* Skip primitives already counted in a brief summary */
        } else if (pcmk__is_set(show_opts, pcmk_show_brief)
                   && pcmk__is_primitive(rsc)) {
            continue;

        /* Skip resources that aren't at least partially active,
         * unless we're displaying inactive resources
         */
        } else if (!partially_active
                   && !pcmk__is_set(show_opts, pcmk_show_inactive_rscs)) {
            continue;

        } else if (partially_active && !pe__rsc_running_on_any(rsc, only_node)) {
            continue;
        }

        if (!printed_header) {
            PCMK__OUTPUT_SPACER_IF(out, print_spacer);
            print_resource_header(out, show_opts);
            printed_header = true;
        }

        /* Print this resource */
        x = out->message(out, (const char *) rsc->priv->xml->name,
                         show_opts, rsc, only_node, only_rsc);
        if (x == pcmk_rc_ok) {
            rc = pcmk_rc_ok;
        }
    }

    if (print_summary && rc != pcmk_rc_ok) {
        if (!printed_header) {
            PCMK__OUTPUT_SPACER_IF(out, print_spacer);
            print_resource_header(out, show_opts);
            printed_header = true;
        }

        /* @FIXME It looks as if we can return pcmk_rc_no_output even after
         * writing output here.
         */
        if (pcmk__is_set(show_opts, pcmk_show_rscs_by_node)) {
            out->list_item(out, NULL, "No inactive resources");
        } else if (pcmk__is_set(show_opts, pcmk_show_inactive_rscs)) {
            out->list_item(out, NULL, "No resources");
        } else {
            out->list_item(out, NULL, "No active resources");
        }
    }

    if (printed_header) {
        out->end_list(out);
    }

    return rc;
}

PCMK__OUTPUT_ARGS("resource-operation-list", "pcmk_scheduler_t *",
                  "pcmk_resource_t *", "pcmk_node_t *", "GList *", "uint32_t")
static int
resource_operation_list(pcmk__output_t *out, va_list args)
{
    pcmk_scheduler_t *scheduler G_GNUC_UNUSED = va_arg(args,
                                                       pcmk_scheduler_t *);
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    pcmk_node_t *node = va_arg(args, pcmk_node_t *);
    GList *op_list = va_arg(args, GList *);
    uint32_t show_opts = va_arg(args, uint32_t);

    GList *gIter = NULL;
    int rc = pcmk_rc_no_output;

    /* Print each operation */
    for (gIter = op_list; gIter != NULL; gIter = gIter->next) {
        xmlNode *xml_op = (xmlNode *) gIter->data;
        const char *task = pcmk__xe_get(xml_op, PCMK_XA_OPERATION);
        const char *interval_ms_s = pcmk__xe_get(xml_op, PCMK_META_INTERVAL);
        const char *op_rc = pcmk__xe_get(xml_op, PCMK__XA_RC_CODE);
        int op_rc_i;

        pcmk__scan_min_int(op_rc, &op_rc_i, 0);

        /* Display 0-interval monitors as "probe" */
        if (pcmk__str_eq(task, PCMK_ACTION_MONITOR, pcmk__str_casei)
            && pcmk__str_eq(interval_ms_s, "0", pcmk__str_null_matches | pcmk__str_casei)) {
            task = "probe";
        }

        /* If this is the first printed operation, print heading for resource */
        if (rc == pcmk_rc_no_output) {
            time_t last_failure = 0;
            int failcount = pe_get_failcount(node, rsc, &last_failure,
                                             pcmk__fc_default, NULL);

            out->message(out, "resource-history", rsc, rsc_printable_id(rsc), true,
                         failcount, last_failure, true);
            rc = pcmk_rc_ok;
        }

        /* Print the operation */
        out->message(out, "op-history", xml_op, task, interval_ms_s,
                     op_rc_i, show_opts);
    }

    /* Free the list we created (no need to free the individual items) */
    g_list_free(op_list);

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("resource-util", "pcmk_resource_t *", "pcmk_node_t *",
                  "const char *")
static int
resource_util(pcmk__output_t *out, va_list args)
{
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    pcmk_node_t *node = va_arg(args, pcmk_node_t *);
    const char *fn = va_arg(args, const char *);

    char *dump_text = pcmk__assert_asprintf("%s: %s utilization on %s:",
                                            fn, rsc->id, pcmk__node_name(node));

    g_hash_table_foreach(rsc->priv->utilization, append_dump_text,
                         &dump_text);
    out->list_item(out, NULL, "%s", dump_text);
    free(dump_text);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("resource-util", "pcmk_resource_t *", "pcmk_node_t *",
                  "const char *")
static int
resource_util_xml(pcmk__output_t *out, va_list args)
{
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    pcmk_node_t *node = va_arg(args, pcmk_node_t *);
    const char *uname = node->priv->name;
    const char *fn = va_arg(args, const char *);

    xmlNode *xml = pcmk__output_create_xml_node(out, PCMK_XE_UTILIZATION);

    pcmk__xe_set(xml, PCMK_XA_RESOURCE, rsc->id);
    pcmk__xe_set(xml, PCMK_XA_NODE, uname);
    pcmk__xe_set(xml, PCMK_XA_FUNCTION, fn);

    g_hash_table_foreach(rsc->priv->utilization, add_dump_node, xml);

    return pcmk_rc_ok;
}

static inline const char *
ticket_status(pcmk__ticket_t *ticket)
{
    if (pcmk__is_set(ticket->flags, pcmk__ticket_granted)) {
        return PCMK_VALUE_GRANTED;
    }
    return PCMK_VALUE_REVOKED;
}

static inline const char *
ticket_standby_text(pcmk__ticket_t *ticket)
{
    return pcmk__is_set(ticket->flags, pcmk__ticket_standby)? " [standby]" : "";
}

PCMK__OUTPUT_ARGS("ticket", "pcmk__ticket_t *", "bool", "bool")
static int
ticket_default(pcmk__output_t *out, va_list args) {
    pcmk__ticket_t *ticket = va_arg(args, pcmk__ticket_t *);
    bool raw = va_arg(args, int);
    bool details = va_arg(args, int);

    GString *detail_str = NULL;

    if (raw) {
        out->list_item(out, ticket->id, "%s", ticket->id);
        return pcmk_rc_ok;
    }

    if (details && g_hash_table_size(ticket->state) > 0) {
        GHashTableIter iter;
        const char *name = NULL;
        const char *value = NULL;
        bool already_added = false;

        detail_str = g_string_sized_new(100);
        pcmk__g_strcat(detail_str, "\t(", NULL);

        g_hash_table_iter_init(&iter, ticket->state);
        while (g_hash_table_iter_next(&iter, (void **) &name, (void **) &value)) {
            if (already_added) {
                g_string_append_printf(detail_str, ", %s=", name);
            } else {
                g_string_append_printf(detail_str, "%s=", name);
                already_added = true;
            }

            if (pcmk__str_any_of(name, PCMK_XA_LAST_GRANTED, "expires", NULL)) {
                char *epoch_str = NULL;
                long long time_ll;

                (void) pcmk__scan_ll(value, &time_ll, 0);
                epoch_str = pcmk__epoch2str((const time_t *) &time_ll, 0);
                pcmk__g_strcat(detail_str, epoch_str, NULL);
                free(epoch_str);
            } else {
                pcmk__g_strcat(detail_str, value, NULL);
            }
        }

        pcmk__g_strcat(detail_str, ")", NULL);
    }

    if (ticket->last_granted > -1) {
        /* Prior to the introduction of the details & raw arguments to this
         * function, last-granted would always be added in this block.  We need
         * to preserve that behavior.  At the same time, we also need to preserve
         * the existing behavior from crm_ticket, which would include last-granted
         * as part of the (...) detail string.
         *
         * Luckily we can check detail_str - if it's NULL, either there were no
         * details, or we are preserving the previous behavior of this function.
         * If it's not NULL, we are either preserving the previous behavior of
         * crm_ticket or we were given details=true as an argument.
         */
        if (detail_str == NULL) {
            char *epoch_str = pcmk__epoch2str(&(ticket->last_granted), 0);

            out->list_item(out, NULL, "%s\t%s%s last-granted=\"%s\"",
                           ticket->id, ticket_status(ticket),
                           ticket_standby_text(ticket), pcmk__s(epoch_str, ""));
            free(epoch_str);
        } else {
            out->list_item(out, NULL, "%s\t%s%s %s",
                           ticket->id, ticket_status(ticket),
                           ticket_standby_text(ticket), detail_str->str);
        }
    } else {
        out->list_item(out, NULL, "%s\t%s%s%s", ticket->id,
                       ticket_status(ticket),
                       ticket_standby_text(ticket),
                       detail_str != NULL ? detail_str->str : "");
    }

    if (detail_str != NULL) {
        g_string_free(detail_str, TRUE);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ticket", "pcmk__ticket_t *", "bool", "bool")
static int
ticket_xml(pcmk__output_t *out, va_list args) {
    pcmk__ticket_t *ticket = va_arg(args, pcmk__ticket_t *);
    bool raw G_GNUC_UNUSED = va_arg(args, int);
    bool details G_GNUC_UNUSED = va_arg(args, int);

    const char *standby = pcmk__flag_text(ticket->flags, pcmk__ticket_standby);

    xmlNode *xml = NULL;
    GHashTableIter iter;
    const char *name = NULL;
    const char *value = NULL;

    xml = pcmk__output_create_xml_node(out, PCMK_XE_TICKET);
    pcmk__xe_set(xml, PCMK_XA_ID, ticket->id);
    pcmk__xe_set(xml, PCMK_XA_STATUS, ticket_status(ticket));
    pcmk__xe_set(xml, PCMK_XA_STANDBY, standby);

    if (ticket->last_granted > -1) {
        char *buf = pcmk__epoch2str(&ticket->last_granted, 0);

        pcmk__xe_set(xml, PCMK_XA_LAST_GRANTED, buf);
        free(buf);
    }

    g_hash_table_iter_init(&iter, ticket->state);
    while (g_hash_table_iter_next(&iter, (void **) &name, (void **) &value)) {
        /* PCMK_XA_LAST_GRANTED and "expires" are already added by the check
         * for ticket->last_granted above.
         */
        if (pcmk__str_any_of(name, PCMK_XA_LAST_GRANTED, PCMK_XA_EXPIRES,
                             NULL)) {
            continue;
        }

        pcmk__xe_set(xml, name, value);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ticket-list", "GHashTable *", "bool", "bool", "bool")
static int
ticket_list(pcmk__output_t *out, va_list args) {
    GHashTable *tickets = va_arg(args, GHashTable *);
    bool print_spacer = va_arg(args, int);
    bool raw = va_arg(args, int);
    bool details = va_arg(args, int);

    GHashTableIter iter;
    gpointer value;

    if (g_hash_table_size(tickets) == 0) {
        return pcmk_rc_no_output;
    }

    PCMK__OUTPUT_SPACER_IF(out, print_spacer);

    /* Print section heading */
    out->begin_list(out, NULL, NULL, "Tickets");

    /* Print each ticket */
    g_hash_table_iter_init(&iter, tickets);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        pcmk__ticket_t *ticket = (pcmk__ticket_t *) value;
        out->message(out, "ticket", ticket, raw, details);
    }

    /* Close section */
    out->end_list(out);
    return pcmk_rc_ok;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "ban", "default", ban_text },
    { "ban", "html", ban_html },
    { "ban", "xml", ban_xml },
    { "ban-list", "default", ban_list },
    { "bundle", "default", pe__bundle_text },
    { "bundle", "xml",  pe__bundle_xml },
    { "bundle", "html",  pe__bundle_html },
    { "clone", "default", pe__clone_default },
    { "clone", "xml",  pe__clone_xml },
    { "cluster-counts", "default", cluster_counts_text },
    { "cluster-counts", "html", cluster_counts_html },
    { "cluster-counts", "xml", cluster_counts_xml },
    { "cluster-dc", "default", cluster_dc_text },
    { "cluster-dc", "html", cluster_dc_html },
    { "cluster-dc", "xml", cluster_dc_xml },
    { "cluster-options", "default", cluster_options_text },
    { "cluster-options", "html", cluster_options_html },
    { "cluster-options", "log", cluster_options_log },
    { "cluster-options", "xml", cluster_options_xml },
    { "cluster-summary", "default", cluster_summary },
    { "cluster-summary", "html", cluster_summary_html },
    { "cluster-stack", "default", cluster_stack_text },
    { "cluster-stack", "html", cluster_stack_html },
    { "cluster-stack", "xml", cluster_stack_xml },
    { "cluster-times", "default", cluster_times_text },
    { "cluster-times", "html", cluster_times_html },
    { "cluster-times", "xml", cluster_times_xml },
    { "failed-action", "default", failed_action_default },
    { "failed-action", "xml", failed_action_xml },
    { "failed-action-list", "default", failed_action_list },
    { "group", "default",  pe__group_default},
    { "group", "xml",  pe__group_xml },
    { "maint-mode", "text", cluster_maint_mode_text },
    { "node", "default", node_text },
    { "node", "html", node_html },
    { "node", "xml", node_xml },
    { "node-and-op", "default", node_and_op },
    { "node-and-op", "xml", node_and_op_xml },
    { "node-capacity", "default", node_capacity },
    { "node-capacity", "xml", node_capacity_xml },
    { "node-history-list", "default", node_history_list },
    { "node-list", "default", node_list_text },
    { "node-list", "html", node_list_html },
    { "node-list", "xml", node_list_xml },
    { "node-weight", "default", node_weight },
    { "node-weight", "xml", node_weight_xml },
    { "node-attribute", "default", node_attribute_text },
    { "node-attribute", "html", node_attribute_html },
    { "node-attribute", "xml", node_attribute_xml },
    { "node-attribute-list", "default", node_attribute_list },
    { "node-summary", "default", node_summary },
    { "op-history", "default", op_history_text },
    { "op-history", "xml", op_history_xml },
    { "primitive", "default",  pe__resource_text },
    { "primitive", "xml",  pe__resource_xml },
    { "primitive", "html",  pe__resource_html },
    { "promotion-score", "default", promotion_score },
    { "promotion-score", "xml", promotion_score_xml },
    { "resource-config", "default", resource_config },
    { "resource-config", "text", resource_config_text },
    { "resource-history", "default", resource_history_text },
    { "resource-history", "xml", resource_history_xml },
    { "resource-list", "default", resource_list },
    { "resource-operation-list", "default", resource_operation_list },
    { "resource-util", "default", resource_util },
    { "resource-util", "xml", resource_util_xml },
    { "ticket", "default", ticket_default },
    { "ticket", "xml", ticket_xml },
    { "ticket-list", "default", ticket_list },

    { NULL, NULL, NULL }
};

void
pe__register_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}
