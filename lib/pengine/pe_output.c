/*
 * Copyright 2019-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <stdint.h>
#include <crm/common/xml_internal.h>
#include <crm/common/output.h>
#include <crm/cib/util.h>
#include <crm/msg_xml.h>
#include <crm/pengine/internal.h>

const char *
pe__resource_description(const pe_resource_t *rsc, uint32_t show_opts)
{
    const char * desc = NULL;
    // User-supplied description
    if (pcmk_any_flags_set(show_opts, pcmk_show_rsc_only|pcmk_show_description)
        || pcmk__list_of_multiple(rsc->running_on)) {
        desc = crm_element_value(rsc->xml, XML_ATTR_DESC);
    }
    return desc;
}

/* Never display node attributes whose name starts with one of these prefixes */
#define FILTER_STR { PCMK__FAIL_COUNT_PREFIX, PCMK__LAST_FAILURE_PREFIX,   \
                     "shutdown", "terminate", "standby", "#", NULL }

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
 * \param[in,out] data_set        Cluster working set
 * \param[in]     attrname        Attribute to find
 * \param[out]    expected_score  Expected value for this attribute
 *
 * \return true if extended information should be printed, false otherwise
 * \note Currently, extended information is only supported for ping/pingd
 *       resources, for which a message will be printed if connectivity is lost
 *       or degraded.
 */
static bool
add_extra_info(const pe_node_t *node, GList *rsc_list, pe_working_set_t *data_set,
               const char *attrname, int *expected_score)
{
    GList *gIter = NULL;

    for (gIter = rsc_list; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *rsc = (pe_resource_t *) gIter->data;
        const char *type = g_hash_table_lookup(rsc->meta, "type");
        const char *name = NULL;
        GHashTable *params = NULL;

        if (rsc->children != NULL) {
            if (add_extra_info(node, rsc->children, data_set, attrname,
                               expected_score)) {
                return true;
            }
        }

        if (!pcmk__strcase_any_of(type, "ping", "pingd", NULL)) {
            continue;
        }

        params = pe_rsc_params(rsc, node, data_set);
        name = g_hash_table_lookup(params, "name");

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

    for (rsc_op = pcmk__xe_first_child(rsc_entry); rsc_op != NULL;
         rsc_op = pcmk__xe_next(rsc_op)) {
        const char *task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);
        const char *interval_ms_s = crm_element_value(rsc_op,
                                                      XML_LRM_ATTR_INTERVAL_MS);
        const char *op_rc = crm_element_value(rsc_op, XML_LRM_ATTR_RC);
        int op_rc_i;

        pcmk__scan_min_int(op_rc, &op_rc_i, 0);

        /* Display 0-interval monitors as "probe" */
        if (pcmk__str_eq(task, PCMK_ACTION_MONITOR, pcmk__str_casei)
            && pcmk__str_eq(interval_ms_s, "0", pcmk__str_null_matches | pcmk__str_casei)) {
            task = "probe";
        }

        /* Ignore notifies and some probes */
        if (pcmk__str_eq(task, CRMD_ACTION_NOTIFY, pcmk__str_casei) || (pcmk__str_eq(task, "probe", pcmk__str_casei) && (op_rc_i == 7))) {
            continue;
        }

        if (pcmk__str_eq((const char *)rsc_op->name, XML_LRM_TAG_RSC_OP, pcmk__str_none)) {
            op_list = g_list_append(op_list, rsc_op);
        }
    }

    op_list = g_list_sort(op_list, sort_op_by_callid);
    return op_list;
}

static void
add_dump_node(gpointer key, gpointer value, gpointer user_data)
{
    xmlNodePtr node = user_data;
    pcmk_create_xml_text_node(node, (const char *) key, (const char *) value);
}

static void
append_dump_text(gpointer key, gpointer value, gpointer user_data)
{
    char **dump_text = user_data;
    char *new_text = crm_strdup_printf("%s %s=%s",
                                       *dump_text, (char *)key, (char *)value);

    free(*dump_text);
    *dump_text = new_text;
}

static const char *
get_cluster_stack(pe_working_set_t *data_set)
{
    xmlNode *stack = get_xpath_object("//nvpair[@name='cluster-infrastructure']",
                                      data_set->input, LOG_DEBUG);
    return stack? crm_element_value(stack, XML_NVPAIR_ATTR_VALUE) : "unknown";
}

static char *
last_changed_string(const char *last_written, const char *user,
                    const char *client, const char *origin) {
    if (last_written != NULL || user != NULL || client != NULL || origin != NULL) {
        return crm_strdup_printf("%s%s%s%s%s%s%s",
                                 last_written ? last_written : "",
                                 user ? " by " : "",
                                 user ? user : "",
                                 client ? " via " : "",
                                 client ? client : "",
                                 origin ? " on " : "",
                                 origin ? origin : "");
    } else {
        return strdup("");
    }
}

static char *
op_history_string(xmlNode *xml_op, const char *task, const char *interval_ms_s,
                  int rc, bool print_timing) {
    const char *call = crm_element_value(xml_op, XML_LRM_ATTR_CALLID);
    char *interval_str = NULL;
    char *buf = NULL;

    if (interval_ms_s && !pcmk__str_eq(interval_ms_s, "0", pcmk__str_casei)) {
        char *pair = pcmk__format_nvpair("interval", interval_ms_s, "ms");
        interval_str = crm_strdup_printf(" %s", pair);
        free(pair);
    }

    if (print_timing) {
        char *last_change_str = NULL;
        char *exec_str = NULL;
        char *queue_str = NULL;

        const char *value = NULL;

        time_t epoch = 0;

        if ((crm_element_value_epoch(xml_op, XML_RSC_OP_LAST_CHANGE, &epoch) == pcmk_ok)
            && (epoch > 0)) {
            char *epoch_str = pcmk__epoch2str(&epoch, 0);

            last_change_str = crm_strdup_printf(" %s=\"%s\"",
                                                XML_RSC_OP_LAST_CHANGE,
                                                pcmk__s(epoch_str, ""));
            free(epoch_str);
        }

        value = crm_element_value(xml_op, XML_RSC_OP_T_EXEC);
        if (value) {
            char *pair = pcmk__format_nvpair(XML_RSC_OP_T_EXEC, value, "ms");
            exec_str = crm_strdup_printf(" %s", pair);
            free(pair);
        }

        value = crm_element_value(xml_op, XML_RSC_OP_T_QUEUE);
        if (value) {
            char *pair = pcmk__format_nvpair(XML_RSC_OP_T_QUEUE, value, "ms");
            queue_str = crm_strdup_printf(" %s", pair);
            free(pair);
        }

        buf = crm_strdup_printf("(%s) %s:%s%s%s%s rc=%d (%s)", call, task,
                                interval_str ? interval_str : "",
                                last_change_str ? last_change_str : "",
                                exec_str ? exec_str : "",
                                queue_str ? queue_str : "",
                                rc, services_ocf_exitcode_str(rc));

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
        buf = crm_strdup_printf("(%s) %s%s%s", call, task,
                                interval_str ? ":" : "",
                                interval_str ? interval_str : "");
    }

    if (interval_str) {
        free(interval_str);
    }

    return buf;
}

static char *
resource_history_string(pe_resource_t *rsc, const char *rsc_id, bool all,
                        int failcount, time_t last_failure) {
    char *buf = NULL;

    if (rsc == NULL) {
        buf = crm_strdup_printf("%s: orphan", rsc_id);
    } else if (all || failcount || last_failure > 0) {
        char *failcount_s = NULL;
        char *lastfail_s = NULL;

        if (failcount > 0) {
            failcount_s = crm_strdup_printf(" %s=%d", PCMK__FAIL_COUNT_PREFIX,
                                            failcount);
        } else {
            failcount_s = strdup("");
        }
        if (last_failure > 0) {
            buf = pcmk__epoch2str(&last_failure, 0);
            lastfail_s = crm_strdup_printf(" %s='%s'",
                                           PCMK__LAST_FAILURE_PREFIX, buf);
            free(buf);
        }

        buf = crm_strdup_printf("%s: migration-threshold=%d%s%s",
                                rsc_id, rsc->migration_threshold, failcount_s,
                                lastfail_s? lastfail_s : "");
        free(failcount_s);
        free(lastfail_s);
    } else {
        buf = crm_strdup_printf("%s:", rsc_id);
    }

    return buf;
}

static const char *
get_node_feature_set(pe_node_t *node) {
    const char *feature_set = NULL;

    if (node->details->online && !pe__is_guest_or_remote_node(node)) {
        feature_set = g_hash_table_lookup(node->details->attrs,
                                          CRM_ATTR_FEATURE_SET);
        /* The feature set attribute is present since 3.15.1. If it is missing
         * then the node must be running an earlier version. */
        if (feature_set == NULL) {
            feature_set = "<3.15.1";
        }
    }
    return feature_set;
}

static bool
is_mixed_version(pe_working_set_t *data_set) {
    const char *feature_set = NULL;
    for (GList *gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = gIter->data;
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

static char *
formatted_xml_buf(pe_resource_t *rsc, bool raw)
{
    if (raw) {
        return dump_xml_formatted(rsc->orig_xml ? rsc->orig_xml : rsc->xml);
    } else {
        return dump_xml_formatted(rsc->xml);
    }
}

PCMK__OUTPUT_ARGS("cluster-summary", "pe_working_set_t *",
                  "enum pcmk_pacemakerd_state", "uint32_t", "uint32_t")
static int
cluster_summary(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);
    enum pcmk_pacemakerd_state pcmkd_state =
        (enum pcmk_pacemakerd_state) va_arg(args, int);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);

    int rc = pcmk_rc_no_output;
    const char *stack_s = get_cluster_stack(data_set);

    if (pcmk_is_set(section_opts, pcmk_section_stack)) {
        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Cluster Summary");
        out->message(out, "cluster-stack", stack_s, pcmkd_state);
    }

    if (pcmk_is_set(section_opts, pcmk_section_dc)) {
        xmlNode *dc_version = get_xpath_object("//nvpair[@name='dc-version']",
                                               data_set->input, LOG_DEBUG);
        const char *dc_version_s = dc_version?
                                   crm_element_value(dc_version, XML_NVPAIR_ATTR_VALUE)
                                   : NULL;
        const char *quorum = crm_element_value(data_set->input, XML_ATTR_HAVE_QUORUM);
        char *dc_name = data_set->dc_node ? pe__node_display_name(data_set->dc_node, pcmk_is_set(show_opts, pcmk_show_node_id)) : NULL;
        bool mixed_version = is_mixed_version(data_set);

        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Cluster Summary");
        out->message(out, "cluster-dc", data_set->dc_node, quorum,
                     dc_version_s, dc_name, mixed_version);
        free(dc_name);
    }

    if (pcmk_is_set(section_opts, pcmk_section_times)) {
        const char *last_written = crm_element_value(data_set->input, XML_CIB_ATTR_WRITTEN);
        const char *user = crm_element_value(data_set->input, XML_ATTR_UPDATE_USER);
        const char *client = crm_element_value(data_set->input, XML_ATTR_UPDATE_CLIENT);
        const char *origin = crm_element_value(data_set->input, XML_ATTR_UPDATE_ORIG);

        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Cluster Summary");
        out->message(out, "cluster-times",
                     data_set->localhost, last_written, user, client, origin);
    }

    if (pcmk_is_set(section_opts, pcmk_section_counts)) {
        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Cluster Summary");
        out->message(out, "cluster-counts", g_list_length(data_set->nodes),
                     data_set->ninstances, data_set->disabled_resources,
                     data_set->blocked_resources);
    }

    if (pcmk_is_set(section_opts, pcmk_section_options)) {
        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Cluster Summary");
        out->message(out, "cluster-options", data_set);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);

    if (pcmk_is_set(section_opts, pcmk_section_maint_mode)) {
        if (out->message(out, "maint-mode", data_set->flags) == pcmk_rc_ok) {
            rc = pcmk_rc_ok;
        }
    }

    return rc;
}

PCMK__OUTPUT_ARGS("cluster-summary", "pe_working_set_t *",
                  "enum pcmk_pacemakerd_state", "uint32_t", "uint32_t")
static int
cluster_summary_html(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);
    enum pcmk_pacemakerd_state pcmkd_state =
        (enum pcmk_pacemakerd_state) va_arg(args, int);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);

    int rc = pcmk_rc_no_output;
    const char *stack_s = get_cluster_stack(data_set);

    if (pcmk_is_set(section_opts, pcmk_section_stack)) {
        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Cluster Summary");
        out->message(out, "cluster-stack", stack_s, pcmkd_state);
    }

    /* Always print DC if none, even if not requested */
    if (data_set->dc_node == NULL || pcmk_is_set(section_opts, pcmk_section_dc)) {
        xmlNode *dc_version = get_xpath_object("//nvpair[@name='dc-version']",
                                               data_set->input, LOG_DEBUG);
        const char *dc_version_s = dc_version?
                                   crm_element_value(dc_version, XML_NVPAIR_ATTR_VALUE)
                                   : NULL;
        const char *quorum = crm_element_value(data_set->input, XML_ATTR_HAVE_QUORUM);
        char *dc_name = data_set->dc_node ? pe__node_display_name(data_set->dc_node, pcmk_is_set(show_opts, pcmk_show_node_id)) : NULL;
        bool mixed_version = is_mixed_version(data_set);

        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Cluster Summary");
        out->message(out, "cluster-dc", data_set->dc_node, quorum,
                     dc_version_s, dc_name, mixed_version);
        free(dc_name);
    }

    if (pcmk_is_set(section_opts, pcmk_section_times)) {
        const char *last_written = crm_element_value(data_set->input, XML_CIB_ATTR_WRITTEN);
        const char *user = crm_element_value(data_set->input, XML_ATTR_UPDATE_USER);
        const char *client = crm_element_value(data_set->input, XML_ATTR_UPDATE_CLIENT);
        const char *origin = crm_element_value(data_set->input, XML_ATTR_UPDATE_ORIG);

        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Cluster Summary");
        out->message(out, "cluster-times",
                     data_set->localhost, last_written, user, client, origin);
    }

    if (pcmk_is_set(section_opts, pcmk_section_counts)) {
        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Cluster Summary");
        out->message(out, "cluster-counts", g_list_length(data_set->nodes),
                     data_set->ninstances, data_set->disabled_resources,
                     data_set->blocked_resources);
    }

    if (pcmk_is_set(section_opts, pcmk_section_options)) {
        /* Kind of a hack - close the list we may have opened earlier in this
         * function so we can put all the options into their own list.  We
         * only want to do this on HTML output, though.
         */
        PCMK__OUTPUT_LIST_FOOTER(out, rc);

        out->begin_list(out, NULL, NULL, "Config Options");
        out->message(out, "cluster-options", data_set);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);

    if (pcmk_is_set(section_opts, pcmk_section_maint_mode)) {
        if (out->message(out, "maint-mode", data_set->flags) == pcmk_rc_ok) {
            rc = pcmk_rc_ok;
        }
    }

    return rc;
}

char *
pe__node_display_name(pe_node_t *node, bool print_detail)
{
    char *node_name;
    const char *node_host = NULL;
    const char *node_id = NULL;
    int name_len;

    CRM_ASSERT((node != NULL) && (node->details != NULL) && (node->details->uname != NULL));

    /* Host is displayed only if this is a guest node and detail is requested */
    if (print_detail && pe__is_guest_node(node)) {
        const pe_resource_t *container = node->details->remote_rsc->container;
        const pe_node_t *host_node = pe__current_node(container);

        if (host_node && host_node->details) {
            node_host = host_node->details->uname;
        }
        if (node_host == NULL) {
            node_host = ""; /* so we at least get "uname@" to indicate guest */
        }
    }

    /* Node ID is displayed if different from uname and detail is requested */
    if (print_detail && !pcmk__str_eq(node->details->uname, node->details->id, pcmk__str_casei)) {
        node_id = node->details->id;
    }

    /* Determine name length */
    name_len = strlen(node->details->uname) + 1;
    if (node_host) {
        name_len += strlen(node_host) + 1; /* "@node_host" */
    }
    if (node_id) {
        name_len += strlen(node_id) + 3; /* + " (node_id)" */
    }

    /* Allocate and populate display name */
    node_name = malloc(name_len);
    CRM_ASSERT(node_name != NULL);
    strcpy(node_name, node->details->uname);
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

int
pe__name_and_nvpairs_xml(pcmk__output_t *out, bool is_list, const char *tag_name
                         , size_t pairs_count, ...)
{
    xmlNodePtr xml_node = NULL;
    va_list args;

    CRM_ASSERT(tag_name != NULL);

    xml_node = pcmk__output_xml_peek_parent(out);
    CRM_ASSERT(xml_node != NULL);
    xml_node = create_xml_node(xml_node, tag_name);

    va_start(args, pairs_count);
    while(pairs_count--) {
        const char *param_name = va_arg(args, const char *);
        const char *param_value = va_arg(args, const char *);
        if (param_name && param_value) {
            crm_xml_add(xml_node, param_name, param_value);
        }
    };
    va_end(args);

    if (is_list) {
        pcmk__output_xml_push_parent(out, xml_node);
    }
    return pcmk_rc_ok;
}

static const char *
role_desc(enum rsc_role_e role)
{
    if (role == RSC_ROLE_PROMOTED) {
#ifdef PCMK__COMPAT_2_0
        return "as " RSC_ROLE_PROMOTED_LEGACY_S " ";
#else
        return "in " RSC_ROLE_PROMOTED_S " role ";
#endif
    }
    return "";
}

PCMK__OUTPUT_ARGS("ban", "pe_node_t *", "pe__location_t *", "uint32_t")
static int
ban_html(pcmk__output_t *out, va_list args) {
    pe_node_t *pe_node = va_arg(args, pe_node_t *);
    pe__location_t *location = va_arg(args, pe__location_t *);
    uint32_t show_opts = va_arg(args, uint32_t);

    char *node_name = pe__node_display_name(pe_node,
                                            pcmk_is_set(show_opts, pcmk_show_node_id));
    char *buf = crm_strdup_printf("%s\tprevents %s from running %son %s",
                                  location->id, location->rsc_lh->id,
                                  role_desc(location->role_filter), node_name);

    pcmk__output_create_html_node(out, "li", NULL, NULL, buf);

    free(node_name);
    free(buf);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ban", "pe_node_t *", "pe__location_t *", "uint32_t")
static int
ban_text(pcmk__output_t *out, va_list args) {
    pe_node_t *pe_node = va_arg(args, pe_node_t *);
    pe__location_t *location = va_arg(args, pe__location_t *);
    uint32_t show_opts = va_arg(args, uint32_t);

    char *node_name = pe__node_display_name(pe_node,
                                            pcmk_is_set(show_opts, pcmk_show_node_id));
    out->list_item(out, NULL, "%s\tprevents %s from running %son %s",
                   location->id, location->rsc_lh->id,
                   role_desc(location->role_filter), node_name);

    free(node_name);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ban", "pe_node_t *", "pe__location_t *", "uint32_t")
static int
ban_xml(pcmk__output_t *out, va_list args) {
    pe_node_t *pe_node = va_arg(args, pe_node_t *);
    pe__location_t *location = va_arg(args, pe__location_t *);
    uint32_t show_opts G_GNUC_UNUSED = va_arg(args, uint32_t);

    const char *promoted_only = pcmk__btoa(location->role_filter == RSC_ROLE_PROMOTED);
    char *weight_s = pcmk__itoa(pe_node->weight);

    pcmk__output_create_xml_node(out, "ban",
                                 "id", location->id,
                                 "resource", location->rsc_lh->id,
                                 "node", pe_node->details->uname,
                                 "weight", weight_s,
                                 "promoted-only", promoted_only,
                                 /* This is a deprecated alias for
                                  * promoted_only. Removing it will break
                                  * backward compatibility of the API schema,
                                  * which will require an API schema major
                                  * version bump.
                                  */
                                 "master_only", promoted_only,
                                 NULL);

    free(weight_s);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ban-list", "pe_working_set_t *", "const char *", "GList *",
                  "uint32_t", "bool")
static int
ban_list(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);
    const char *prefix = va_arg(args, const char *);
    GList *only_rsc = va_arg(args, GList *);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool print_spacer = va_arg(args, int);

    GList *gIter, *gIter2;
    int rc = pcmk_rc_no_output;

    /* Print each ban */
    for (gIter = data_set->placement_constraints; gIter != NULL; gIter = gIter->next) {
        pe__location_t *location = gIter->data;
        const pe_resource_t *rsc = location->rsc_lh;

        if (prefix != NULL && !g_str_has_prefix(location->id, prefix)) {
            continue;
        }

        if (!pcmk__str_in_list(rsc_printable_id(rsc), only_rsc,
                               pcmk__str_star_matches)
            && !pcmk__str_in_list(rsc_printable_id(pe__const_top_resource(rsc, false)),
                                  only_rsc, pcmk__str_star_matches)) {
            continue;
        }

        for (gIter2 = location->node_list_rh; gIter2 != NULL; gIter2 = gIter2->next) {
            pe_node_t *node = (pe_node_t *) gIter2->data;

            if (node->weight < 0) {
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

    xmlNodePtr nodes_node = pcmk__output_create_xml_node(out, "li", NULL);
    xmlNodePtr resources_node = pcmk__output_create_xml_node(out, "li", NULL);

    char *nnodes_str = crm_strdup_printf("%d node%s configured",
                                         nnodes, pcmk__plural_s(nnodes));

    pcmk_create_html_node(nodes_node, "span", NULL, NULL, nnodes_str);
    free(nnodes_str);

    if (ndisabled && nblocked) {
        char *s = crm_strdup_printf("%d resource instance%s configured (%d ",
                                    nresources, pcmk__plural_s(nresources),
                                    ndisabled);
        pcmk_create_html_node(resources_node, "span", NULL, NULL, s);
        free(s);

        pcmk_create_html_node(resources_node, "span", NULL, "bold", "DISABLED");

        s = crm_strdup_printf(", %d ", nblocked);
        pcmk_create_html_node(resources_node, "span", NULL, NULL, s);
        free(s);

        pcmk_create_html_node(resources_node, "span", NULL, "bold", "BLOCKED");
        pcmk_create_html_node(resources_node, "span", NULL, NULL,
                              " from further action due to failure)");
    } else if (ndisabled && !nblocked) {
        char *s = crm_strdup_printf("%d resource instance%s configured (%d ",
                                    nresources, pcmk__plural_s(nresources),
                                    ndisabled);
        pcmk_create_html_node(resources_node, "span", NULL, NULL, s);
        free(s);

        pcmk_create_html_node(resources_node, "span", NULL, "bold", "DISABLED");
        pcmk_create_html_node(resources_node, "span", NULL, NULL, ")");
    } else if (!ndisabled && nblocked) {
        char *s = crm_strdup_printf("%d resource instance%s configured (%d ",
                                    nresources, pcmk__plural_s(nresources),
                                    nblocked);
        pcmk_create_html_node(resources_node, "span", NULL, NULL, s);
        free(s);

        pcmk_create_html_node(resources_node, "span", NULL, "bold", "BLOCKED");
        pcmk_create_html_node(resources_node, "span", NULL, NULL,
                              " from further action due to failure)");
    } else {
        char *s = crm_strdup_printf("%d resource instance%s configured",
                                    nresources, pcmk__plural_s(nresources));
        pcmk_create_html_node(resources_node, "span", NULL, NULL, s);
        free(s);
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

    xmlNodePtr nodes_node = pcmk__output_create_xml_node(out, "nodes_configured", NULL);
    xmlNodePtr resources_node = pcmk__output_create_xml_node(out, "resources_configured", NULL);

    char *s = pcmk__itoa(nnodes);
    crm_xml_add(nodes_node, "number", s);
    free(s);

    s = pcmk__itoa(nresources);
    crm_xml_add(resources_node, "number", s);
    free(s);

    s = pcmk__itoa(ndisabled);
    crm_xml_add(resources_node, "disabled", s);
    free(s);

    s = pcmk__itoa(nblocked);
    crm_xml_add(resources_node, "blocked", s);
    free(s);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("cluster-dc", "pe_node_t *", "const char *", "const char *",
                  "char *", "int")
static int
cluster_dc_html(pcmk__output_t *out, va_list args) {
    pe_node_t *dc = va_arg(args, pe_node_t *);
    const char *quorum = va_arg(args, const char *);
    const char *dc_version_s = va_arg(args, const char *);
    char *dc_name = va_arg(args, char *);
    bool mixed_version = va_arg(args, int);

    xmlNodePtr node = pcmk__output_create_xml_node(out, "li", NULL);

    pcmk_create_html_node(node, "span", NULL, "bold", "Current DC: ");

    if (dc) {
        char *buf = crm_strdup_printf("%s (version %s) -", dc_name,
                                      dc_version_s ? dc_version_s : "unknown");
        pcmk_create_html_node(node, "span", NULL, NULL, buf);
        free(buf);

        if (mixed_version) {
            pcmk_create_html_node(node, "span", NULL, "warning",
                                  " MIXED-VERSION");
        }
        pcmk_create_html_node(node, "span", NULL, NULL, " partition");
        if (crm_is_true(quorum)) {
            pcmk_create_html_node(node, "span", NULL, NULL, " with");
        } else {
            pcmk_create_html_node(node, "span", NULL, "warning", " WITHOUT");
        }
        pcmk_create_html_node(node, "span", NULL, NULL, " quorum");
    } else {
        pcmk_create_html_node(node, "span", NULL, "warning", "NONE");
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("cluster-dc", "pe_node_t *", "const char *", "const char *",
                  "char *", "int")
static int
cluster_dc_text(pcmk__output_t *out, va_list args) {
    pe_node_t *dc = va_arg(args, pe_node_t *);
    const char *quorum = va_arg(args, const char *);
    const char *dc_version_s = va_arg(args, const char *);
    char *dc_name = va_arg(args, char *);
    bool mixed_version = va_arg(args, int);

    if (dc) {
        out->list_item(out, "Current DC",
                       "%s (version %s) - %spartition %s quorum",
                       dc_name, dc_version_s ? dc_version_s : "unknown",
                       mixed_version ? "MIXED-VERSION " : "",
                       crm_is_true(quorum) ? "with" : "WITHOUT");
    } else {
        out->list_item(out, "Current DC", "NONE");
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("cluster-dc", "pe_node_t *", "const char *", "const char *",
                  "char *", "int")
static int
cluster_dc_xml(pcmk__output_t *out, va_list args) {
    pe_node_t *dc = va_arg(args, pe_node_t *);
    const char *quorum = va_arg(args, const char *);
    const char *dc_version_s = va_arg(args, const char *);
    char *dc_name G_GNUC_UNUSED = va_arg(args, char *);
    bool mixed_version = va_arg(args, int);

    if (dc) {
        pcmk__output_create_xml_node(out, "current_dc",
                                     "present", "true",
                                     "version", dc_version_s ? dc_version_s : "",
                                     "name", dc->details->uname,
                                     "id", dc->details->id,
                                     "with_quorum", pcmk__btoa(crm_is_true(quorum)),
                                     "mixed_version", pcmk__btoa(mixed_version),
                                     NULL);
    } else {
        pcmk__output_create_xml_node(out, "current_dc",
                                     "present", "false",
                                     NULL);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("maint-mode", "unsigned long long int")
static int
cluster_maint_mode_text(pcmk__output_t *out, va_list args) {
    unsigned long long flags = va_arg(args, unsigned long long);

    if (pcmk_is_set(flags, pe_flag_maintenance_mode)) {
        pcmk__formatted_printf(out, "\n              *** Resource management is DISABLED ***\n");
        pcmk__formatted_printf(out, "  The cluster will not attempt to start, stop or recover services\n");
        return pcmk_rc_ok;
    } else if (pcmk_is_set(flags, pe_flag_stop_everything)) {
        pcmk__formatted_printf(out, "\n    *** Resource management is DISABLED ***\n");
        pcmk__formatted_printf(out, "  The cluster will keep all resources stopped\n");
        return pcmk_rc_ok;
    } else {
        return pcmk_rc_no_output;
    }
}

PCMK__OUTPUT_ARGS("cluster-options", "pe_working_set_t *")
static int
cluster_options_html(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);

    out->list_item(out, NULL, "STONITH of failed nodes %s",
                   pcmk_is_set(data_set->flags, pe_flag_stonith_enabled) ? "enabled" : "disabled");

    out->list_item(out, NULL, "Cluster is %s",
                   pcmk_is_set(data_set->flags, pe_flag_symmetric_cluster) ? "symmetric" : "asymmetric");

    switch (data_set->no_quorum_policy) {
        case no_quorum_freeze:
            out->list_item(out, NULL, "No quorum policy: Freeze resources");
            break;

        case no_quorum_stop:
            out->list_item(out, NULL, "No quorum policy: Stop ALL resources");
            break;

        case no_quorum_demote:
            out->list_item(out, NULL, "No quorum policy: Demote promotable "
                           "resources and stop all other resources");
            break;

        case no_quorum_ignore:
            out->list_item(out, NULL, "No quorum policy: Ignore");
            break;

        case no_quorum_suicide:
            out->list_item(out, NULL, "No quorum policy: Suicide");
            break;
    }

    if (pcmk_is_set(data_set->flags, pe_flag_maintenance_mode)) {
        xmlNodePtr node = pcmk__output_create_xml_node(out, "li", NULL);

        pcmk_create_html_node(node, "span", NULL, NULL, "Resource management: ");
        pcmk_create_html_node(node, "span", NULL, "bold", "DISABLED");
        pcmk_create_html_node(node, "span", NULL, NULL,
                              " (the cluster will not attempt to start, stop, or recover services)");
    } else if (pcmk_is_set(data_set->flags, pe_flag_stop_everything)) {
        xmlNodePtr node = pcmk__output_create_xml_node(out, "li", NULL);

        pcmk_create_html_node(node, "span", NULL, NULL, "Resource management: ");
        pcmk_create_html_node(node, "span", NULL, "bold", "STOPPED");
        pcmk_create_html_node(node, "span", NULL, NULL,
                              " (the cluster will keep all resources stopped)");
    } else {
        out->list_item(out, NULL, "Resource management: enabled");
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("cluster-options", "pe_working_set_t *")
static int
cluster_options_log(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);

    if (pcmk_is_set(data_set->flags, pe_flag_maintenance_mode)) {
        return out->info(out, "Resource management is DISABLED.  The cluster will not attempt to start, stop or recover services.");
    } else if (pcmk_is_set(data_set->flags, pe_flag_stop_everything)) {
        return out->info(out, "Resource management is DISABLED.  The cluster has stopped all resources.");
    } else {
        return pcmk_rc_no_output;
    }
}

PCMK__OUTPUT_ARGS("cluster-options", "pe_working_set_t *")
static int
cluster_options_text(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);

    out->list_item(out, NULL, "STONITH of failed nodes %s",
                   pcmk_is_set(data_set->flags, pe_flag_stonith_enabled) ? "enabled" : "disabled");

    out->list_item(out, NULL, "Cluster is %s",
                   pcmk_is_set(data_set->flags, pe_flag_symmetric_cluster) ? "symmetric" : "asymmetric");

    switch (data_set->no_quorum_policy) {
        case no_quorum_freeze:
            out->list_item(out, NULL, "No quorum policy: Freeze resources");
            break;

        case no_quorum_stop:
            out->list_item(out, NULL, "No quorum policy: Stop ALL resources");
            break;

        case no_quorum_demote:
            out->list_item(out, NULL, "No quorum policy: Demote promotable "
                           "resources and stop all other resources");
            break;

        case no_quorum_ignore:
            out->list_item(out, NULL, "No quorum policy: Ignore");
            break;

        case no_quorum_suicide:
            out->list_item(out, NULL, "No quorum policy: Suicide");
            break;
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("cluster-options", "pe_working_set_t *")
static int
cluster_options_xml(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);

    const char *no_quorum_policy = NULL;
    char *stonith_timeout_str = pcmk__itoa(data_set->stonith_timeout);
    char *priority_fencing_delay_str = pcmk__itoa(data_set->priority_fencing_delay * 1000);

    switch (data_set->no_quorum_policy) {
        case no_quorum_freeze:
            no_quorum_policy = "freeze";
            break;

        case no_quorum_stop:
            no_quorum_policy = "stop";
            break;

        case no_quorum_demote:
            no_quorum_policy = "demote";
            break;

        case no_quorum_ignore:
            no_quorum_policy = "ignore";
            break;

        case no_quorum_suicide:
            no_quorum_policy = "suicide";
            break;
    }

    pcmk__output_create_xml_node(out, "cluster_options",
                                 "stonith-enabled", pcmk__btoa(pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)),
                                 "symmetric-cluster", pcmk__btoa(pcmk_is_set(data_set->flags, pe_flag_symmetric_cluster)),
                                 "no-quorum-policy", no_quorum_policy,
                                 "maintenance-mode", pcmk__btoa(pcmk_is_set(data_set->flags, pe_flag_maintenance_mode)),
                                 "stop-all-resources", pcmk__btoa(pcmk_is_set(data_set->flags, pe_flag_stop_everything)),
                                 "stonith-timeout-ms", stonith_timeout_str,
                                 "priority-fencing-delay-ms", priority_fencing_delay_str,
                                 NULL);
    free(stonith_timeout_str);
    free(priority_fencing_delay_str);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("cluster-stack", "const char *", "enum pcmk_pacemakerd_state")
static int
cluster_stack_html(pcmk__output_t *out, va_list args) {
    const char *stack_s = va_arg(args, const char *);
    enum pcmk_pacemakerd_state pcmkd_state =
        (enum pcmk_pacemakerd_state) va_arg(args, int);

    xmlNodePtr node = pcmk__output_create_xml_node(out, "li", NULL);

    pcmk_create_html_node(node, "span", NULL, "bold", "Stack: ");
    pcmk_create_html_node(node, "span", NULL, NULL, stack_s);

    if (pcmkd_state != pcmk_pacemakerd_state_invalid) {
        pcmk_create_html_node(node, "span", NULL, NULL, " (");
        pcmk_create_html_node(node, "span", NULL, NULL,
                              pcmk__pcmkd_state_enum2friendly(pcmkd_state));
        pcmk_create_html_node(node, "span", NULL, NULL, ")");
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

    const char *state_s = NULL;

    if (pcmkd_state != pcmk_pacemakerd_state_invalid) {
        state_s = pcmk_pacemakerd_api_daemon_state_enum2text(pcmkd_state);
    }

    pcmk__output_create_xml_node(out, "stack",
                                 "type", stack_s,
                                 "pacemakerd-state", state_s,
                                 NULL);

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

    xmlNodePtr updated_node = pcmk__output_create_xml_node(out, "li", NULL);
    xmlNodePtr changed_node = pcmk__output_create_xml_node(out, "li", NULL);

    char *time_s = pcmk__epoch2str(NULL, 0);

    pcmk_create_html_node(updated_node, "span", NULL, "bold", "Last updated: ");
    pcmk_create_html_node(updated_node, "span", NULL, NULL, time_s);

    if (our_nodename != NULL) {
        pcmk_create_html_node(updated_node, "span", NULL, NULL, " on ");
        pcmk_create_html_node(updated_node, "span", NULL, NULL, our_nodename);
    }

    free(time_s);
    time_s = last_changed_string(last_written, user, client, origin);

    pcmk_create_html_node(changed_node, "span", NULL, "bold", "Last change: ");
    pcmk_create_html_node(changed_node, "span", NULL, NULL, time_s);

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

    char *time_s = pcmk__epoch2str(NULL, 0);

    pcmk__output_create_xml_node(out, "last_update",
                                 "time", time_s,
                                 "origin", our_nodename,
                                 NULL);

    pcmk__output_create_xml_node(out, "last_change",
                                 "time", last_written ? last_written : "",
                                 "user", user ? user : "",
                                 "client", client ? client : "",
                                 "origin", origin ? origin : "",
                                 NULL);

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
        rsc_id = strdup("unknown resource");
        task = strdup("unknown action");
        interval_ms = 0;
    }
    CRM_ASSERT((rsc_id != NULL) && (task != NULL));

    str = g_string_sized_new(256); // Should be sufficient for most messages

    pcmk__g_strcat(str, rsc_id, " ", NULL);

    if (interval_ms != 0) {
        pcmk__g_strcat(str, pcmk__readable_interval(interval_ms), "-interval ",
                       NULL);
    }
    pcmk__g_strcat(str, crm_action_str(task, interval_ms), " on ", node_name,
                   NULL);

    if (status == PCMK_EXEC_DONE) {
        pcmk__g_strcat(str, " returned '", services_ocf_exitcode_str(rc), "'",
                       NULL);
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


    if (crm_element_value_epoch(xml_op, XML_RSC_OP_LAST_CHANGE,
                                &last_change_epoch) == pcmk_ok) {
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
    const char *call_id = crm_element_value(xml_op, XML_LRM_ATTR_CALLID);
    const char *queue_time = crm_element_value(xml_op, XML_RSC_OP_T_QUEUE);
    const char *exit_status = services_ocf_exitcode_str(rc);
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

    if (crm_element_value_epoch(xml_op, XML_RSC_OP_LAST_CHANGE,
                                &last_change_epoch) == pcmk_ok) {
        char *last_change_str = pcmk__epoch2str(&last_change_epoch, 0);

        pcmk__g_strcat(str,
                       ", " XML_RSC_OP_LAST_CHANGE "="
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

PCMK__OUTPUT_ARGS("failed-action", "xmlNodePtr", "uint32_t")
static int
failed_action_default(pcmk__output_t *out, va_list args)
{
    xmlNodePtr xml_op = va_arg(args, xmlNodePtr);
    uint32_t show_opts = va_arg(args, uint32_t);

    const char *op_key = pe__xe_history_key(xml_op);
    const char *node_name = crm_element_value(xml_op, XML_ATTR_UNAME);
    const char *exit_reason = crm_element_value(xml_op,
                                                XML_LRM_ATTR_EXIT_REASON);
    const char *exec_time = crm_element_value(xml_op, XML_RSC_OP_T_EXEC);

    int rc;
    int status;

    pcmk__scan_min_int(crm_element_value(xml_op, XML_LRM_ATTR_RC), &rc, 0);

    pcmk__scan_min_int(crm_element_value(xml_op, XML_LRM_ATTR_OPSTATUS),
                       &status, 0);

    if (pcmk__str_empty(node_name)) {
        node_name = "unknown node";
    }

    if (pcmk_is_set(show_opts, pcmk_show_failed_detail)) {
        failed_action_technical(out, xml_op, op_key, node_name, rc, status,
                                exit_reason, exec_time);
    } else {
        failed_action_friendly(out, xml_op, op_key, node_name, rc, status,
                               exit_reason, exec_time);
    }
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("failed-action", "xmlNodePtr", "uint32_t")
static int
failed_action_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr xml_op = va_arg(args, xmlNodePtr);
    uint32_t show_opts G_GNUC_UNUSED = va_arg(args, uint32_t);

    const char *op_key = pe__xe_history_key(xml_op);
    const char *op_key_name = "op_key";
    int rc;
    int status;
    const char *exit_reason = crm_element_value(xml_op, XML_LRM_ATTR_EXIT_REASON);

    time_t epoch = 0;
    char *rc_s = NULL;
    char *reason_s = crm_xml_escape(exit_reason ? exit_reason : "none");
    xmlNodePtr node = NULL;

    pcmk__scan_min_int(crm_element_value(xml_op, XML_LRM_ATTR_RC), &rc, 0);
    pcmk__scan_min_int(crm_element_value(xml_op, XML_LRM_ATTR_OPSTATUS),
                       &status, 0);

    rc_s = pcmk__itoa(rc);
    if (crm_element_value(xml_op, XML_LRM_ATTR_TASK_KEY) == NULL) {
        op_key_name = "id";
    }
    node = pcmk__output_create_xml_node(out, "failure",
                                        op_key_name, op_key,
                                        "node", crm_element_value(xml_op, XML_ATTR_UNAME),
                                        "exitstatus", services_ocf_exitcode_str(rc),
                                        "exitreason", pcmk__s(reason_s, ""),
                                        "exitcode", rc_s,
                                        "call", crm_element_value(xml_op, XML_LRM_ATTR_CALLID),
                                        "status", pcmk_exec_status_str(status),
                                        NULL);
    free(rc_s);

    if ((crm_element_value_epoch(xml_op, XML_RSC_OP_LAST_CHANGE,
                                 &epoch) == pcmk_ok) && (epoch > 0)) {
        guint interval_ms = 0;
        char *interval_ms_s = NULL;
        char *rc_change = pcmk__epoch2str(&epoch,
                                          crm_time_log_date
                                          |crm_time_log_timeofday
                                          |crm_time_log_with_timezone);

        crm_element_value_ms(xml_op, XML_LRM_ATTR_INTERVAL_MS, &interval_ms);
        interval_ms_s = crm_strdup_printf("%u", interval_ms);

        pcmk__xe_set_props(node, XML_RSC_OP_LAST_CHANGE, rc_change,
                           "queued", crm_element_value(xml_op, XML_RSC_OP_T_QUEUE),
                           "exec", crm_element_value(xml_op, XML_RSC_OP_T_EXEC),
                           "interval", interval_ms_s,
                           "task", crm_element_value(xml_op, XML_LRM_ATTR_TASK),
                           NULL);

        free(interval_ms_s);
        free(rc_change);
    }

    free(reason_s);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("failed-action-list", "pe_working_set_t *", "GList *",
                  "GList *", "uint32_t", "bool")
static int
failed_action_list(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool print_spacer = va_arg(args, int);

    xmlNode *xml_op = NULL;
    int rc = pcmk_rc_no_output;

    if (xmlChildElementCount(data_set->failed) == 0) {
        return rc;
    }

    for (xml_op = pcmk__xml_first_child(data_set->failed); xml_op != NULL;
         xml_op = pcmk__xml_next(xml_op)) {
        char *rsc = NULL;

        if (!pcmk__str_in_list(crm_element_value(xml_op, XML_ATTR_UNAME), only_node,
                               pcmk__str_star_matches|pcmk__str_casei)) {
            continue;
        }

        if (pcmk_xe_mask_probe_failure(xml_op)) {
            continue;
        }

        if (!parse_op_key(pe__xe_history_key(xml_op), &rsc, NULL, NULL)) {
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
status_node(pe_node_t *node, xmlNodePtr parent, uint32_t show_opts)
{
    int health = pe__node_health(node);

    // Cluster membership
    if (node->details->online) {
        pcmk_create_html_node(parent, "span", NULL, "online", " online");
    } else {
        pcmk_create_html_node(parent, "span", NULL, "offline", " OFFLINE");
    }

    // Standby mode
    if (node->details->standby_onfail && (node->details->running_rsc != NULL)) {
        pcmk_create_html_node(parent, "span", NULL, "standby",
                              " (in standby due to on-fail,"
                              " with active resources)");
    } else if (node->details->standby_onfail) {
        pcmk_create_html_node(parent, "span", NULL, "standby",
                              " (in standby due to on-fail)");
    } else if (node->details->standby && (node->details->running_rsc != NULL)) {
        pcmk_create_html_node(parent, "span", NULL, "standby",
                              " (in standby, with active resources)");
    } else if (node->details->standby) {
        pcmk_create_html_node(parent, "span", NULL, "standby", " (in standby)");
    }

    // Maintenance mode
    if (node->details->maintenance) {
        pcmk_create_html_node(parent, "span", NULL, "maint",
                              " (in maintenance mode)");
    }

    // Node health
    if (health < 0) {
        pcmk_create_html_node(parent, "span", NULL, "health_red",
                              " (health is RED)");
    } else if (health == 0) {
        pcmk_create_html_node(parent, "span", NULL, "health_yellow",
                              " (health is YELLOW)");
    }

    // Feature set
    if (pcmk_is_set(show_opts, pcmk_show_feature_set)) {
        const char *feature_set = get_node_feature_set(node);
        if (feature_set != NULL) {
            char *buf = crm_strdup_printf(", feature set %s", feature_set);
            pcmk_create_html_node(parent, "span", NULL, NULL, buf);
            free(buf);
        }
    }
}

PCMK__OUTPUT_ARGS("node", "pe_node_t *", "uint32_t", "bool",
                  "GList *", "GList *")
static int
node_html(pcmk__output_t *out, va_list args) {
    pe_node_t *node = va_arg(args, pe_node_t *);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool full = va_arg(args, int);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    char *node_name = pe__node_display_name(node, pcmk_is_set(show_opts, pcmk_show_node_id));

    if (full) {
        xmlNodePtr item_node;

        if (pcmk_all_flags_set(show_opts, pcmk_show_brief | pcmk_show_rscs_by_node)) {
            GList *rscs = pe__filter_rsc_list(node->details->running_rsc, only_rsc);

            out->begin_list(out, NULL, NULL, "%s:", node_name);
            item_node = pcmk__output_xml_create_parent(out, "li", NULL);
            pcmk_create_html_node(item_node, "span", NULL, NULL, "Status:");
            status_node(node, item_node, show_opts);

            if (rscs != NULL) {
                uint32_t new_show_opts = (show_opts | pcmk_show_rsc_only) & ~pcmk_show_inactive_rscs;
                out->begin_list(out, NULL, NULL, "Resources");
                pe__rscs_brief_output(out, rscs, new_show_opts);
                out->end_list(out);
            }

            pcmk__output_xml_pop_parent(out);
            out->end_list(out);

        } else if (pcmk_is_set(show_opts, pcmk_show_rscs_by_node)) {
            GList *lpc2 = NULL;
            int rc = pcmk_rc_no_output;

            out->begin_list(out, NULL, NULL, "%s:", node_name);
            item_node = pcmk__output_xml_create_parent(out, "li", NULL);
            pcmk_create_html_node(item_node, "span", NULL, NULL, "Status:");
            status_node(node, item_node, show_opts);

            for (lpc2 = node->details->running_rsc; lpc2 != NULL; lpc2 = lpc2->next) {
                pe_resource_t *rsc = (pe_resource_t *) lpc2->data;
                PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Resources");

                show_opts |= pcmk_show_rsc_only;
                out->message(out, crm_map_element_name(rsc->xml), show_opts,
                             rsc, only_node, only_rsc);
            }

            PCMK__OUTPUT_LIST_FOOTER(out, rc);
            pcmk__output_xml_pop_parent(out);
            out->end_list(out);

        } else {
            char *buf = crm_strdup_printf("%s:", node_name);

            item_node = pcmk__output_create_xml_node(out, "li", NULL);
            pcmk_create_html_node(item_node, "span", NULL, "bold", buf);
            status_node(node, item_node, show_opts);

            free(buf);
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
node_text_status(const pe_node_t *node)
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

    } else if (node->details->standby_onfail && node->details->online) {
        return "standby (on-fail)";

    } else if (node->details->standby) {
        if (node->details->online) {
            if (node->details->running_rsc) {
                return "standby (with active resources)";
            } else {
                return "standby";
            }
        } else {
            return "OFFLINE (standby)";
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

PCMK__OUTPUT_ARGS("node", "pe_node_t *", "uint32_t", "bool", "GList *", "GList *")
static int
node_text(pcmk__output_t *out, va_list args) {
    pe_node_t *node = va_arg(args, pe_node_t *);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool full = va_arg(args, int);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    if (full) {
        char *node_name = pe__node_display_name(node, pcmk_is_set(show_opts, pcmk_show_node_id));
        GString *str = g_string_sized_new(64);
        int health = pe__node_health(node);

        // Create a summary line with node type, name, and status
        if (pe__is_guest_node(node)) {
            g_string_append(str, "GuestNode");
        } else if (pe__is_remote_node(node)) {
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
        if (pcmk_is_set(show_opts, pcmk_show_feature_set)) {
            const char *feature_set = get_node_feature_set(node);
            if (feature_set != NULL) {
                pcmk__g_strcat(str, ", feature set ", feature_set, NULL);
            }
        }

        /* If we're grouping by node, print its resources */
        if (pcmk_is_set(show_opts, pcmk_show_rscs_by_node)) {
            if (pcmk_is_set(show_opts, pcmk_show_brief)) {
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
                    pe_resource_t *rsc = (pe_resource_t *) gIter2->data;

                    show_opts |= pcmk_show_rsc_only;
                    out->message(out, crm_map_element_name(rsc->xml), show_opts,
                                 rsc, only_node, only_rsc);
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
        char *node_name = pe__node_display_name(node, pcmk_is_set(show_opts, pcmk_show_node_id));
        out->begin_list(out, NULL, NULL, "Node: %s", node_name);
        free(node_name);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node", "pe_node_t *", "uint32_t", "bool", "GList *", "GList *")
static int
node_xml(pcmk__output_t *out, va_list args) {
    pe_node_t *node = va_arg(args, pe_node_t *);
    uint32_t show_opts G_GNUC_UNUSED = va_arg(args, uint32_t);
    bool full = va_arg(args, int);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    if (full) {
        const char *node_type = "unknown";
        char *length_s = pcmk__itoa(g_list_length(node->details->running_rsc));
        int health = pe__node_health(node);
        const char *health_s = NULL;
        const char *feature_set;

        switch (node->details->type) {
            case node_member:
                node_type = "member";
                break;
            case node_remote:
                node_type = "remote";
                break;
            case node_ping:
                node_type = "ping";
                break;
        }

        if (health < 0) {
            health_s = "red";
        } else if (health == 0) {
            health_s = "yellow";
        } else {
            health_s = "green";
        }

        feature_set = get_node_feature_set(node);

        pe__name_and_nvpairs_xml(out, true, "node", 15,
                                 "name", node->details->uname,
                                 "id", node->details->id,
                                 "online", pcmk__btoa(node->details->online),
                                 "standby", pcmk__btoa(node->details->standby),
                                 "standby_onfail", pcmk__btoa(node->details->standby_onfail),
                                 "maintenance", pcmk__btoa(node->details->maintenance),
                                 "pending", pcmk__btoa(node->details->pending),
                                 "unclean", pcmk__btoa(node->details->unclean),
                                 "health", health_s,
                                 "feature_set", feature_set,
                                 "shutdown", pcmk__btoa(node->details->shutdown),
                                 "expected_up", pcmk__btoa(node->details->expected_up),
                                 "is_dc", pcmk__btoa(node->details->is_dc),
                                 "resources_running", length_s,
                                 "type", node_type);

        if (pe__is_guest_node(node)) {
            xmlNodePtr xml_node = pcmk__output_xml_peek_parent(out);
            crm_xml_add(xml_node, "id_as_resource", node->details->remote_rsc->container->id);
        }

        if (pcmk_is_set(show_opts, pcmk_show_rscs_by_node)) {
            GList *lpc = NULL;

            for (lpc = node->details->running_rsc; lpc != NULL; lpc = lpc->next) {
                pe_resource_t *rsc = (pe_resource_t *) lpc->data;

                show_opts |= pcmk_show_rsc_only;
                out->message(out, crm_map_element_name(rsc->xml), show_opts,
                             rsc, only_node, only_rsc);
            }
        }

        free(length_s);

        out->end_list(out);
    } else {
        pcmk__output_xml_create_parent(out, "node",
                                       "name", node->details->uname,
                                       NULL);
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
        int v;
        char *s = crm_strdup_printf("%s: %s", name, value);
        xmlNodePtr item_node = pcmk__output_create_xml_node(out, "li", NULL);

        if (value == NULL) {
            v = 0;
        } else {
            pcmk__scan_min_int(value, &v, INT_MIN);
        }

        pcmk_create_html_node(item_node, "span", NULL, NULL, s);
        free(s);

        if (v <= 0) {
            pcmk_create_html_node(item_node, "span", NULL, "bold", "(connectivity is lost)");
        } else if (v < expected_score) {
            char *buf = crm_strdup_printf("(connectivity is degraded -- expected %d", expected_score);
            pcmk_create_html_node(item_node, "span", NULL, "bold", buf);
            free(buf);
        }
    } else {
        out->list_item(out, NULL, "%s: %s", name, value);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-and-op", "pe_working_set_t *", "xmlNodePtr")
static int
node_and_op(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);
    xmlNodePtr xml_op = va_arg(args, xmlNodePtr);

    pe_resource_t *rsc = NULL;
    gchar *node_str = NULL;
    char *last_change_str = NULL;

    const char *op_rsc = crm_element_value(xml_op, "resource");
    int status;
    time_t last_change = 0;

    pcmk__scan_min_int(crm_element_value(xml_op, XML_LRM_ATTR_OPSTATUS),
                       &status, PCMK_EXEC_UNKNOWN);

    rsc = pe_find_resource(data_set->resources, op_rsc);

    if (rsc) {
        const pe_node_t *node = pe__current_node(rsc);
        const char *target_role = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET_ROLE);
        uint32_t show_opts = pcmk_show_rsc_only | pcmk_show_pending;

        if (node == NULL) {
            node = rsc->pending_node;
        }

        node_str = pcmk__native_output_string(rsc, rsc_printable_id(rsc), node,
                                              show_opts, target_role, false);
    } else {
        node_str = crm_strdup_printf("Unknown resource %s", op_rsc);
    }

    if (crm_element_value_epoch(xml_op, XML_RSC_OP_LAST_CHANGE,
                                &last_change) == pcmk_ok) {
        last_change_str = crm_strdup_printf(", %s='%s', exec=%sms",
                                            XML_RSC_OP_LAST_CHANGE,
                                            pcmk__trim(ctime(&last_change)),
                                            crm_element_value(xml_op, XML_RSC_OP_T_EXEC));
    }

    out->list_item(out, NULL, "%s: %s (node=%s, call=%s, rc=%s%s): %s",
                   node_str, pe__xe_history_key(xml_op),
                   crm_element_value(xml_op, XML_ATTR_UNAME),
                   crm_element_value(xml_op, XML_LRM_ATTR_CALLID),
                   crm_element_value(xml_op, XML_LRM_ATTR_RC),
                   last_change_str ? last_change_str : "",
                   pcmk_exec_status_str(status));

    g_free(node_str);
    free(last_change_str);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-and-op", "pe_working_set_t *", "xmlNodePtr")
static int
node_and_op_xml(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);
    xmlNodePtr xml_op = va_arg(args, xmlNodePtr);

    pe_resource_t *rsc = NULL;
    const char *op_rsc = crm_element_value(xml_op, "resource");
    int status;
    time_t last_change = 0;
    xmlNode *node = NULL;

    pcmk__scan_min_int(crm_element_value(xml_op, XML_LRM_ATTR_OPSTATUS),
                       &status, PCMK_EXEC_UNKNOWN);
    node = pcmk__output_create_xml_node(out, "operation",
                                        "op", pe__xe_history_key(xml_op),
                                        "node", crm_element_value(xml_op, XML_ATTR_UNAME),
                                        "call", crm_element_value(xml_op, XML_LRM_ATTR_CALLID),
                                        "rc", crm_element_value(xml_op, XML_LRM_ATTR_RC),
                                        "status", pcmk_exec_status_str(status),
                                        NULL);

    rsc = pe_find_resource(data_set->resources, op_rsc);

    if (rsc) {
        const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
        const char *kind = crm_element_value(rsc->xml, XML_ATTR_TYPE);
        char *agent_tuple = NULL;

        agent_tuple = crm_strdup_printf("%s:%s:%s", class,
                                        pcmk_is_set(pcmk_get_ra_caps(class), pcmk_ra_cap_provider) ? crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER) : "",
                                        kind);

        pcmk__xe_set_props(node, "rsc", rsc_printable_id(rsc),
                           "agent", agent_tuple,
                           NULL);
        free(agent_tuple);
    }

    if (crm_element_value_epoch(xml_op, XML_RSC_OP_LAST_CHANGE,
                                &last_change) == pcmk_ok) {
        pcmk__xe_set_props(node, XML_RSC_OP_LAST_CHANGE,
                           pcmk__trim(ctime(&last_change)),
                           XML_RSC_OP_T_EXEC, crm_element_value(xml_op, XML_RSC_OP_T_EXEC),
                           NULL);
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

    xmlNodePtr node = pcmk__output_create_xml_node(out, "attribute",
                                                   "name", name,
                                                   "value", value,
                                                   NULL);

    if (add_extra) {
        char *buf = pcmk__itoa(expected_score);
        crm_xml_add(node, "expected", buf);
        free(buf);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-attribute-list", "pe_working_set_t *", "uint32_t",
                  "bool", "GList *", "GList *")
static int
node_attribute_list(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool print_spacer = va_arg(args, int);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    int rc = pcmk_rc_no_output;

    /* Display each node's attributes */
    for (GList *gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = gIter->data;

        GList *attr_list = NULL;
        GHashTableIter iter;
        gpointer key;

        if (!node || !node->details || !node->details->online) {
            continue;
        }

        g_hash_table_iter_init(&iter, node->details->attrs);
        while (g_hash_table_iter_next (&iter, &key, NULL)) {
            attr_list = filter_attr_list(attr_list, key);
        }

        if (attr_list == NULL) {
            continue;
        }

        if (!pcmk__str_in_list(node->details->uname, only_node, pcmk__str_star_matches|pcmk__str_casei)) {
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

            value = pe_node_attribute_raw(node, name);

            add_extra = add_extra_info(node, node->details->running_rsc,
                                       data_set, name, &expected_score);

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

PCMK__OUTPUT_ARGS("node-capacity", "const pe_node_t *", "const char *")
static int
node_capacity(pcmk__output_t *out, va_list args)
{
    const pe_node_t *node = va_arg(args, pe_node_t *);
    const char *comment = va_arg(args, const char *);

    char *dump_text = crm_strdup_printf("%s: %s capacity:",
                                        comment, pe__node_name(node));

    g_hash_table_foreach(node->details->utilization, append_dump_text, &dump_text);
    out->list_item(out, NULL, "%s", dump_text);
    free(dump_text);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-capacity", "const pe_node_t *", "const char *")
static int
node_capacity_xml(pcmk__output_t *out, va_list args)
{
    const pe_node_t *node = va_arg(args, pe_node_t *);
    const char *comment = va_arg(args, const char *);

    xmlNodePtr xml_node = pcmk__output_create_xml_node(out, "capacity",
                                                       "node", node->details->uname,
                                                       "comment", comment,
                                                       NULL);
    g_hash_table_foreach(node->details->utilization, add_dump_node, xml_node);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-history-list", "pe_working_set_t *", "pe_node_t *", "xmlNodePtr",
                  "GList *", "GList *", "uint32_t", "uint32_t")
static int
node_history_list(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);
    pe_node_t *node = va_arg(args, pe_node_t *);
    xmlNode *node_state = va_arg(args, xmlNode *);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);

    xmlNode *lrm_rsc = NULL;
    xmlNode *rsc_entry = NULL;
    int rc = pcmk_rc_no_output;

    lrm_rsc = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
    lrm_rsc = find_xml_node(lrm_rsc, XML_LRM_TAG_RESOURCES, FALSE);

    /* Print history of each of the node's resources */
    for (rsc_entry = first_named_child(lrm_rsc, XML_LRM_TAG_RESOURCE);
         rsc_entry != NULL; rsc_entry = crm_next_same_xml(rsc_entry)) {
        const char *rsc_id = crm_element_value(rsc_entry, XML_ATTR_ID);
        pe_resource_t *rsc = pe_find_resource(data_set->resources, rsc_id);
        const pe_resource_t *parent = pe__const_top_resource(rsc, false);

        /* We can't use is_filtered here to filter group resources.  For is_filtered,
         * we have to decide whether to check the parent or not.  If we check the
         * parent, all elements of a group will always be printed because that's how
         * is_filtered works for groups.  If we do not check the parent, sometimes
         * this will filter everything out.
         *
         * For other resource types, is_filtered is okay.
         */
        if (parent->variant == pe_group) {
            if (!pcmk__str_in_list(rsc_printable_id(rsc), only_rsc,
                                   pcmk__str_star_matches)
                && !pcmk__str_in_list(rsc_printable_id(parent), only_rsc,
                                      pcmk__str_star_matches)) {
                continue;
            }
        } else {
            if (rsc->fns->is_filtered(rsc, only_rsc, TRUE)) {
                continue;
            }
        }

        if (!pcmk_is_set(section_opts, pcmk_section_operations)) {
            time_t last_failure = 0;
            int failcount = pe_get_failcount(node, rsc, &last_failure, pe_fc_default,
                                             NULL);

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
            pe_resource_t *rsc = pe_find_resource(data_set->resources,
                                                  crm_element_value(rsc_entry, XML_ATTR_ID));

            if (op_list == NULL) {
                continue;
            }

            if (rc == pcmk_rc_no_output) {
                rc = pcmk_rc_ok;
                out->message(out, "node", node, show_opts, false, only_node,
                             only_rsc);
            }

            out->message(out, "resource-operation-list", data_set, rsc, node,
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
        pe_node_t *node = (pe_node_t *) gIter->data;

        if (!pcmk__str_in_list(node->details->uname, only_node,
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
        pe_node_t *node = (pe_node_t *) gIter->data;
        char *node_name = pe__node_display_name(node, pcmk_is_set(show_opts, pcmk_show_node_id));

        if (!pcmk__str_in_list(node->details->uname, only_node,
                               pcmk__str_star_matches|pcmk__str_casei)) {
            free(node_name);
            continue;
        }

        PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Node List");

        // Determine whether to display node individually or in a list
        if (node->details->unclean || node->details->pending
            || (node->details->standby_onfail && node->details->online)
            || node->details->standby || node->details->maintenance
            || pcmk_is_set(show_opts, pcmk_show_rscs_by_node)
            || pcmk_is_set(show_opts, pcmk_show_feature_set)
            || (pe__node_health(node) <= 0)) {
            // Display node individually

        } else if (node->details->online) {
            // Display online node in a list
            if (pe__is_guest_node(node)) {
                pcmk__add_word(&online_guest_nodes, 1024, node_name);

            } else if (pe__is_remote_node(node)) {
                pcmk__add_word(&online_remote_nodes, 1024, node_name);

            } else {
                pcmk__add_word(&online_nodes, 1024, node_name);
            }
            free(node_name);
            continue;

        } else {
            // Display offline node in a list
            if (pe__is_remote_node(node)) {
                pcmk__add_word(&offline_remote_nodes, 1024, node_name);

            } else if (pe__is_guest_node(node)) {
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

    out->begin_list(out, NULL, NULL, "nodes");
    for (GList *gIter = nodes; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = (pe_node_t *) gIter->data;

        if (!pcmk__str_in_list(node->details->uname, only_node,
                               pcmk__str_star_matches|pcmk__str_casei)) {
            continue;
        }

        out->message(out, "node", node, show_opts, true, only_node, only_rsc);
    }
    out->end_list(out);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-summary", "pe_working_set_t *", "GList *", "GList *",
                  "uint32_t", "uint32_t", "bool")
static int
node_summary(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool print_spacer = va_arg(args, int);

    xmlNode *node_state = NULL;
    xmlNode *cib_status = pcmk_find_cib_element(data_set->input,
                                                XML_CIB_TAG_STATUS);
    int rc = pcmk_rc_no_output;

    if (xmlChildElementCount(cib_status) == 0) {
        return rc;
    }

    for (node_state = first_named_child(cib_status, XML_CIB_TAG_STATE);
         node_state != NULL; node_state = crm_next_same_xml(node_state)) {
        pe_node_t *node = pe_find_node_id(data_set->nodes, ID(node_state));

        if (!node || !node->details || !node->details->online) {
            continue;
        }

        if (!pcmk__str_in_list(node->details->uname, only_node,
                               pcmk__str_star_matches|pcmk__str_casei)) {
            continue;
        }

        PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc,
                                 pcmk_is_set(section_opts, pcmk_section_operations) ? "Operations" : "Migration Summary");

        out->message(out, "node-history-list", data_set, node, node_state,
                     only_node, only_rsc, section_opts, show_opts);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("node-weight", "const pe_resource_t *", "const char *",
                  "const char *", "const char *")
static int
node_weight(pcmk__output_t *out, va_list args)
{
    const pe_resource_t *rsc = va_arg(args, const pe_resource_t *);
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

PCMK__OUTPUT_ARGS("node-weight", "const pe_resource_t *", "const char *",
                  "const char *", "const char *")
static int
node_weight_xml(pcmk__output_t *out, va_list args)
{
    const pe_resource_t *rsc = va_arg(args, const pe_resource_t *);
    const char *prefix = va_arg(args, const char *);
    const char *uname = va_arg(args, const char *);
    const char *score = va_arg(args, const char *);

    xmlNodePtr node = pcmk__output_create_xml_node(out, "node_weight",
                                                   "function", prefix,
                                                   "node", uname,
                                                   "score", score,
                                                   NULL);

    if (rsc) {
        crm_xml_add(node, "id", rsc->id);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("op-history", "xmlNodePtr", "const char *", "const char *", "int", "uint32_t")
static int
op_history_text(pcmk__output_t *out, va_list args) {
    xmlNodePtr xml_op = va_arg(args, xmlNodePtr);
    const char *task = va_arg(args, const char *);
    const char *interval_ms_s = va_arg(args, const char *);
    int rc = va_arg(args, int);
    uint32_t show_opts = va_arg(args, uint32_t);

    char *buf = op_history_string(xml_op, task, interval_ms_s, rc,
                                  pcmk_is_set(show_opts, pcmk_show_timing));

    out->list_item(out, NULL, "%s", buf);

    free(buf);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("op-history", "xmlNodePtr", "const char *", "const char *", "int", "uint32_t")
static int
op_history_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr xml_op = va_arg(args, xmlNodePtr);
    const char *task = va_arg(args, const char *);
    const char *interval_ms_s = va_arg(args, const char *);
    int rc = va_arg(args, int);
    uint32_t show_opts = va_arg(args, uint32_t);

    char *rc_s = pcmk__itoa(rc);
    xmlNodePtr node = pcmk__output_create_xml_node(out, "operation_history",
                                                   "call", crm_element_value(xml_op, XML_LRM_ATTR_CALLID),
                                                   "task", task,
                                                   "rc", rc_s,
                                                   "rc_text", services_ocf_exitcode_str(rc),
                                                   NULL);
    free(rc_s);

    if (interval_ms_s && !pcmk__str_eq(interval_ms_s, "0", pcmk__str_casei)) {
        char *s = crm_strdup_printf("%sms", interval_ms_s);
        crm_xml_add(node, "interval", s);
        free(s);
    }

    if (pcmk_is_set(show_opts, pcmk_show_timing)) {
        const char *value = NULL;
        time_t epoch = 0;

        if ((crm_element_value_epoch(xml_op, XML_RSC_OP_LAST_CHANGE,
                                     &epoch) == pcmk_ok) && (epoch > 0)) {
            char *s = pcmk__epoch2str(&epoch, 0);
            crm_xml_add(node, XML_RSC_OP_LAST_CHANGE, s);
            free(s);
        }

        value = crm_element_value(xml_op, XML_RSC_OP_T_EXEC);
        if (value) {
            char *s = crm_strdup_printf("%sms", value);
            crm_xml_add(node, XML_RSC_OP_T_EXEC, s);
            free(s);
        }
        value = crm_element_value(xml_op, XML_RSC_OP_T_QUEUE);
        if (value) {
            char *s = crm_strdup_printf("%sms", value);
            crm_xml_add(node, XML_RSC_OP_T_QUEUE, s);
            free(s);
        }
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("promotion-score", "pe_resource_t *", "pe_node_t *", "const char *")
static int
promotion_score(pcmk__output_t *out, va_list args)
{
    pe_resource_t *child_rsc = va_arg(args, pe_resource_t *);
    pe_node_t *chosen = va_arg(args, pe_node_t *);
    const char *score = va_arg(args, const char *);

    out->list_item(out, NULL, "%s promotion score on %s: %s",
                   child_rsc->id,
                   chosen? chosen->details->uname : "none",
                   score);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("promotion-score", "pe_resource_t *", "pe_node_t *", "const char *")
static int
promotion_score_xml(pcmk__output_t *out, va_list args)
{
    pe_resource_t *child_rsc = va_arg(args, pe_resource_t *);
    pe_node_t *chosen = va_arg(args, pe_node_t *);
    const char *score = va_arg(args, const char *);

    xmlNodePtr node = pcmk__output_create_xml_node(out, "promotion_score",
                                                   "id", child_rsc->id,
                                                   "score", score,
                                                   NULL);

    if (chosen) {
        crm_xml_add(node, "node", chosen->details->uname);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("resource-config", "pe_resource_t *", "bool")
static int
resource_config(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    bool raw = va_arg(args, int);

    char *rsc_xml = formatted_xml_buf(rsc, raw);

    out->output_xml(out, "xml", rsc_xml);

    free(rsc_xml);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("resource-config", "pe_resource_t *", "bool")
static int
resource_config_text(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    bool raw = va_arg(args, int);

    char *rsc_xml = formatted_xml_buf(rsc, raw);

    pcmk__formatted_printf(out, "Resource XML:\n");
    out->output_xml(out, "xml", rsc_xml);

    free(rsc_xml);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("resource-history", "pe_resource_t *", "const char *", "bool", "int", "time_t", "bool")
static int
resource_history_text(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
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

PCMK__OUTPUT_ARGS("resource-history", "pe_resource_t *", "const char *", "bool", "int", "time_t", "bool")
static int
resource_history_xml(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    const char *rsc_id = va_arg(args, const char *);
    bool all = va_arg(args, int);
    int failcount = va_arg(args, int);
    time_t last_failure = va_arg(args, time_t);
    bool as_header = va_arg(args, int);

    xmlNodePtr node = pcmk__output_xml_create_parent(out, "resource_history",
                                                     "id", rsc_id,
                                                     NULL);

    if (rsc == NULL) {
        pcmk__xe_set_bool_attr(node, "orphan", true);
    } else if (all || failcount || last_failure > 0) {
        char *migration_s = pcmk__itoa(rsc->migration_threshold);

        pcmk__xe_set_props(node, "orphan", "false",
                           "migration-threshold", migration_s,
                           NULL);
        free(migration_s);

        if (failcount > 0) {
            char *s = pcmk__itoa(failcount);

            crm_xml_add(node, PCMK__FAIL_COUNT_PREFIX, s);
            free(s);
        }

        if (last_failure > 0) {
            char *s = pcmk__epoch2str(&last_failure, 0);

            crm_xml_add(node, PCMK__LAST_FAILURE_PREFIX, s);
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
    if (pcmk_is_set(show_opts, pcmk_show_rscs_by_node)) {
        /* Active resources have already been printed by node */
        out->begin_list(out, NULL, NULL, "Inactive Resources");
    } else if (pcmk_is_set(show_opts, pcmk_show_inactive_rscs)) {
        out->begin_list(out, NULL, NULL, "Full List of Resources");
    } else {
        out->begin_list(out, NULL, NULL, "Active Resources");
    }
}


PCMK__OUTPUT_ARGS("resource-list", "pe_working_set_t *", "uint32_t", "bool",
                  "GList *", "GList *", "bool")
static int
resource_list(pcmk__output_t *out, va_list args)
{
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);
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
    if (pcmk_is_set(show_opts, pcmk_show_rscs_by_node) &&
        !pcmk_is_set(show_opts, pcmk_show_inactive_rscs)) {
        return rc;
    }

    /* If we haven't already printed resources grouped by node,
     * and brief output was requested, print resource summary */
    if (pcmk_is_set(show_opts, pcmk_show_brief) && !pcmk_is_set(show_opts, pcmk_show_rscs_by_node)) {
        GList *rscs = pe__filter_rsc_list(data_set->resources, only_rsc);

        PCMK__OUTPUT_SPACER_IF(out, print_spacer);
        print_resource_header(out, show_opts);
        printed_header = true;

        rc = pe__rscs_brief_output(out, rscs, show_opts);
        g_list_free(rscs);
    }

    /* For each resource, display it if appropriate */
    for (rsc_iter = data_set->resources; rsc_iter != NULL; rsc_iter = rsc_iter->next) {
        pe_resource_t *rsc = (pe_resource_t *) rsc_iter->data;
        int x;

        /* Complex resources may have some sub-resources active and some inactive */
        gboolean is_active = rsc->fns->active(rsc, TRUE);
        gboolean partially_active = rsc->fns->active(rsc, FALSE);

        /* Skip inactive orphans (deleted but still in CIB) */
        if (pcmk_is_set(rsc->flags, pe_rsc_orphan) && !is_active) {
            continue;

        /* Skip active resources if we already displayed them by node */
        } else if (pcmk_is_set(show_opts, pcmk_show_rscs_by_node)) {
            if (is_active) {
                continue;
            }

        /* Skip primitives already counted in a brief summary */
        } else if (pcmk_is_set(show_opts, pcmk_show_brief) && (rsc->variant == pe_native)) {
            continue;

        /* Skip resources that aren't at least partially active,
         * unless we're displaying inactive resources
         */
        } else if (!partially_active && !pcmk_is_set(show_opts, pcmk_show_inactive_rscs)) {
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
        x = out->message(out, crm_map_element_name(rsc->xml), show_opts, rsc,
                         only_node, only_rsc);
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

        if (pcmk_is_set(show_opts, pcmk_show_rscs_by_node)) {
            out->list_item(out, NULL, "No inactive resources");
        } else if (pcmk_is_set(show_opts, pcmk_show_inactive_rscs)) {
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

PCMK__OUTPUT_ARGS("resource-operation-list", "pe_working_set_t *", "pe_resource_t *",
                  "pe_node_t *", "GList *", "uint32_t")
static int
resource_operation_list(pcmk__output_t *out, va_list args)
{
    pe_working_set_t *data_set G_GNUC_UNUSED = va_arg(args, pe_working_set_t *);
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    pe_node_t *node = va_arg(args, pe_node_t *);
    GList *op_list = va_arg(args, GList *);
    uint32_t show_opts = va_arg(args, uint32_t);

    GList *gIter = NULL;
    int rc = pcmk_rc_no_output;

    /* Print each operation */
    for (gIter = op_list; gIter != NULL; gIter = gIter->next) {
        xmlNode *xml_op = (xmlNode *) gIter->data;
        const char *task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
        const char *interval_ms_s = crm_element_value(xml_op,
                                                      XML_LRM_ATTR_INTERVAL_MS);
        const char *op_rc = crm_element_value(xml_op, XML_LRM_ATTR_RC);
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
            int failcount = pe_get_failcount(node, rsc, &last_failure, pe_fc_default,
                                             NULL);

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

PCMK__OUTPUT_ARGS("resource-util", "pe_resource_t *", "pe_node_t *", "const char *")
static int
resource_util(pcmk__output_t *out, va_list args)
{
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    pe_node_t *node = va_arg(args, pe_node_t *);
    const char *fn = va_arg(args, const char *);

    char *dump_text = crm_strdup_printf("%s: %s utilization on %s:",
                                        fn, rsc->id, pe__node_name(node));

    g_hash_table_foreach(rsc->utilization, append_dump_text, &dump_text);
    out->list_item(out, NULL, "%s", dump_text);
    free(dump_text);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("resource-util", "pe_resource_t *", "pe_node_t *", "const char *")
static int
resource_util_xml(pcmk__output_t *out, va_list args)
{
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    pe_node_t *node = va_arg(args, pe_node_t *);
    const char *fn = va_arg(args, const char *);

    xmlNodePtr xml_node = pcmk__output_create_xml_node(out, "utilization",
                                                       "resource", rsc->id,
                                                       "node", node->details->uname,
                                                       "function", fn,
                                                       NULL);
    g_hash_table_foreach(rsc->utilization, add_dump_node, xml_node);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ticket", "pe_ticket_t *")
static int
ticket_html(pcmk__output_t *out, va_list args) {
    pe_ticket_t *ticket = va_arg(args, pe_ticket_t *);

    if (ticket->last_granted > -1) {
        char *epoch_str = pcmk__epoch2str(&(ticket->last_granted), 0);

        out->list_item(out, NULL, "%s:\t%s%s %s=\"%s\"", ticket->id,
                       ticket->granted ? "granted" : "revoked",
                       ticket->standby ? " [standby]" : "",
                       "last-granted", pcmk__s(epoch_str, ""));
        free(epoch_str);
    } else {
        out->list_item(out, NULL, "%s:\t%s%s", ticket->id,
                       ticket->granted ? "granted" : "revoked",
                       ticket->standby ? " [standby]" : "");
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ticket", "pe_ticket_t *")
static int
ticket_text(pcmk__output_t *out, va_list args) {
    pe_ticket_t *ticket = va_arg(args, pe_ticket_t *);

    if (ticket->last_granted > -1) {
        char *epoch_str = pcmk__epoch2str(&(ticket->last_granted), 0);

        out->list_item(out, ticket->id, "%s%s %s=\"%s\"",
                       ticket->granted ? "granted" : "revoked",
                       ticket->standby ? " [standby]" : "",
                       "last-granted", pcmk__s(epoch_str, ""));
        free(epoch_str);
    } else {
        out->list_item(out, ticket->id, "%s%s",
                       ticket->granted ? "granted" : "revoked",
                       ticket->standby ? " [standby]" : "");
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ticket", "pe_ticket_t *")
static int
ticket_xml(pcmk__output_t *out, va_list args) {
    pe_ticket_t *ticket = va_arg(args, pe_ticket_t *);

    xmlNodePtr node = NULL;

    node = pcmk__output_create_xml_node(out, "ticket",
                                        "id", ticket->id,
                                        "status", ticket->granted ? "granted" : "revoked",
                                        "standby", pcmk__btoa(ticket->standby),
                                        NULL);

    if (ticket->last_granted > -1) {
        char *buf = pcmk__epoch2str(&ticket->last_granted, 0);

        crm_xml_add(node, "last-granted", buf);
        free(buf);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ticket-list", "pe_working_set_t *", "bool")
static int
ticket_list(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);
    bool print_spacer = va_arg(args, int);

    GHashTableIter iter;
    gpointer key, value;

    if (g_hash_table_size(data_set->tickets) == 0) {
        return pcmk_rc_no_output;
    }

    PCMK__OUTPUT_SPACER_IF(out, print_spacer);

    /* Print section heading */
    out->begin_list(out, NULL, NULL, "Tickets");

    /* Print each ticket */
    g_hash_table_iter_init(&iter, data_set->tickets);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        pe_ticket_t *ticket = (pe_ticket_t *) value;
        out->message(out, "ticket", ticket);
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
    { "ticket", "default", ticket_text },
    { "ticket", "html", ticket_html },
    { "ticket", "xml", ticket_xml },
    { "ticket-list", "default", ticket_list },

    { NULL, NULL, NULL }
};

void
pe__register_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}
