/*
 * Copyright 2019-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/common/results.h>
#include <crm/common/output_internal.h>
#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/pengine/internal.h>
#include <libxml/tree.h>
#include <pacemaker-internal.h>

pcmk__supported_format_t pcmk__out_formats[] = {
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

int
pcmk__out_prologue(pcmk__output_t **out, xmlNodePtr *xml) {
    int rc = pcmk_rc_ok;

    if (*xml != NULL) {
        xmlFreeNode(*xml);
    }

    pcmk__register_formats(NULL, pcmk__out_formats);
    rc = pcmk__output_new(out, "xml", NULL, NULL);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    return rc;
}

void
pcmk__out_epilogue(pcmk__output_t *out, xmlNodePtr *xml, int retval) {
    if (retval == pcmk_rc_ok) {
        out->finish(out, 0, FALSE, (void **) xml);
    }

    pcmk__output_free(out);
}

static char *
colocations_header(pe_resource_t *rsc, pcmk__colocation_t *cons,
                   gboolean dependents) {
    char *score = NULL;
    char *retval = NULL;

    score = score2char(cons->score);
    if (cons->role_rh > RSC_ROLE_STARTED) {
            retval = crm_strdup_printf("%s (score=%s, %s role=%s, id=%s)",
                                       rsc->id, score, dependents ? "needs" : "with",
                                       role2text(cons->role_rh), cons->id);
    } else {
        retval = crm_strdup_printf("%s (score=%s, id=%s)",
                                   rsc->id, score, cons->id);
    }

    free(score);
    return retval;
}

static void
colocations_xml_node(pcmk__output_t *out, pe_resource_t *rsc,
                     pcmk__colocation_t *cons) {
    char *score = NULL;
    xmlNodePtr node = NULL;

    score = score2char(cons->score);
    node = pcmk__output_create_xml_node(out, XML_CONS_TAG_RSC_DEPEND,
                                        "id", cons->id,
                                        "rsc", cons->rsc_lh->id,
                                        "with-rsc", cons->rsc_rh->id,
                                        "score", score,
                                        NULL);

    if (cons->node_attribute) {
        xmlSetProp(node, (pcmkXmlStr) "node-attribute", (pcmkXmlStr) cons->node_attribute);
    }

    if (cons->role_lh != RSC_ROLE_UNKNOWN) {
        xmlSetProp(node, (pcmkXmlStr) "rsc-role", (pcmkXmlStr) role2text(cons->role_lh));
    }

    if (cons->role_rh != RSC_ROLE_UNKNOWN) {
        xmlSetProp(node, (pcmkXmlStr) "with-rsc-role", (pcmkXmlStr) role2text(cons->role_rh));
    }

    free(score);
}

static int
do_locations_list_xml(pcmk__output_t *out, pe_resource_t *rsc, bool add_header)
{
    GList *lpc = NULL;
    GList *list = rsc->rsc_location;
    int rc = pcmk_rc_no_output;

    for (lpc = list; lpc != NULL; lpc = lpc->next) {
        pe__location_t *cons = lpc->data;

        GList *lpc2 = NULL;

        for (lpc2 = cons->node_list_rh; lpc2 != NULL; lpc2 = lpc2->next) {
            pe_node_t *node = (pe_node_t *) lpc2->data;
            char *score = score2char(node->weight);

            if (add_header) {
                PCMK__OUTPUT_LIST_HEADER(out, FALSE, rc, "locations");
            }

            pcmk__output_create_xml_node(out, XML_CONS_TAG_RSC_LOCATION,
                                         "node", node->details->uname,
                                         "rsc", rsc->id,
                                         "id", cons->id,
                                         "score", score,
                                         NULL);
            free(score);
        }
    }

    if (add_header) {
        PCMK__OUTPUT_LIST_FOOTER(out, rc);
    }

    return rc;
}

PCMK__OUTPUT_ARGS("rsc-is-colocated-with-list", "pe_resource_t *", "gboolean")
static int
rsc_is_colocated_with_list(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    gboolean recursive = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        return rc;
    }

    pe__set_resource_flags(rsc, pe_rsc_allocating);
    for (GList *lpc = rsc->rsc_cons; lpc != NULL; lpc = lpc->next) {
        pcmk__colocation_t *cons = (pcmk__colocation_t *) lpc->data;
        char *hdr = NULL;

        PCMK__OUTPUT_LIST_HEADER(out, FALSE, rc, "Resources %s is colocated with", rsc->id);

        if (pcmk_is_set(cons->rsc_rh->flags, pe_rsc_allocating)) {
            out->list_item(out, NULL, "%s (id=%s - loop)", cons->rsc_rh->id, cons->id);
            continue;
        }

        hdr = colocations_header(cons->rsc_rh, cons, FALSE);
        out->list_item(out, NULL, "%s", hdr);
        free(hdr);

        /* Empty list header just for indentation of information about this resource. */
        out->begin_list(out, NULL, NULL, NULL);

        out->message(out, "locations-list", cons->rsc_rh);
        if (recursive) {
            out->message(out, "rsc-is-colocated-with-list", cons->rsc_rh, recursive);
        }

        out->end_list(out);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("rsc-is-colocated-with-list", "pe_resource_t *", "gboolean")
static int
rsc_is_colocated_with_list_xml(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    gboolean recursive = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        return rc;
    }

    pe__set_resource_flags(rsc, pe_rsc_allocating);
    for (GList *lpc = rsc->rsc_cons; lpc != NULL; lpc = lpc->next) {
        pcmk__colocation_t *cons = (pcmk__colocation_t *) lpc->data;

        if (pcmk_is_set(cons->rsc_rh->flags, pe_rsc_allocating)) {
            colocations_xml_node(out, cons->rsc_rh, cons);
            continue;
        }

        colocations_xml_node(out, cons->rsc_rh, cons);
        do_locations_list_xml(out, cons->rsc_rh, false);

        if (recursive) {
            out->message(out, "rsc-is-colocated-with-list", cons->rsc_rh, recursive);
        }
    }

    return rc;
}

PCMK__OUTPUT_ARGS("rscs-colocated-with-list", "pe_resource_t *", "gboolean")
static int
rscs_colocated_with_list(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    gboolean recursive = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        return rc;
    }

    pe__set_resource_flags(rsc, pe_rsc_allocating);
    for (GList *lpc = rsc->rsc_cons_lhs; lpc != NULL; lpc = lpc->next) {
        pcmk__colocation_t *cons = (pcmk__colocation_t *) lpc->data;
        char *hdr = NULL;

        PCMK__OUTPUT_LIST_HEADER(out, FALSE, rc, "Resources colocated with %s", rsc->id);

        if (pcmk_is_set(cons->rsc_lh->flags, pe_rsc_allocating)) {
            out->list_item(out, NULL, "%s (id=%s - loop)", cons->rsc_lh->id, cons->id);
            continue;
        }

        hdr = colocations_header(cons->rsc_lh, cons, TRUE);
        out->list_item(out, NULL, "%s", hdr);
        free(hdr);

        /* Empty list header just for indentation of information about this resource. */
        out->begin_list(out, NULL, NULL, NULL);

        out->message(out, "locations-list", cons->rsc_lh);
        if (recursive) {
            out->message(out, "rscs-colocated-with-list", cons->rsc_lh, recursive);
        }

        out->end_list(out);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("rscs-colocated-with-list", "pe_resource_t *", "gboolean")
static int
rscs_colocated_with_list_xml(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    gboolean recursive = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        return rc;
    }

    pe__set_resource_flags(rsc, pe_rsc_allocating);
    for (GList *lpc = rsc->rsc_cons_lhs; lpc != NULL; lpc = lpc->next) {
        pcmk__colocation_t *cons = (pcmk__colocation_t *) lpc->data;

        if (pcmk_is_set(cons->rsc_lh->flags, pe_rsc_allocating)) {
            colocations_xml_node(out, cons->rsc_lh, cons);
            continue;
        }

        colocations_xml_node(out, cons->rsc_lh, cons);
        do_locations_list_xml(out, cons->rsc_lh, false);

        if (recursive) {
            out->message(out, "rscs-colocated-with-list", cons->rsc_lh, recursive);
        }
    }

    return rc;
}

PCMK__OUTPUT_ARGS("locations-list", "pe_resource_t *")
static int
locations_list(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);

    GList *lpc = NULL;
    GList *list = rsc->rsc_location;
    int rc = pcmk_rc_no_output;

    for (lpc = list; lpc != NULL; lpc = lpc->next) {
        pe__location_t *cons = lpc->data;

        GList *lpc2 = NULL;

        for (lpc2 = cons->node_list_rh; lpc2 != NULL; lpc2 = lpc2->next) {
            pe_node_t *node = (pe_node_t *) lpc2->data;
            char *score = score2char(node->weight);

            PCMK__OUTPUT_LIST_HEADER(out, FALSE, rc, "Locations");
            out->list_item(out, NULL, "Node %s (score=%s, id=%s, rsc=%s)",
                           node->details->uname, score, cons->id, rsc->id);
            free(score);
        }
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("locations-list", "pe_resource_t *")
static int
locations_list_xml(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    return do_locations_list_xml(out, rsc, true);
}

PCMK__OUTPUT_ARGS("stacks-constraints", "pe_resource_t *", "pe_working_set_t *", "gboolean")
static int
stacks_and_constraints(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);
    gboolean recursive = va_arg(args, gboolean);

    xmlNodePtr cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS,
                                                 data_set->input);

    unpack_constraints(cib_constraints, data_set);

    // Constraints apply to group/clone, not member/instance
    rsc = uber_parent(rsc);

    out->message(out, "locations-list", rsc);

    pe__clear_resource_flags_on_all(data_set, pe_rsc_allocating);
    out->message(out, "rscs-colocated-with-list", rsc, recursive);

    pe__clear_resource_flags_on_all(data_set, pe_rsc_allocating);
    out->message(out, "rsc-is-colocated-with-list", rsc, recursive);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("stacks-constraints", "pe_resource_t *", "pe_working_set_t *", "gboolean")
static int
stacks_and_constraints_xml(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);
    gboolean recursive = va_arg(args, gboolean);

    xmlNodePtr cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS,
                                                 data_set->input);

    unpack_constraints(cib_constraints, data_set);

    // Constraints apply to group/clone, not member/instance
    rsc = uber_parent(rsc);

    pcmk__output_xml_create_parent(out, "constraints", NULL);
    do_locations_list_xml(out, rsc, false);

    pe__clear_resource_flags_on_all(data_set, pe_rsc_allocating);
    out->message(out, "rscs-colocated-with-list", rsc, recursive);

    pe__clear_resource_flags_on_all(data_set, pe_rsc_allocating);
    out->message(out, "rsc-is-colocated-with-list", rsc, recursive);

    pcmk__output_xml_pop_parent(out);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("health", "const char *", "const char *", "const char *", "const char *")
static int
health_text(pcmk__output_t *out, va_list args)
{
    const char *sys_from = va_arg(args, const char *);
    const char *host_from = va_arg(args, const char *);
    const char *fsa_state = va_arg(args, const char *);
    const char *result = va_arg(args, const char *);

    if (!out->is_quiet(out)) {
        out->info(out, "Status of %s@%s: %s (%s)", crm_str(sys_from),
                       crm_str(host_from), crm_str(fsa_state), crm_str(result));
    } else if (fsa_state != NULL) {
        out->info(out, "%s", fsa_state);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("health", "const char *", "const char *", "const char *", "const char *")
static int
health_xml(pcmk__output_t *out, va_list args)
{
    const char *sys_from = va_arg(args, const char *);
    const char *host_from = va_arg(args, const char *);
    const char *fsa_state = va_arg(args, const char *);
    const char *result = va_arg(args, const char *);

    pcmk__output_create_xml_node(out, crm_str(sys_from),
                                 "node_name", crm_str(host_from),
                                 "state", crm_str(fsa_state),
                                 "result", crm_str(result),
                                 NULL);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("pacemakerd-health", "const char *", "const char *", "const char *")
static int
pacemakerd_health_text(pcmk__output_t *out, va_list args)
{
    const char *sys_from = va_arg(args, const char *);
    const char *state = va_arg(args, const char *);
    const char *last_updated = va_arg(args, const char *);

    if (!out->is_quiet(out)) {
        out->info(out, "Status of %s: '%s' %s %s", crm_str(sys_from),
                  crm_str(state), (!pcmk__str_empty(last_updated))?
                  "last updated":"", crm_str(last_updated));
    } else {
        out->info(out, "%s", crm_str(state));
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("pacemakerd-health", "const char *", "const char *", "const char *")
static int
pacemakerd_health_xml(pcmk__output_t *out, va_list args)
{
    const char *sys_from = va_arg(args, const char *);
    const char *state = va_arg(args, const char *);
    const char *last_updated = va_arg(args, const char *);

    pcmk__output_create_xml_node(out, crm_str(sys_from),
                                 "state", crm_str(state),
                                 "last_updated", crm_str(last_updated),
                                 NULL);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("dc", "const char *")
static int
dc_text(pcmk__output_t *out, va_list args)
{
    const char *dc = va_arg(args, const char *);

    if (!out->is_quiet(out)) {
        out->info(out, "Designated Controller is: %s", crm_str(dc));
    } else if (dc != NULL) {
        out->info(out, "%s", dc);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("dc", "const char *")
static int
dc_xml(pcmk__output_t *out, va_list args)
{
    const char *dc = va_arg(args, const char *);

    pcmk__output_create_xml_node(out, "dc",
                                 "node_name", crm_str(dc),
                                 NULL);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("crmadmin-node", "const char *", "const char *", "const char *", "gboolean")
static int
crmadmin_node_text(pcmk__output_t *out, va_list args)
{
    const char *type = va_arg(args, const char *);
    const char *name = va_arg(args, const char *);
    const char *id = va_arg(args, const char *);
    gboolean BASH_EXPORT = va_arg(args, gboolean);

    if (out->is_quiet(out)) {
        out->info(out, "%s", crm_str(name));
    } else if (BASH_EXPORT) {
        out->info(out, "export %s=%s", crm_str(name), crm_str(id));
    } else {
        out->info(out, "%s node: %s (%s)", type ? type : "member",
                  crm_str(name), crm_str(id));
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("crmadmin-node", "const char *", "const char *", "const char *", "gboolean")
static int
crmadmin_node_xml(pcmk__output_t *out, va_list args)
{
    const char *type = va_arg(args, const char *);
    const char *name = va_arg(args, const char *);
    const char *id = va_arg(args, const char *);

    pcmk__output_create_xml_node(out, "node",
                                 "type", type ? type : "member",
                                 "name", crm_str(name),
                                 "id", crm_str(id),
                                 NULL);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("digests", "pe_resource_t *", "pe_node_t *", "const char *",
                  "guint", "op_digest_cache_t *")
static int
digests_text(pcmk__output_t *out, va_list args)
{
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    pe_node_t *node = va_arg(args, pe_node_t *);
    const char *task = va_arg(args, const char *);
    guint interval_ms = va_arg(args, guint);
    op_digest_cache_t *digests = va_arg(args, op_digest_cache_t *);

    char *action_desc = NULL;
    const char *rsc_desc = "unknown resource";
    const char *node_desc = "unknown node";

    if (interval_ms != 0) {
        action_desc = crm_strdup_printf("%ums-interval %s action", interval_ms,
                                        ((task == NULL)? "unknown" : task));
    } else if (pcmk__str_eq(task, "monitor", pcmk__str_none)) {
        action_desc = strdup("probe action");
    } else {
        action_desc = crm_strdup_printf("%s action",
                                        ((task == NULL)? "unknown" : task));
    }
    if ((rsc != NULL) && (rsc->id != NULL)) {
        rsc_desc = rsc->id;
    }
    if ((node != NULL) && (node->details->uname != NULL)) {
        node_desc = node->details->uname;
    }
    out->begin_list(out, NULL, NULL, "Digests for %s %s on %s",
                    rsc_desc, action_desc, node_desc);
    free(action_desc);

    if (digests == NULL) {
        out->list_item(out, NULL, "none");
        out->end_list(out);
        return pcmk_rc_ok;
    }
    if (digests->digest_all_calc != NULL) {
        out->list_item(out, NULL, "%s (all parameters)",
                       digests->digest_all_calc);
    }
    if (digests->digest_secure_calc != NULL) {
        out->list_item(out, NULL, "%s (non-private parameters)",
                       digests->digest_secure_calc);
    }
    if (digests->digest_restart_calc != NULL) {
        out->list_item(out, NULL, "%s (non-reloadable parameters)",
                       digests->digest_restart_calc);
    }
    out->end_list(out);
    return pcmk_rc_ok;
}

static void
add_digest_xml(xmlNode *parent, const char *type, const char *digest,
               xmlNode *digest_source)
{
    if (digest != NULL) {
        xmlNodePtr digest_xml = create_xml_node(parent, "digest");

        crm_xml_add(digest_xml, "type", ((type == NULL)? "unspecified" : type));
        crm_xml_add(digest_xml, "hash", digest);
        if (digest_source != NULL) {
            add_node_copy(digest_xml, digest_source);
        }
    }
}

PCMK__OUTPUT_ARGS("digests", "pe_resource_t *", "pe_node_t *", "const char *",
                  "guint", "op_digest_cache_t *")
static int
digests_xml(pcmk__output_t *out, va_list args)
{
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    pe_node_t *node = va_arg(args, pe_node_t *);
    const char *task = va_arg(args, const char *);
    guint interval_ms = va_arg(args, guint);
    op_digest_cache_t *digests = va_arg(args, op_digest_cache_t *);

    char *interval_s = crm_strdup_printf("%ums", interval_ms);
    xmlNode *xml = NULL;

    xml = pcmk__output_create_xml_node(out, "digests",
                                       "resource", crm_str(rsc->id),
                                       "node", crm_str(node->details->uname),
                                       "task", crm_str(task),
                                       "interval", interval_s,
                                       NULL);
    free(interval_s);
    if (digests != NULL) {
        add_digest_xml(xml, "all", digests->digest_all_calc,
                       digests->params_all);
        add_digest_xml(xml, "nonprivate", digests->digest_secure_calc,
                       digests->params_secure);
        add_digest_xml(xml, "nonreloadable", digests->digest_restart_calc,
                       digests->params_restart);
    }
    return pcmk_rc_ok;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "rsc-is-colocated-with-list", "default", rsc_is_colocated_with_list },
    { "rsc-is-colocated-with-list", "xml", rsc_is_colocated_with_list_xml },
    { "rscs-colocated-with-list", "default", rscs_colocated_with_list },
    { "rscs-colocated-with-list", "xml", rscs_colocated_with_list_xml },
    { "locations-list", "default", locations_list },
    { "locations-list", "xml", locations_list_xml },
    { "stacks-constraints", "default", stacks_and_constraints },
    { "stacks-constraints", "xml", stacks_and_constraints_xml },
    { "health", "default", health_text },
    { "health", "xml", health_xml },
    { "pacemakerd-health", "default", pacemakerd_health_text },
    { "pacemakerd-health", "xml", pacemakerd_health_xml },
    { "dc", "default", dc_text },
    { "dc", "xml", dc_xml },
    { "crmadmin-node", "default", crmadmin_node_text },
    { "crmadmin-node", "xml", crmadmin_node_xml },
    { "digests", "default", digests_text },
    { "digests", "xml", digests_xml },

    { NULL, NULL, NULL }
};

void
pcmk__register_lib_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}
