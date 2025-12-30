/*
 * Copyright 2019-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/common/output.h>
#include <crm/common/results.h>
#include <crm/common/xml.h>
#include <crm/stonith-ng.h>         // stonith_history_t
#include <crm/fencing/internal.h>   // stonith__*
#include <crm/pengine/internal.h>
#include <libxml/tree.h>
#include <pacemaker-internal.h>

#include <inttypes.h>
#include <stdint.h>

static char *
colocations_header(pcmk_resource_t *rsc, pcmk__colocation_t *cons,
                   bool dependents) {
    char *retval = NULL;

    if (cons->primary_role > pcmk_role_started) {
        retval = pcmk__assert_asprintf("%s (score=%s, %s role=%s, id=%s)",
                                       rsc->id,
                                       pcmk_readable_score(cons->score),
                                       (dependents? "needs" : "with"),
                                       pcmk_role_text(cons->primary_role),
                                       cons->id);
    } else {
        retval = pcmk__assert_asprintf("%s (score=%s, id=%s)",
                                       rsc->id,
                                       pcmk_readable_score(cons->score),
                                       cons->id);
    }
    return retval;
}

static void
colocations_xml_node(pcmk__output_t *out, pcmk_resource_t *rsc,
                     pcmk__colocation_t *cons) {
    const char *score = pcmk_readable_score(cons->score);
    const char *dependent_role = NULL;
    const char *primary_role = NULL;

    if (cons->dependent_role != pcmk_role_unknown) {
        dependent_role = pcmk_role_text(cons->dependent_role);
    }
    if (cons->primary_role != pcmk_role_unknown) {
        primary_role = pcmk_role_text(cons->primary_role);
    }

    pcmk__output_create_xml_node(out, PCMK_XE_RSC_COLOCATION,
                                 PCMK_XA_ID, cons->id,
                                 PCMK_XA_RSC, cons->dependent->id,
                                 PCMK_XA_WITH_RSC, cons->primary->id,
                                 PCMK_XA_SCORE, score,
                                 PCMK_XA_NODE_ATTRIBUTE, cons->node_attribute,
                                 PCMK_XA_RSC_ROLE, dependent_role,
                                 PCMK_XA_WITH_RSC_ROLE, primary_role,
                                 NULL);
}

static int
do_locations_list_xml(pcmk__output_t *out, pcmk_resource_t *rsc,
                      bool add_header)
{
    GList *lpc = NULL;
    int rc = pcmk_rc_no_output;

    for (lpc = rsc->priv->location_constraints;
         lpc != NULL; lpc = lpc->next) {
        pcmk__location_t *cons = lpc->data;

        GList *lpc2 = NULL;

        for (lpc2 = cons->nodes; lpc2 != NULL; lpc2 = lpc2->next) {
            pcmk_node_t *node = (pcmk_node_t *) lpc2->data;

            if (add_header) {
                PCMK__OUTPUT_LIST_HEADER(out, false, rc, "locations");
            }

            pcmk__output_create_xml_node(out, PCMK_XE_RSC_LOCATION,
                                         PCMK_XA_NODE, node->priv->name,
                                         PCMK_XA_RSC, rsc->id,
                                         PCMK_XA_ID, cons->id,
                                         PCMK_XA_SCORE,
                                         pcmk_readable_score(node->assign->score),
                                         NULL);
        }
    }

    if (add_header) {
        PCMK__OUTPUT_LIST_FOOTER(out, rc);
    }

    return rc;
}

PCMK__OUTPUT_ARGS("rsc-action-item", "const char *", "pcmk_resource_t *",
                  "pcmk_node_t *", "pcmk_node_t *", "pcmk_action_t *",
                  "pcmk_action_t *")
static int
rsc_action_item(pcmk__output_t *out, va_list args)
{
    const char *change = va_arg(args, const char *);
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    pcmk_node_t *origin = va_arg(args, pcmk_node_t *);
    pcmk_node_t *destination = va_arg(args, pcmk_node_t *);
    pcmk_action_t *action = va_arg(args, pcmk_action_t *);
    pcmk_action_t *source = va_arg(args, pcmk_action_t *);

    int len = 0;
    char *reason = NULL;
    char *details = NULL;
    bool same_host = false;
    bool same_role = false;
    bool need_role = false;

    static int rsc_width = 5;
    static int detail_width = 5;

    pcmk__assert((action != NULL)
                 && ((destination != NULL) || (origin != NULL)));

    if (source == NULL) {
        source = action;
    }

    len = strlen(rsc->id);
    if (len > rsc_width) {
        rsc_width = len + 2;
    }

    if ((rsc->priv->orig_role > pcmk_role_started)
        || (rsc->priv->next_role > pcmk_role_unpromoted)) {
        need_role = true;
    }

    if (pcmk__same_node(origin, destination)) {
        same_host = true;
    }

    if (rsc->priv->orig_role == rsc->priv->next_role) {
        same_role = true;
    }

    if (need_role && (origin == NULL)) {
        /* Starting and promoting a promotable clone instance */
        details = pcmk__assert_asprintf("%s -> %s %s",
                                        pcmk_role_text(rsc->priv->orig_role),
                                        pcmk_role_text(rsc->priv->next_role),
                                        pcmk__node_name(destination));

    } else if (origin == NULL) {
        /* Starting a resource */
        details = pcmk__assert_asprintf("%s", pcmk__node_name(destination));

    } else if (need_role && (destination == NULL)) {
        /* Stopping a promotable clone instance */
        details = pcmk__assert_asprintf("%s %s",
                                        pcmk_role_text(rsc->priv->orig_role),
                                        pcmk__node_name(origin));

    } else if (destination == NULL) {
        /* Stopping a resource */
        details = pcmk__assert_asprintf("%s", pcmk__node_name(origin));

    } else if (need_role && same_role && same_host) {
        /* Recovering, restarting or re-promoting a promotable clone instance */
        details = pcmk__assert_asprintf("%s %s",
                                        pcmk_role_text(rsc->priv->orig_role),
                                        pcmk__node_name(origin));

    } else if (same_role && same_host) {
        /* Recovering or Restarting a normal resource */
        details = pcmk__assert_asprintf("%s", pcmk__node_name(origin));

    } else if (need_role && same_role) {
        /* Moving a promotable clone instance */
        details = pcmk__assert_asprintf("%s -> %s %s", pcmk__node_name(origin),
                                        pcmk__node_name(destination),
                                        pcmk_role_text(rsc->priv->orig_role));

    } else if (same_role) {
        /* Moving a normal resource */
        details = pcmk__assert_asprintf("%s -> %s", pcmk__node_name(origin),
                                        pcmk__node_name(destination));

    } else if (same_host) {
        /* Promoting or demoting a promotable clone instance */
        details = pcmk__assert_asprintf("%s -> %s %s",
                                        pcmk_role_text(rsc->priv->orig_role),
                                        pcmk_role_text(rsc->priv->next_role),
                                        pcmk__node_name(origin));

    } else {
        /* Moving and promoting/demoting */
        details = pcmk__assert_asprintf("%s %s -> %s %s",
                                        pcmk_role_text(rsc->priv->orig_role),
                                        pcmk__node_name(origin),
                                        pcmk_role_text(rsc->priv->next_role),
                                        pcmk__node_name(destination));
    }

    len = strlen(details);
    if (len > detail_width) {
        detail_width = len;
    }

    if ((source->reason != NULL)
        && !pcmk__is_set(action->flags, pcmk__action_runnable)) {
        reason = pcmk__assert_asprintf("due to %s (blocked)", source->reason);

    } else if (source->reason) {
        reason = pcmk__assert_asprintf("due to %s", source->reason);

    } else if (!pcmk__is_set(action->flags, pcmk__action_runnable)) {
        reason = strdup("blocked");

    }

    out->list_item(out, NULL, "%-8s   %-*s   ( %*s )%s%s",
                   change, rsc_width, rsc->id, detail_width, details,
                   ((reason == NULL)? "" : "  "), pcmk__s(reason, ""));

    free(details);
    free(reason);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("rsc-action-item", "const char *", "pcmk_resource_t *",
                  "pcmk_node_t *", "pcmk_node_t *", "pcmk_action_t *",
                  "pcmk_action_t *")
static int
rsc_action_item_xml(pcmk__output_t *out, va_list args)
{
    const char *change = va_arg(args, const char *);
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    pcmk_node_t *origin = va_arg(args, pcmk_node_t *);
    pcmk_node_t *destination = va_arg(args, pcmk_node_t *);
    pcmk_action_t *action = va_arg(args, pcmk_action_t *);
    pcmk_action_t *source = va_arg(args, pcmk_action_t *);

    char *change_str = NULL;

    bool same_host = false;
    bool same_role = false;
    bool need_role = false;
    xmlNode *xml = NULL;

    pcmk__assert((action != NULL)
                 && ((destination != NULL) || (origin != NULL)));

    if (source == NULL) {
        source = action;
    }

    if ((rsc->priv->orig_role > pcmk_role_started)
        || (rsc->priv->next_role > pcmk_role_unpromoted)) {
        need_role = true;
    }

    if (pcmk__same_node(origin, destination)) {
        same_host = true;
    }

    if (rsc->priv->orig_role == rsc->priv->next_role) {
        same_role = true;
    }

    change_str = g_ascii_strdown(change, -1);
    xml = pcmk__output_create_xml_node(out, PCMK_XE_RSC_ACTION,
                                       PCMK_XA_ACTION, change_str,
                                       PCMK_XA_RESOURCE, rsc->id,
                                       NULL);
    g_free(change_str);

    if (need_role && (origin == NULL)) {
        /* Starting and promoting a promotable clone instance */
        pcmk__xe_set(xml, PCMK_XA_ROLE, pcmk_role_text(rsc->priv->orig_role));
        pcmk__xe_set(xml, PCMK_XA_NEXT_ROLE,
                     pcmk_role_text(rsc->priv->next_role));
        pcmk__xe_set(xml, PCMK_XA_DEST, destination->priv->name);

    } else if (origin == NULL) {
        /* Starting a resource */
        pcmk__xe_set(xml, PCMK_XA_NODE, destination->priv->name);

    } else if (need_role && (destination == NULL)) {
        /* Stopping a promotable clone instance */
        pcmk__xe_set(xml, PCMK_XA_ROLE, pcmk_role_text(rsc->priv->orig_role));
        pcmk__xe_set(xml, PCMK_XA_NODE, origin->priv->name);

    } else if (destination == NULL) {
        /* Stopping a resource */
        pcmk__xe_set(xml, PCMK_XA_NODE, origin->priv->name);

    } else if (need_role && same_role && same_host) {
        /* Recovering, restarting or re-promoting a promotable clone instance */
        pcmk__xe_set(xml, PCMK_XA_ROLE, pcmk_role_text(rsc->priv->orig_role));
        pcmk__xe_set(xml, PCMK_XA_SOURCE, origin->priv->name);

    } else if (same_role && same_host) {
        /* Recovering or Restarting a normal resource */
        pcmk__xe_set(xml, PCMK_XA_SOURCE, origin->priv->name);

    } else if (need_role && same_role) {
        /* Moving a promotable clone instance */
        pcmk__xe_set(xml, PCMK_XA_SOURCE, origin->priv->name);
        pcmk__xe_set(xml, PCMK_XA_DEST, destination->priv->name);
        pcmk__xe_set(xml, PCMK_XA_ROLE, pcmk_role_text(rsc->priv->orig_role));

    } else if (same_role) {
        /* Moving a normal resource */
        pcmk__xe_set(xml, PCMK_XA_SOURCE, origin->priv->name);
        pcmk__xe_set(xml, PCMK_XA_DEST, destination->priv->name);

    } else if (same_host) {
        /* Promoting or demoting a promotable clone instance */
        pcmk__xe_set(xml, PCMK_XA_ROLE, pcmk_role_text(rsc->priv->orig_role));
        pcmk__xe_set(xml, PCMK_XA_NEXT_ROLE,
                     pcmk_role_text(rsc->priv->next_role));
        pcmk__xe_set(xml, PCMK_XA_SOURCE, origin->priv->name);

    } else {
        /* Moving and promoting/demoting */
        pcmk__xe_set(xml, PCMK_XA_ROLE, pcmk_role_text(rsc->priv->orig_role));
        pcmk__xe_set(xml, PCMK_XA_SOURCE, origin->priv->name);
        pcmk__xe_set(xml, PCMK_XA_NEXT_ROLE,
                     pcmk_role_text(rsc->priv->next_role));
        pcmk__xe_set(xml, PCMK_XA_DEST, destination->priv->name);
    }

    if ((source->reason != NULL)
        && !pcmk__is_set(action->flags, pcmk__action_runnable)) {

        pcmk__xe_set(xml,PCMK_XA_REASON, source->reason);
        pcmk__xe_set(xml, PCMK_XA_BLOCKED, PCMK_VALUE_TRUE);

    } else if (source->reason != NULL) {
        pcmk__xe_set(xml, PCMK_XA_REASON, source->reason);

    } else if (!pcmk__is_set(action->flags, pcmk__action_runnable)) {
        pcmk__xe_set_bool(xml, PCMK_XA_BLOCKED, true);

    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("rsc-is-colocated-with-list", "pcmk_resource_t *", "bool")
static int
rsc_is_colocated_with_list(pcmk__output_t *out, va_list args) {
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    bool recursive = va_arg(args, int);

    int rc = pcmk_rc_no_output;

    if (pcmk__is_set(rsc->flags, pcmk__rsc_detect_loop)) {
        return rc;
    }

    /* We're listing constraints explicitly involving rsc, so use
     * rsc->private->this_with_colocations directly rather than call
     * rsc->private->cmds->this_with_colocations().
     */
    pcmk__set_rsc_flags(rsc, pcmk__rsc_detect_loop);
    for (GList *lpc = rsc->priv->this_with_colocations;
         lpc != NULL; lpc = lpc->next) {
        pcmk__colocation_t *cons = (pcmk__colocation_t *) lpc->data;
        char *hdr = NULL;

        PCMK__OUTPUT_LIST_HEADER(out, false, rc,
                                 "Resources %s is colocated with", rsc->id);

        if (pcmk__is_set(cons->primary->flags, pcmk__rsc_detect_loop)) {
            out->list_item(out, NULL, "%s (id=%s - loop)",
                           cons->primary->id, cons->id);
            continue;
        }

        hdr = colocations_header(cons->primary, cons, false);
        out->list_item(out, NULL, "%s", hdr);
        free(hdr);

        // Empty list header for indentation of information about this resource
        out->begin_list(out, NULL, NULL, NULL);

        out->message(out, "locations-list", cons->primary);
        if (recursive) {
            out->message(out, "rsc-is-colocated-with-list",
                         cons->primary, recursive);
        }

        out->end_list(out);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("rsc-is-colocated-with-list", "pcmk_resource_t *", "bool")
static int
rsc_is_colocated_with_list_xml(pcmk__output_t *out, va_list args) {
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    bool recursive = va_arg(args, int);

    int rc = pcmk_rc_no_output;

    if (pcmk__is_set(rsc->flags, pcmk__rsc_detect_loop)) {
        return rc;
    }

    /* We're listing constraints explicitly involving rsc, so use
     * rsc->private->this_with_colocations directly rather than call
     * rsc->private->cmds->this_with_colocations().
     */
    pcmk__set_rsc_flags(rsc, pcmk__rsc_detect_loop);
    for (GList *lpc = rsc->priv->this_with_colocations;
         lpc != NULL; lpc = lpc->next) {
        pcmk__colocation_t *cons = (pcmk__colocation_t *) lpc->data;

        if (pcmk__is_set(cons->primary->flags, pcmk__rsc_detect_loop)) {
            colocations_xml_node(out, cons->primary, cons);
            continue;
        }

        colocations_xml_node(out, cons->primary, cons);
        do_locations_list_xml(out, cons->primary, false);

        if (recursive) {
            out->message(out, "rsc-is-colocated-with-list",
                         cons->primary, recursive);
        }
    }

    return rc;
}

PCMK__OUTPUT_ARGS("rscs-colocated-with-list", "pcmk_resource_t *", "bool")
static int
rscs_colocated_with_list(pcmk__output_t *out, va_list args) {
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    bool recursive = va_arg(args, int);

    int rc = pcmk_rc_no_output;

    if (pcmk__is_set(rsc->flags, pcmk__rsc_detect_loop)) {
        return rc;
    }

    /* We're listing constraints explicitly involving rsc, so use
     * rsc->private->with_this_colocations directly rather than
     * rsc->private->cmds->with_this_colocations().
     */
    pcmk__set_rsc_flags(rsc, pcmk__rsc_detect_loop);
    for (GList *lpc = rsc->priv->with_this_colocations;
         lpc != NULL; lpc = lpc->next) {
        pcmk__colocation_t *cons = (pcmk__colocation_t *) lpc->data;
        char *hdr = NULL;

        PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Resources colocated with %s",
                                 rsc->id);

        if (pcmk__is_set(cons->dependent->flags, pcmk__rsc_detect_loop)) {
            out->list_item(out, NULL, "%s (id=%s - loop)",
                           cons->dependent->id, cons->id);
            continue;
        }

        hdr = colocations_header(cons->dependent, cons, true);
        out->list_item(out, NULL, "%s", hdr);
        free(hdr);

        // Empty list header for indentation of information about this resource
        out->begin_list(out, NULL, NULL, NULL);

        out->message(out, "locations-list", cons->dependent);
        if (recursive) {
            out->message(out, "rscs-colocated-with-list",
                         cons->dependent, recursive);
        }

        out->end_list(out);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("rscs-colocated-with-list", "pcmk_resource_t *", "bool")
static int
rscs_colocated_with_list_xml(pcmk__output_t *out, va_list args) {
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    bool recursive = va_arg(args, int);

    int rc = pcmk_rc_no_output;

    if (pcmk__is_set(rsc->flags, pcmk__rsc_detect_loop)) {
        return rc;
    }

    /* We're listing constraints explicitly involving rsc, so use
     * rsc->private->with_this_colocations directly rather than
     * rsc->private->cmds->with_this_colocations().
     */
    pcmk__set_rsc_flags(rsc, pcmk__rsc_detect_loop);
    for (GList *lpc = rsc->priv->with_this_colocations;
         lpc != NULL; lpc = lpc->next) {
        pcmk__colocation_t *cons = (pcmk__colocation_t *) lpc->data;

        if (pcmk__is_set(cons->dependent->flags, pcmk__rsc_detect_loop)) {
            colocations_xml_node(out, cons->dependent, cons);
            continue;
        }

        colocations_xml_node(out, cons->dependent, cons);
        do_locations_list_xml(out, cons->dependent, false);

        if (recursive) {
            out->message(out, "rscs-colocated-with-list",
                         cons->dependent, recursive);
        }
    }

    return rc;
}

PCMK__OUTPUT_ARGS("locations-list", "pcmk_resource_t *")
static int
locations_list(pcmk__output_t *out, va_list args) {
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);

    GList *lpc = NULL;
    int rc = pcmk_rc_no_output;

    for (lpc = rsc->priv->location_constraints;
         lpc != NULL; lpc = lpc->next) {
        pcmk__location_t *cons = lpc->data;

        GList *lpc2 = NULL;

        for (lpc2 = cons->nodes; lpc2 != NULL; lpc2 = lpc2->next) {
            pcmk_node_t *node = (pcmk_node_t *) lpc2->data;

            PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Locations");
            out->list_item(out, NULL, "Node %s (score=%s, id=%s, rsc=%s)",
                           pcmk__node_name(node),
                           pcmk_readable_score(node->assign->score), cons->id,
                           rsc->id);
        }
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("locations-list", "pcmk_resource_t *")
static int
locations_list_xml(pcmk__output_t *out, va_list args) {
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    return do_locations_list_xml(out, rsc, true);
}

PCMK__OUTPUT_ARGS("locations-and-colocations", "pcmk_resource_t *",
                  "bool", "bool")
static int
locations_and_colocations(pcmk__output_t *out, va_list args)
{
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    bool recursive = va_arg(args, int);
    bool force = va_arg(args, int);

    pcmk__unpack_constraints(rsc->priv->scheduler);

    // Constraints apply to group/clone, not member/instance
    if (!force) {
        rsc = uber_parent(rsc);
    }

    out->message(out, "locations-list", rsc);

    pe__clear_resource_flags_on_all(rsc->priv->scheduler,
                                    pcmk__rsc_detect_loop);
    out->message(out, "rscs-colocated-with-list", rsc, recursive);

    pe__clear_resource_flags_on_all(rsc->priv->scheduler,
                                    pcmk__rsc_detect_loop);
    out->message(out, "rsc-is-colocated-with-list", rsc, recursive);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("locations-and-colocations", "pcmk_resource_t *",
                  "bool", "bool")
static int
locations_and_colocations_xml(pcmk__output_t *out, va_list args)
{
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    bool recursive = va_arg(args, int);
    bool force = va_arg(args, int);

    pcmk__unpack_constraints(rsc->priv->scheduler);

    // Constraints apply to group/clone, not member/instance
    if (!force) {
        rsc = uber_parent(rsc);
    }

    pcmk__output_xml_create_parent(out, PCMK_XE_CONSTRAINTS);
    do_locations_list_xml(out, rsc, false);

    pe__clear_resource_flags_on_all(rsc->priv->scheduler,
                                    pcmk__rsc_detect_loop);
    out->message(out, "rscs-colocated-with-list", rsc, recursive);

    pe__clear_resource_flags_on_all(rsc->priv->scheduler,
                                    pcmk__rsc_detect_loop);
    out->message(out, "rsc-is-colocated-with-list", rsc, recursive);

    pcmk__output_xml_pop_parent(out);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("health", "const char *", "const char *", "const char *",
                  "const char *")
static int
health(pcmk__output_t *out, va_list args)
{
    const char *sys_from G_GNUC_UNUSED = va_arg(args, const char *);
    const char *host_from = va_arg(args, const char *);
    const char *fsa_state = va_arg(args, const char *);
    const char *result = va_arg(args, const char *);

    return out->info(out, "Controller on %s in state %s: %s",
                     pcmk__s(host_from, "unknown node"),
                     pcmk__s(fsa_state, "unknown"),
                     pcmk__s(result, "unknown result"));
}

PCMK__OUTPUT_ARGS("health", "const char *", "const char *", "const char *",
                  "const char *")
static int
health_text(pcmk__output_t *out, va_list args)
{
    if (!out->is_quiet(out)) {
        return health(out, args);
    } else {
        const char *sys_from G_GNUC_UNUSED = va_arg(args, const char *);
        const char *host_from G_GNUC_UNUSED = va_arg(args, const char *);
        const char *fsa_state = va_arg(args, const char *);
        const char *result G_GNUC_UNUSED = va_arg(args, const char *);

        if (fsa_state != NULL) {
            pcmk__formatted_printf(out, "%s\n", fsa_state);
            return pcmk_rc_ok;
        }
    }

    return pcmk_rc_no_output;
}

PCMK__OUTPUT_ARGS("health", "const char *", "const char *", "const char *",
                  "const char *")
static int
health_xml(pcmk__output_t *out, va_list args)
{
    const char *sys_from = va_arg(args, const char *);
    const char *host_from = va_arg(args, const char *);
    const char *fsa_state = va_arg(args, const char *);
    const char *result = va_arg(args, const char *);

    pcmk__output_create_xml_node(out, pcmk__s(sys_from, ""),
                                 PCMK_XA_NODE_NAME, pcmk__s(host_from, ""),
                                 PCMK_XA_STATE, pcmk__s(fsa_state, ""),
                                 PCMK_XA_RESULT, pcmk__s(result, ""),
                                 NULL);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("pacemakerd-health", "const char *",
                  "enum pcmk_pacemakerd_state", "const char *", "time_t")
static int
pacemakerd_health(pcmk__output_t *out, va_list args)
{
    const char *sys_from = va_arg(args, const char *);
    enum pcmk_pacemakerd_state state =
        (enum pcmk_pacemakerd_state) va_arg(args, int);
    const char *state_s = va_arg(args, const char *);
    time_t last_updated = va_arg(args, time_t);

    char *last_updated_s = NULL;
    int rc = pcmk_rc_ok;

    if (sys_from == NULL) {
        if (state == pcmk_pacemakerd_state_remote) {
            sys_from = PCMK__SERVER_REMOTED;
        } else {
            sys_from = CRM_SYSTEM_MCP;
        }
    }

    if (state_s == NULL) {
        state_s = pcmk__pcmkd_state_enum2friendly(state);
    }

    if (last_updated != 0) {
        last_updated_s = pcmk__epoch2str(&last_updated,
                                         crm_time_log_date
                                         |crm_time_log_timeofday
                                         |crm_time_log_with_timezone);
    }

    rc = out->info(out, "Status of %s: '%s' (last updated %s)",
                   sys_from, state_s,
                   pcmk__s(last_updated_s, "at unknown time"));

    free(last_updated_s);
    return rc;
}

PCMK__OUTPUT_ARGS("pacemakerd-health", "const char *",
                  "enum pcmk_pacemakerd_state", "const char *", "time_t")
static int
pacemakerd_health_html(pcmk__output_t *out, va_list args)
{
    const char *sys_from = va_arg(args, const char *);
    enum pcmk_pacemakerd_state state =
        (enum pcmk_pacemakerd_state) va_arg(args, int);
    const char *state_s = va_arg(args, const char *);
    time_t last_updated = va_arg(args, time_t);

    char *last_updated_s = NULL;
    char *msg = NULL;

    if (sys_from == NULL) {
        if (state == pcmk_pacemakerd_state_remote) {
            sys_from = PCMK__SERVER_REMOTED;
        } else {
            sys_from = CRM_SYSTEM_MCP;
        }
    }

    if (state_s == NULL) {
        state_s = pcmk__pcmkd_state_enum2friendly(state);
    }

    if (last_updated != 0) {
        last_updated_s = pcmk__epoch2str(&last_updated,
                                         crm_time_log_date
                                         |crm_time_log_timeofday
                                         |crm_time_log_with_timezone);
    }

    msg = pcmk__assert_asprintf("Status of %s: '%s' (last updated %s)",
                                sys_from, state_s,
                                pcmk__s(last_updated_s, "at unknown time"));
    pcmk__output_create_html_node(out, "li", NULL, NULL, msg);

    free(msg);
    free(last_updated_s);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("pacemakerd-health", "const char *",
                  "enum pcmk_pacemakerd_state", "const char *", "time_t")
static int
pacemakerd_health_text(pcmk__output_t *out, va_list args)
{
    if (!out->is_quiet(out)) {
        return pacemakerd_health(out, args);
    } else {
        const char *sys_from G_GNUC_UNUSED = va_arg(args, const char *);
        enum pcmk_pacemakerd_state state =
            (enum pcmk_pacemakerd_state) va_arg(args, int);
        const char *state_s = va_arg(args, const char *);
        time_t last_updated G_GNUC_UNUSED = va_arg(args, time_t);

        if (state_s == NULL) {
            state_s = pcmk_pacemakerd_api_daemon_state_enum2text(state);
        }
        pcmk__formatted_printf(out, "%s\n", state_s);
        return pcmk_rc_ok;
    }
}

PCMK__OUTPUT_ARGS("pacemakerd-health", "const char *",
                  "enum pcmk_pacemakerd_state", "const char *", "time_t")
static int
pacemakerd_health_xml(pcmk__output_t *out, va_list args)
{
    const char *sys_from = va_arg(args, const char *);
    enum pcmk_pacemakerd_state state =
        (enum pcmk_pacemakerd_state) va_arg(args, int);
    const char *state_s = va_arg(args, const char *);
    time_t last_updated = va_arg(args, time_t);

    char *last_updated_s = NULL;

    if (sys_from == NULL) {
        if (state == pcmk_pacemakerd_state_remote) {
            sys_from = PCMK__SERVER_REMOTED;
        } else {
            sys_from = CRM_SYSTEM_MCP;
        }
    }

    if (state_s == NULL) {
        state_s = pcmk_pacemakerd_api_daemon_state_enum2text(state);
    }

    if (last_updated != 0) {
        last_updated_s = pcmk__epoch2str(&last_updated,
                                         crm_time_log_date
                                         |crm_time_log_timeofday
                                         |crm_time_log_with_timezone);
    }

    pcmk__output_create_xml_node(out, PCMK_XE_PACEMAKERD,
                                 PCMK_XA_SYS_FROM, sys_from,
                                 PCMK_XA_STATE, state_s,
                                 PCMK_XA_LAST_UPDATED, last_updated_s,
                                 NULL);
    free(last_updated_s);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("profile", "const char *", "clock_t", "clock_t")
static int
profile_default(pcmk__output_t *out, va_list args) {
    const char *xml_file = va_arg(args, const char *);
    clock_t start = va_arg(args, clock_t);
    clock_t end = va_arg(args, clock_t);

    out->list_item(out, NULL, "Testing %s ... %.2f secs", xml_file,
                   (end - start) / (float) CLOCKS_PER_SEC);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("profile", "const char *", "clock_t", "clock_t")
static int
profile_xml(pcmk__output_t *out, va_list args) {
    const char *xml_file = va_arg(args, const char *);
    clock_t start = va_arg(args, clock_t);
    clock_t end = va_arg(args, clock_t);

    char *duration = pcmk__ftoa((end - start) / (float) CLOCKS_PER_SEC);

    pcmk__output_create_xml_node(out, PCMK_XE_TIMING,
                                 PCMK_XA_FILE, xml_file,
                                 PCMK_XA_DURATION, duration,
                                 NULL);

    free(duration);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("dc", "const char *")
static int
dc(pcmk__output_t *out, va_list args)
{
    const char *dc = va_arg(args, const char *);

    return out->info(out, "Designated Controller is: %s",
                     pcmk__s(dc, "not yet elected"));
}

PCMK__OUTPUT_ARGS("dc", "const char *")
static int
dc_text(pcmk__output_t *out, va_list args)
{
    if (!out->is_quiet(out)) {
        return dc(out, args);
    } else {
        const char *dc = va_arg(args, const char *);

        if (dc != NULL) {
            pcmk__formatted_printf(out, "%s\n", pcmk__s(dc, ""));
            return pcmk_rc_ok;
        }
    }

    return pcmk_rc_no_output;
}

PCMK__OUTPUT_ARGS("dc", "const char *")
static int
dc_xml(pcmk__output_t *out, va_list args)
{
    const char *dc = va_arg(args, const char *);

    pcmk__output_create_xml_node(out, PCMK_XE_DC,
                                 PCMK_XA_NODE_NAME, pcmk__s(dc, ""),
                                 NULL);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("crmadmin-node", "const char *", "const char *",
                  "const char *", "bool")
static int
crmadmin_node(pcmk__output_t *out, va_list args)
{
    const char *type = va_arg(args, const char *);
    const char *name = va_arg(args, const char *);
    const char *id = va_arg(args, const char *);
    bool bash_export = va_arg(args, int);

    if (bash_export) {
        return out->info(out, "export %s=%s",
                         pcmk__s(name, "<null>"), pcmk__s(id, ""));
    } else {
        return out->info(out, "%s node: %s (%s)", type ? type : "cluster",
                         pcmk__s(name, "<null>"), pcmk__s(id, "<null>"));
    }
}

PCMK__OUTPUT_ARGS("crmadmin-node", "const char *", "const char *",
                  "const char *", "bool")
static int
crmadmin_node_text(pcmk__output_t *out, va_list args)
{
    if (!out->is_quiet(out)) {
        return crmadmin_node(out, args);
    } else {
        const char *type G_GNUC_UNUSED = va_arg(args, const char *);
        const char *name = va_arg(args, const char *);
        const char *id G_GNUC_UNUSED = va_arg(args, const char *);
        bool bash_export G_GNUC_UNUSED = va_arg(args, int);

        pcmk__formatted_printf(out, "%s\n", pcmk__s(name, "<null>"));
        return pcmk_rc_ok;
    }
}

PCMK__OUTPUT_ARGS("crmadmin-node", "const char *", "const char *",
                  "const char *", "bool")
static int
crmadmin_node_xml(pcmk__output_t *out, va_list args)
{
    const char *type = va_arg(args, const char *);
    const char *name = va_arg(args, const char *);
    const char *id = va_arg(args, const char *);
    bool bash_export G_GNUC_UNUSED = va_arg(args, int);

    pcmk__output_create_xml_node(out, PCMK_XE_NODE,
                                 PCMK_XA_TYPE, pcmk__s(type, "cluster"),
                                 PCMK_XA_NAME, pcmk__s(name, ""),
                                 PCMK_XA_ID, pcmk__s(id, ""),
                                 NULL);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("digests", "const pcmk_resource_t *", "const pcmk_node_t *",
                  "const char *", "guint", "const pcmk__op_digest_t *")
static int
digests_text(pcmk__output_t *out, va_list args)
{
    const pcmk_resource_t *rsc = va_arg(args, const pcmk_resource_t *);
    const pcmk_node_t *node = va_arg(args, const pcmk_node_t *);
    const char *task = va_arg(args, const char *);
    guint interval_ms = va_arg(args, guint);
    const pcmk__op_digest_t *digests = va_arg(args, const pcmk__op_digest_t *);

    char *action_desc = NULL;
    const char *rsc_desc = "unknown resource";
    const char *node_desc = "unknown node";

    if (interval_ms != 0) {
        action_desc = pcmk__assert_asprintf("%ums-interval %s action",
                                            interval_ms,
                                            pcmk__s(task, "unknown"));
    } else if (pcmk__str_eq(task, PCMK_ACTION_MONITOR, pcmk__str_none)) {
        action_desc = strdup("probe action");
    } else {
        action_desc = pcmk__assert_asprintf("%s action",
                                            pcmk__s(task, "unknown"));
    }
    if ((rsc != NULL) && (rsc->id != NULL)) {
        rsc_desc = rsc->id;
    }
    if ((node != NULL) && (node->priv->name != NULL)) {
        node_desc = node->priv->name;
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
        xmlNodePtr digest_xml = pcmk__xe_create(parent, PCMK_XE_DIGEST);

        pcmk__xe_set(digest_xml, PCMK_XA_TYPE, pcmk__s(type, "unspecified"));
        pcmk__xe_set(digest_xml, PCMK_XA_HASH, digest);
        pcmk__xml_copy(digest_xml, digest_source);
    }
}

PCMK__OUTPUT_ARGS("digests", "const pcmk_resource_t *", "const pcmk_node_t *",
                  "const char *", "guint", "const pcmk__op_digest_t *")
static int
digests_xml(pcmk__output_t *out, va_list args)
{
    const pcmk_resource_t *rsc = va_arg(args, const pcmk_resource_t *);
    const pcmk_node_t *node = va_arg(args, const pcmk_node_t *);
    const char *task = va_arg(args, const char *);
    guint interval_ms = va_arg(args, guint);
    const pcmk__op_digest_t *digests = va_arg(args, const pcmk__op_digest_t *);

    char *interval_s = pcmk__assert_asprintf("%ums", interval_ms);
    xmlNode *xml = NULL;

    xml = pcmk__output_create_xml_node(out, PCMK_XE_DIGESTS,
                                       PCMK_XA_RESOURCE, pcmk__s(rsc->id, ""),
                                       PCMK_XA_NODE,
                                       pcmk__s(node->priv->name, ""),
                                       PCMK_XA_TASK, pcmk__s(task, ""),
                                       PCMK_XA_INTERVAL, interval_s,
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

#define STOP_SANITY_ASSERT(lineno) do {                                     \
        if ((current != NULL) && current->details->unclean) {               \
            /* It will be a pseudo op */                                    \
        } else if (stop == NULL) {                                          \
            pcmk__err("%s:%d: No stop action exists for %s",                \
                      __func__, lineno, rsc->id);                           \
            pcmk__assert(stop != NULL);                                     \
        } else if (pcmk__is_set(stop->flags, pcmk__action_optional)) {      \
            pcmk__err("%s:%d: Action %s is still optional",                 \
                      __func__, lineno, stop->uuid);                        \
            pcmk__assert(!pcmk__is_set(stop->flags,                         \
                                       pcmk__action_optional));             \
        }                                                                   \
    } while (0)

PCMK__OUTPUT_ARGS("rsc-action", "pcmk_resource_t *", "pcmk_node_t *",
                  "pcmk_node_t *")
static int
rsc_action_default(pcmk__output_t *out, va_list args)
{
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    pcmk_node_t *current = va_arg(args, pcmk_node_t *);
    pcmk_node_t *next = va_arg(args, pcmk_node_t *);

    GList *possible_matches = NULL;
    char *key = NULL;
    int rc = pcmk_rc_no_output;
    bool moving = false;

    pcmk_node_t *start_node = NULL;
    pcmk_action_t *start = NULL;
    pcmk_action_t *stop = NULL;
    pcmk_action_t *promote = NULL;
    pcmk_action_t *demote = NULL;
    pcmk_action_t *reason_op = NULL;

    if (!pcmk__is_set(rsc->flags, pcmk__rsc_managed)
        || ((current == NULL) && (next == NULL))) {
        const bool managed = pcmk__is_set(rsc->flags, pcmk__rsc_managed);

        pcmk__rsc_info(rsc, "Leave   %s\t(%s%s)",
                       rsc->id, pcmk_role_text(rsc->priv->orig_role),
                       (managed? "" : " unmanaged"));
        return rc;
    }

    moving = (current != NULL) && (next != NULL)
             && !pcmk__same_node(current, next);

    possible_matches = pe__resource_actions(rsc, next, PCMK_ACTION_START,
                                            false);
    if (possible_matches) {
        start = possible_matches->data;
        g_list_free(possible_matches);
    }

    if ((start == NULL)
        || !pcmk__is_set(start->flags, pcmk__action_runnable)) {
        start_node = NULL;
    } else {
        start_node = current;
    }
    possible_matches = pe__resource_actions(rsc, start_node, PCMK_ACTION_STOP,
                                            false);
    if (possible_matches) {
        stop = possible_matches->data;
        g_list_free(possible_matches);
    } else if (pcmk__is_set(rsc->flags, pcmk__rsc_stop_unexpected)) {
        /* The resource is multiply active with PCMK_META_MULTIPLE_ACTIVE set to
         * PCMK_VALUE_STOP_UNEXPECTED, and not stopping on its current node, but
         * it should be stopping elsewhere.
         */
        possible_matches = pe__resource_actions(rsc, NULL, PCMK_ACTION_STOP,
                                                false);
        if (possible_matches != NULL) {
            stop = possible_matches->data;
            g_list_free(possible_matches);
        }
    }

    possible_matches = pe__resource_actions(rsc, next, PCMK_ACTION_PROMOTE,
                                            false);
    if (possible_matches) {
        promote = possible_matches->data;
        g_list_free(possible_matches);
    }

    possible_matches = pe__resource_actions(rsc, next, PCMK_ACTION_DEMOTE,
                                            false);
    if (possible_matches) {
        demote = possible_matches->data;
        g_list_free(possible_matches);
    }

    if (rsc->priv->orig_role == rsc->priv->next_role) {
        pcmk_action_t *migrate_op = NULL;

        CRM_CHECK(next != NULL, return rc);

        possible_matches = pe__resource_actions(rsc, next,
                                                PCMK_ACTION_MIGRATE_FROM,
                                                false);
        if (possible_matches) {
            migrate_op = possible_matches->data;
        }

        if ((migrate_op != NULL) && (current != NULL)
            && pcmk__is_set(migrate_op->flags, pcmk__action_runnable)) {
            rc = out->message(out, "rsc-action-item", "Migrate", rsc, current,
                              next, start, NULL);

        } else if (pcmk__is_set(rsc->flags, pcmk__rsc_reload)) {
            rc = out->message(out, "rsc-action-item", "Reload", rsc, current,
                              next, start, NULL);

        } else if ((start == NULL)
                   || pcmk__is_set(start->flags, pcmk__action_optional)) {
            if ((demote != NULL) && (promote != NULL)
                && !pcmk__is_set(demote->flags, pcmk__action_optional)
                && !pcmk__is_set(promote->flags, pcmk__action_optional)) {
                rc = out->message(out, "rsc-action-item", "Re-promote", rsc,
                                  current, next, promote, demote);
            } else {
                pcmk__rsc_info(rsc, "Leave   %s\t(%s %s)", rsc->id,
                               pcmk_role_text(rsc->priv->orig_role),
                               pcmk__node_name(next));
            }

        } else if (!pcmk__is_set(start->flags, pcmk__action_runnable)) {
            if ((stop == NULL) || (stop->reason == NULL)) {
                reason_op = start;
            } else {
                reason_op = stop;
            }
            rc = out->message(out, "rsc-action-item", "Stop", rsc, current,
                              NULL, stop, reason_op);
            STOP_SANITY_ASSERT(__LINE__);

        } else if (moving && current) {
            const bool failed = pcmk__is_set(rsc->flags, pcmk__rsc_failed);

            rc = out->message(out, "rsc-action-item",
                              (failed? "Recover" : "Move"), rsc, current, next,
                              stop, NULL);

        } else if (pcmk__is_set(rsc->flags, pcmk__rsc_failed)) {
            rc = out->message(out, "rsc-action-item", "Recover", rsc, current,
                              NULL, stop, NULL);
            STOP_SANITY_ASSERT(__LINE__);

        } else {
            rc = out->message(out, "rsc-action-item", "Restart", rsc, current,
                              next, start, NULL);
#if 0
            /* @TODO This can be reached in situations that should really be
             * "Start" (see for example the migrate-fail-7 regression test)
             */
            STOP_SANITY_ASSERT(__LINE__);
#endif
        }

        g_list_free(possible_matches);
        return rc;
    }

    if ((stop != NULL)
        && ((rsc->priv->next_role == pcmk_role_stopped)
            || ((start != NULL)
                && !pcmk__is_set(start->flags, pcmk__action_runnable)))) {

        key = stop_key(rsc);
        for (GList *iter = rsc->priv->active_nodes;
             iter != NULL; iter = iter->next) {

            pcmk_node_t *node = iter->data;
            pcmk_action_t *stop_op = NULL;

            reason_op = start;
            possible_matches = find_actions(rsc->priv->actions, key, node);
            if (possible_matches) {
                stop_op = possible_matches->data;
                g_list_free(possible_matches);
            }

            if (stop_op != NULL) {
                if (pcmk__is_set(stop_op->flags, pcmk__action_runnable)) {
                    STOP_SANITY_ASSERT(__LINE__);
                }
                if (stop_op->reason != NULL) {
                    reason_op = stop_op;
                }
            }

            if (out->message(out, "rsc-action-item", "Stop", rsc, node, NULL,
                             stop_op, reason_op) == pcmk_rc_ok) {
                rc = pcmk_rc_ok;
            }
        }

        free(key);

    } else if ((stop != NULL)
               && pcmk__all_flags_set(rsc->flags,
                                      pcmk__rsc_failed
                                      |pcmk__rsc_stop_if_failed)) {
        /* 'stop' may be NULL if the failure was ignored */
        rc = out->message(out, "rsc-action-item", "Recover", rsc, current,
                          next, stop, start);
        STOP_SANITY_ASSERT(__LINE__);

    } else if (moving) {
        rc = out->message(out, "rsc-action-item", "Move", rsc, current, next,
                          stop, NULL);
        STOP_SANITY_ASSERT(__LINE__);

    } else if (pcmk__is_set(rsc->flags, pcmk__rsc_reload)) {
        rc = out->message(out, "rsc-action-item", "Reload", rsc, current, next,
                          start, NULL);

    } else if ((stop != NULL)
               && !pcmk__is_set(stop->flags, pcmk__action_optional)) {
        rc = out->message(out, "rsc-action-item", "Restart", rsc, current,
                          next, start, NULL);
        STOP_SANITY_ASSERT(__LINE__);

    } else if (rsc->priv->orig_role == pcmk_role_promoted) {
        CRM_LOG_ASSERT(current != NULL);
        rc = out->message(out, "rsc-action-item", "Demote", rsc, current,
                          next, demote, NULL);

    } else if (rsc->priv->next_role == pcmk_role_promoted) {
        CRM_LOG_ASSERT(next);
        rc = out->message(out, "rsc-action-item", "Promote", rsc, current,
                          next, promote, NULL);

    } else if ((rsc->priv->orig_role == pcmk_role_stopped)
               && (rsc->priv->next_role > pcmk_role_stopped)) {
        rc = out->message(out, "rsc-action-item", "Start", rsc, current, next,
                          start, NULL);
    }

    return rc;
}

PCMK__OUTPUT_ARGS("node-action", "const char *", "const char *", "const char *")
static int
node_action(pcmk__output_t *out, va_list args)
{
    const char *task = va_arg(args, const char *);
    const char *node_name = va_arg(args, const char *);
    const char *reason = va_arg(args, const char *);

    if (task == NULL) {
        return pcmk_rc_no_output;
    } else if (reason) {
        out->list_item(out, NULL, "%s %s '%s'", task, node_name, reason);
    } else {
        pcmk__notice(" * %s %s", task, node_name);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-action", "const char *", "const char *", "const char *")
static int
node_action_xml(pcmk__output_t *out, va_list args)
{
    const char *task = va_arg(args, const char *);
    const char *node_name = va_arg(args, const char *);
    const char *reason = va_arg(args, const char *);

    if (task == NULL) {
        return pcmk_rc_no_output;
    } else if (reason) {
        pcmk__output_create_xml_node(out, PCMK_XE_NODE_ACTION,
                                     PCMK_XA_TASK, task,
                                     PCMK_XA_NODE, node_name,
                                     PCMK_XA_REASON, reason,
                                     NULL);
    } else {
        pcmk__notice(" * %s %s", task, node_name);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-info", "uint32_t", "const char *", "const char *",
                  "const char *", "bool", "bool")
static int
node_info_default(pcmk__output_t *out, va_list args)
{
    uint32_t node_id = va_arg(args, uint32_t);
    const char *node_name = va_arg(args, const char *);
    const char *uuid = va_arg(args, const char *);
    const char *state = va_arg(args, const char *);
    bool have_quorum = (bool) va_arg(args, int);
    bool is_remote = (bool) va_arg(args, int);

    return out->info(out,
                     "Node %" PRIu32 ": %s "
                     "(uuid=%s, state=%s, have_quorum=%s, is_remote=%s)",
                     node_id, pcmk__s(node_name, "unknown"),
                     pcmk__s(uuid, "unknown"), pcmk__s(state, "unknown"),
                     pcmk__btoa(have_quorum), pcmk__btoa(is_remote));
}

PCMK__OUTPUT_ARGS("node-info", "uint32_t", "const char *", "const char *",
                  "const char *", "bool", "bool")
static int
node_info_xml(pcmk__output_t *out, va_list args)
{
    uint32_t node_id = va_arg(args, uint32_t);
    const char *node_name = va_arg(args, const char *);
    const char *uuid = va_arg(args, const char *);
    const char *state = va_arg(args, const char *);
    bool have_quorum = (bool) va_arg(args, int);
    bool is_remote = (bool) va_arg(args, int);

    char *id_s = pcmk__assert_asprintf("%" PRIu32, node_id);

    pcmk__output_create_xml_node(out, PCMK_XE_NODE_INFO,
                                 PCMK_XA_NODEID, id_s,
                                 PCMK_XA_UNAME, node_name,
                                 PCMK_XA_ID, uuid,
                                 PCMK_XA_CRMD, state,
                                 PCMK_XA_HAVE_QUORUM, pcmk__btoa(have_quorum),
                                 PCMK_XA_REMOTE_NODE, pcmk__btoa(is_remote),
                                 NULL);
    free(id_s);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("inject-cluster-action", "const char *", "const char *",
                  "xmlNode *")
static int
inject_cluster_action(pcmk__output_t *out, va_list args)
{
    const char *node = va_arg(args, const char *);
    const char *task = va_arg(args, const char *);
    xmlNodePtr rsc = va_arg(args, xmlNodePtr);

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    if (rsc != NULL) {
        out->list_item(out, NULL, "Cluster action:  %s for %s on %s",
                       task, pcmk__xe_id(rsc), node);
    } else {
        out->list_item(out, NULL, "Cluster action:  %s on %s", task, node);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("inject-cluster-action", "const char *", "const char *",
                  "xmlNode *")
static int
inject_cluster_action_xml(pcmk__output_t *out, va_list args)
{
    const char *node = va_arg(args, const char *);
    const char *task = va_arg(args, const char *);
    xmlNodePtr rsc = va_arg(args, xmlNodePtr);

    xmlNodePtr xml_node = NULL;

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    xml_node = pcmk__output_create_xml_node(out, PCMK_XE_CLUSTER_ACTION,
                                            PCMK_XA_TASK, task,
                                            PCMK_XA_NODE, node,
                                            NULL);

    if (rsc) {
        pcmk__xe_set(xml_node, PCMK_XA_ID, pcmk__xe_id(rsc));
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("inject-fencing-action", "const char *", "const char *")
static int
inject_fencing_action(pcmk__output_t *out, va_list args)
{
    const char *target = va_arg(args, const char *);
    const char *op = va_arg(args, const char *);

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    out->list_item(out, NULL, "Fencing %s (%s)", target, op);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("inject-fencing-action", "const char *", "const char *")
static int
inject_fencing_action_xml(pcmk__output_t *out, va_list args)
{
    const char *target = va_arg(args, const char *);
    const char *op = va_arg(args, const char *);

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    pcmk__output_create_xml_node(out, PCMK_XE_FENCING_ACTION,
                                 PCMK_XA_TARGET, target,
                                 PCMK_XA_OP, op,
                                 NULL);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("inject-attr", "const char *", "const char *", "xmlNode *")
static int
inject_attr(pcmk__output_t *out, va_list args)
{
    const char *name = va_arg(args, const char *);
    const char *value = va_arg(args, const char *);
    xmlNodePtr cib_node = va_arg(args, xmlNodePtr);

    xmlChar *node_path = NULL;

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    node_path = xmlGetNodePath(cib_node);

    out->list_item(out, NULL, "Injecting attribute %s=%s into %s '%s'",
                   name, value, node_path, pcmk__xe_id(cib_node));

    free(node_path);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("inject-attr", "const char *", "const char *", "xmlNode *")
static int
inject_attr_xml(pcmk__output_t *out, va_list args)
{
    const char *name = va_arg(args, const char *);
    const char *value = va_arg(args, const char *);
    xmlNodePtr cib_node = va_arg(args, xmlNodePtr);

    xmlChar *node_path = NULL;

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    node_path = xmlGetNodePath(cib_node);

    pcmk__output_create_xml_node(out, PCMK_XE_INJECT_ATTR,
                                 PCMK_XA_NAME, name,
                                 PCMK_XA_VALUE, value,
                                 PCMK_XA_NODE_PATH, node_path,
                                 PCMK_XA_CIB_NODE, pcmk__xe_id(cib_node),
                                 NULL);
    free(node_path);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("inject-spec", "const char *")
static int
inject_spec(pcmk__output_t *out, va_list args)
{
    const char *spec = va_arg(args, const char *);

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    out->list_item(out, NULL, "Injecting %s into the configuration", spec);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("inject-spec", "const char *")
static int
inject_spec_xml(pcmk__output_t *out, va_list args)
{
    const char *spec = va_arg(args, const char *);

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    pcmk__output_create_xml_node(out, PCMK_XE_INJECT_SPEC,
                                 PCMK_XA_SPEC, spec,
                                 NULL);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("inject-modify-config", "const char *", "const char *")
static int
inject_modify_config(pcmk__output_t *out, va_list args)
{
    const char *quorum = va_arg(args, const char *);
    const char *watchdog = va_arg(args, const char *);

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    out->begin_list(out, NULL, NULL, "Performing Requested Modifications");

    if (quorum) {
        out->list_item(out, NULL, "Setting quorum: %s", quorum);
    }

    if (watchdog) {
        out->list_item(out, NULL, "Setting watchdog: %s", watchdog);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("inject-modify-config", "const char *", "const char *")
static int
inject_modify_config_xml(pcmk__output_t *out, va_list args)
{
    const char *quorum = va_arg(args, const char *);
    const char *watchdog = va_arg(args, const char *);

    xmlNodePtr node = NULL;

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    node = pcmk__output_xml_create_parent(out, PCMK_XE_MODIFICATIONS);

    if (quorum) {
        pcmk__xe_set(node, PCMK_XA_QUORUM, quorum);
    }

    if (watchdog) {
        pcmk__xe_set(node, PCMK_XA_WATCHDOG, watchdog);
    }

    pcmk__output_xml_pop_parent(out);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("inject-modify-node", "const char *", "const char *")
static int
inject_modify_node(pcmk__output_t *out, va_list args)
{
    const char *action = va_arg(args, const char *);
    const char *node = va_arg(args, const char *);

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    if (pcmk__str_eq(action, "Online", pcmk__str_none)) {
        out->list_item(out, NULL, "Bringing node %s online", node);
        return pcmk_rc_ok;
    } else if (pcmk__str_eq(action, "Offline", pcmk__str_none)) {
        out->list_item(out, NULL, "Taking node %s offline", node);
        return pcmk_rc_ok;
    } else if (pcmk__str_eq(action, "Failing", pcmk__str_none)) {
        out->list_item(out, NULL, "Failing node %s", node);
        return pcmk_rc_ok;
    }

    return pcmk_rc_no_output;
}

PCMK__OUTPUT_ARGS("inject-modify-node", "const char *", "const char *")
static int
inject_modify_node_xml(pcmk__output_t *out, va_list args)
{
    const char *action = va_arg(args, const char *);
    const char *node = va_arg(args, const char *);

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    pcmk__output_create_xml_node(out, PCMK_XE_MODIFY_NODE,
                                 PCMK_XA_ACTION, action,
                                 PCMK_XA_NODE, node,
                                 NULL);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("inject-modify-ticket", "const char *", "const char *")
static int
inject_modify_ticket(pcmk__output_t *out, va_list args)
{
    const char *action = va_arg(args, const char *);
    const char *ticket = va_arg(args, const char *);

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    if (pcmk__str_eq(action, "Standby", pcmk__str_none)) {
        out->list_item(out, NULL, "Making ticket %s standby", ticket);
    } else {
        out->list_item(out, NULL, "%s ticket %s", action, ticket);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("inject-modify-ticket", "const char *", "const char *")
static int
inject_modify_ticket_xml(pcmk__output_t *out, va_list args)
{
    const char *action = va_arg(args, const char *);
    const char *ticket = va_arg(args, const char *);

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    pcmk__output_create_xml_node(out, PCMK_XE_MODIFY_TICKET,
                                 PCMK_XA_ACTION, action,
                                 PCMK_XA_TICKET, ticket,
                                 NULL);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("inject-pseudo-action", "const char *", "const char *")
static int
inject_pseudo_action(pcmk__output_t *out, va_list args)
{
    const char *node = va_arg(args, const char *);
    const char *task = va_arg(args, const char *);

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    out->list_item(out, NULL, "Pseudo action:   %s%s%s",
                   task, ((node == NULL)? "" : " on "), pcmk__s(node, ""));
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("inject-pseudo-action", "const char *", "const char *")
static int
inject_pseudo_action_xml(pcmk__output_t *out, va_list args)
{
    const char *node = va_arg(args, const char *);
    const char *task = va_arg(args, const char *);

    xmlNodePtr xml_node = NULL;

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    xml_node = pcmk__output_create_xml_node(out, PCMK_XE_PSEUDO_ACTION,
                                            PCMK_XA_TASK, task,
                                            NULL);
    if (node) {
        pcmk__xe_set(xml_node, PCMK_XA_NODE, node);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("inject-rsc-action", "const char *", "const char *",
                  "const char *", "guint")
static int
inject_rsc_action(pcmk__output_t *out, va_list args)
{
    const char *rsc = va_arg(args, const char *);
    const char *operation = va_arg(args, const char *);
    const char *node = va_arg(args, const char *);
    guint interval_ms = va_arg(args, guint);

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    if (interval_ms) {
        out->list_item(out, NULL, "Resource action: %-15s %s=%u on %s",
                       rsc, operation, interval_ms, node);
    } else {
        out->list_item(out, NULL, "Resource action: %-15s %s on %s",
                       rsc, operation, node);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("inject-rsc-action", "const char *", "const char *",
                  "const char *", "guint")
static int
inject_rsc_action_xml(pcmk__output_t *out, va_list args)
{
    const char *rsc = va_arg(args, const char *);
    const char *operation = va_arg(args, const char *);
    const char *node = va_arg(args, const char *);
    guint interval_ms = va_arg(args, guint);

    xmlNodePtr xml_node = NULL;

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    xml_node = pcmk__output_create_xml_node(out, PCMK_XE_RSC_ACTION,
                                            PCMK_XA_RESOURCE, rsc,
                                            PCMK_XA_OP, operation,
                                            PCMK_XA_NODE, node,
                                            NULL);

    if (interval_ms) {
        char *interval_s = pcmk__itoa(interval_ms);

        pcmk__xe_set(xml_node, PCMK_XA_INTERVAL, interval_s);
        free(interval_s);
    }

    return pcmk_rc_ok;
}

#define CHECK_RC(retcode, retval)   \
    if (retval == pcmk_rc_ok) {     \
        retcode = pcmk_rc_ok;       \
    }

PCMK__OUTPUT_ARGS("cluster-status", "pcmk_scheduler_t *",
                  "enum pcmk_pacemakerd_state", "crm_exit_t",
                  "stonith_history_t *", "enum pcmk__fence_history", "uint32_t",
                  "uint32_t", "const char *", "GList *", "GList *")
int
pcmk__cluster_status_text(pcmk__output_t *out, va_list args)
{
    pcmk_scheduler_t *scheduler = va_arg(args, pcmk_scheduler_t *);
    enum pcmk_pacemakerd_state pcmkd_state =
        (enum pcmk_pacemakerd_state) va_arg(args, int);
    crm_exit_t history_rc = va_arg(args, crm_exit_t);
    stonith_history_t *stonith_history = va_arg(args, stonith_history_t *);
    enum pcmk__fence_history fence_history = va_arg(args, int);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);
    const char *prefix = va_arg(args, const char *);
    GList *unames = va_arg(args, GList *);
    GList *resources = va_arg(args, GList *);

    int rc = pcmk_rc_no_output;
    bool already_printed_failure = false;

    CHECK_RC(rc, out->message(out, "cluster-summary", scheduler, pcmkd_state,
                              section_opts, show_opts));

    if (pcmk__is_set(section_opts, pcmk_section_nodes) && unames) {
        CHECK_RC(rc, out->message(out, "node-list", scheduler->nodes, unames,
                                  resources, show_opts, rc == pcmk_rc_ok));
    }

    /* Print resources section, if needed */
    if (pcmk__is_set(section_opts, pcmk_section_resources)) {
        CHECK_RC(rc, out->message(out, "resource-list", scheduler, show_opts,
                                  true, unames, resources, rc == pcmk_rc_ok));
    }

    /* print Node Attributes section if requested */
    if (pcmk__is_set(section_opts, pcmk_section_attributes)) {
        CHECK_RC(rc, out->message(out, "node-attribute-list", scheduler,
                                  show_opts, (rc == pcmk_rc_ok), unames,
                                  resources));
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (pcmk__any_flags_set(section_opts,
                            pcmk_section_operations|pcmk_section_failcounts)) {
        CHECK_RC(rc, out->message(out, "node-summary", scheduler, unames,
                                  resources, section_opts, show_opts,
                                  (rc == pcmk_rc_ok)));
    }

    /* If there were any failed actions, print them */
    if (pcmk__is_set(section_opts, pcmk_section_failures)
        && (scheduler->priv->failed != NULL)
        && (scheduler->priv->failed->children != NULL)) {

        CHECK_RC(rc, out->message(out, "failed-action-list", scheduler, unames,
                                  resources, show_opts, rc == pcmk_rc_ok));
    }

    // Print failed fencing actions
    if (pcmk__is_set(section_opts, pcmk_section_fence_failed)
        && (fence_history != pcmk__fence_history_none)) {

        if (history_rc == 0) {
            stonith_history_t *hp = NULL;

            hp = stonith__first_matching_event(stonith_history,
                                               stonith__event_state_eq,
                                               GINT_TO_POINTER(st_failed));
            if (hp) {
                CHECK_RC(rc, out->message(out, "failed-fencing-list",
                                          stonith_history, unames, section_opts,
                                          show_opts, rc == pcmk_rc_ok));
            }
        } else {
            PCMK__OUTPUT_SPACER_IF(out, rc == pcmk_rc_ok);
            out->begin_list(out, NULL, NULL, "Failed Fencing Actions");
            out->list_item(out, NULL, "Failed to get fencing history: %s",
                           crm_exit_str(history_rc));
            out->end_list(out);

            already_printed_failure = true;
        }
    }

    /* Print tickets if requested */
    if (pcmk__is_set(section_opts, pcmk_section_tickets)) {
        CHECK_RC(rc, out->message(out, "ticket-list",
                                  scheduler->priv->ticket_constraints,
                                  (rc == pcmk_rc_ok), false, false));
    }

    /* Print negative location constraints if requested */
    if (pcmk__is_set(section_opts, pcmk_section_bans)) {
        CHECK_RC(rc, out->message(out, "ban-list", scheduler, prefix, resources,
                                  show_opts, rc == pcmk_rc_ok));
    }

    // Print fencing history
    if (pcmk__any_flags_set(section_opts, pcmk_section_fencing_all)
        && (fence_history != pcmk__fence_history_none)) {

        if (history_rc != 0) {
            if (!already_printed_failure) {
                PCMK__OUTPUT_SPACER_IF(out, rc == pcmk_rc_ok);
                out->begin_list(out, NULL, NULL, "Failed Fencing Actions");
                out->list_item(out, NULL, "Failed to get fencing history: %s",
                               crm_exit_str(history_rc));
                out->end_list(out);
            }
        } else if (pcmk__is_set(section_opts, pcmk_section_fence_worked)) {
            stonith_history_t *hp = NULL;

            hp = stonith__first_matching_event(stonith_history,
                                               stonith__event_state_neq,
                                               GINT_TO_POINTER(st_failed));
            if (hp) {
                CHECK_RC(rc, out->message(out, "fencing-list", hp, unames,
                                          section_opts, show_opts,
                                          rc == pcmk_rc_ok));
            }
        } else if (pcmk__is_set(section_opts, pcmk_section_fence_pending)) {
            stonith_history_t *hp = NULL;

            hp = stonith__first_matching_event(stonith_history,
                                               stonith__event_state_pending,
                                               NULL);
            if (hp) {
                CHECK_RC(rc, out->message(out, "pending-fencing-list", hp,
                                          unames, section_opts, show_opts,
                                          rc == pcmk_rc_ok));
            }
        }
    }

    return rc;
}

PCMK__OUTPUT_ARGS("cluster-status", "pcmk_scheduler_t *",
                  "enum pcmk_pacemakerd_state", "crm_exit_t",
                  "stonith_history_t *", "enum pcmk__fence_history", "uint32_t",
                  "uint32_t", "const char *", "GList *", "GList *")
static int
cluster_status_xml(pcmk__output_t *out, va_list args)
{
    pcmk_scheduler_t *scheduler = va_arg(args, pcmk_scheduler_t *);
    enum pcmk_pacemakerd_state pcmkd_state =
        (enum pcmk_pacemakerd_state) va_arg(args, int);
    crm_exit_t history_rc = va_arg(args, crm_exit_t);
    stonith_history_t *stonith_history = va_arg(args, stonith_history_t *);
    enum pcmk__fence_history fence_history = va_arg(args, int);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);
    const char *prefix = va_arg(args, const char *);
    GList *unames = va_arg(args, GList *);
    GList *resources = va_arg(args, GList *);

    out->message(out, "cluster-summary", scheduler, pcmkd_state, section_opts,
                 show_opts);

    /*** NODES ***/
    if (pcmk__is_set(section_opts, pcmk_section_nodes)) {
        out->message(out, "node-list", scheduler->nodes, unames, resources,
                     show_opts, false);
    }

    /* Print resources section, if needed */
    if (pcmk__is_set(section_opts, pcmk_section_resources)) {
        /* XML output always displays full details. */
        uint32_t full_show_opts = show_opts & ~pcmk_show_brief;

        out->message(out, "resource-list", scheduler, full_show_opts,
                     false, unames, resources, false);
    }

    /* print Node Attributes section if requested */
    if (pcmk__is_set(section_opts, pcmk_section_attributes)) {
        out->message(out, "node-attribute-list", scheduler, show_opts, false,
                     unames, resources);
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (pcmk__any_flags_set(section_opts,
                            pcmk_section_operations|pcmk_section_failcounts)) {
        out->message(out, "node-summary", scheduler, unames,
                     resources, section_opts, show_opts, false);
    }

    /* If there were any failed actions, print them */
    if (pcmk__is_set(section_opts, pcmk_section_failures)
        && (scheduler->priv->failed != NULL)
        && (scheduler->priv->failed->children != NULL)) {

        out->message(out, "failed-action-list", scheduler, unames, resources,
                     show_opts, false);
    }

    // Print fencing history
    if (pcmk__is_set(section_opts, pcmk_section_fencing_all)
        && (fence_history != pcmk__fence_history_none)) {

        out->message(out, "full-fencing-list", history_rc, stonith_history,
                     unames, section_opts, show_opts, false);
    }

    /* Print tickets if requested */
    if (pcmk__is_set(section_opts, pcmk_section_tickets)) {
        out->message(out, "ticket-list", scheduler->priv->ticket_constraints,
                     false, false, false);
    }

    /* Print negative location constraints if requested */
    if (pcmk__is_set(section_opts, pcmk_section_bans)) {
        out->message(out, "ban-list", scheduler, prefix, resources, show_opts,
                     false);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("cluster-status", "pcmk_scheduler_t *",
                  "enum pcmk_pacemakerd_state", "crm_exit_t",
                  "stonith_history_t *", "enum pcmk__fence_history", "uint32_t",
                  "uint32_t", "const char *", "GList *", "GList *")
static int
cluster_status_html(pcmk__output_t *out, va_list args)
{
    pcmk_scheduler_t *scheduler = va_arg(args, pcmk_scheduler_t *);
    enum pcmk_pacemakerd_state pcmkd_state =
        (enum pcmk_pacemakerd_state) va_arg(args, int);
    crm_exit_t history_rc = va_arg(args, crm_exit_t);
    stonith_history_t *stonith_history = va_arg(args, stonith_history_t *);
    enum pcmk__fence_history fence_history = va_arg(args, int);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);
    const char *prefix = va_arg(args, const char *);
    GList *unames = va_arg(args, GList *);
    GList *resources = va_arg(args, GList *);
    bool already_printed_failure = false;

    out->message(out, "cluster-summary", scheduler, pcmkd_state, section_opts,
                 show_opts);

    /*** NODE LIST ***/
    if (pcmk__is_set(section_opts, pcmk_section_nodes) && (unames != NULL)) {
        out->message(out, "node-list", scheduler->nodes, unames, resources,
                     show_opts, false);
    }

    /* Print resources section, if needed */
    if (pcmk__is_set(section_opts, pcmk_section_resources)) {
        out->message(out, "resource-list", scheduler, show_opts, true, unames,
                     resources, false);
    }

    /* print Node Attributes section if requested */
    if (pcmk__is_set(section_opts, pcmk_section_attributes)) {
        out->message(out, "node-attribute-list", scheduler, show_opts, false,
                     unames, resources);
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (pcmk__any_flags_set(section_opts,
                            pcmk_section_operations|pcmk_section_failcounts)) {
        out->message(out, "node-summary", scheduler, unames,
                     resources, section_opts, show_opts, false);
    }

    /* If there were any failed actions, print them */
    if (pcmk__is_set(section_opts, pcmk_section_failures)
        && (scheduler->priv->failed != NULL)
        && (scheduler->priv->failed->children != NULL)) {

        out->message(out, "failed-action-list", scheduler, unames, resources,
                     show_opts, false);
    }

    // Print failed fencing actions
    if (pcmk__is_set(section_opts, pcmk_section_fence_failed)
        && (fence_history != pcmk__fence_history_none)) {

        if (history_rc == 0) {
            stonith_history_t *hp = NULL;

            hp = stonith__first_matching_event(stonith_history,
                                               stonith__event_state_eq,
                                               GINT_TO_POINTER(st_failed));
            if (hp) {
                out->message(out, "failed-fencing-list", stonith_history,
                             unames, section_opts, show_opts, false);
            }
        } else {
            out->begin_list(out, NULL, NULL, "Failed Fencing Actions");
            out->list_item(out, NULL, "Failed to get fencing history: %s",
                           crm_exit_str(history_rc));
            out->end_list(out);
        }
    }

    // Print fencing history
    if (pcmk__any_flags_set(section_opts, pcmk_section_fencing_all)
        && (fence_history != pcmk__fence_history_none)) {

        if (history_rc != 0) {
            if (!already_printed_failure) {
                out->begin_list(out, NULL, NULL, "Failed Fencing Actions");
                out->list_item(out, NULL, "Failed to get fencing history: %s",
                               crm_exit_str(history_rc));
                out->end_list(out);
            }
        } else if (pcmk__is_set(section_opts, pcmk_section_fence_worked)) {
            stonith_history_t *hp = NULL;

            hp = stonith__first_matching_event(stonith_history,
                                               stonith__event_state_neq,
                                               GINT_TO_POINTER(st_failed));
            if (hp) {
                out->message(out, "fencing-list", hp, unames, section_opts,
                             show_opts, false);
            }
        } else if (pcmk__is_set(section_opts, pcmk_section_fence_pending)) {
            stonith_history_t *hp = NULL;

            hp = stonith__first_matching_event(stonith_history,
                                               stonith__event_state_pending,
                                               NULL);
            if (hp) {
                out->message(out, "pending-fencing-list", hp, unames,
                             section_opts, show_opts, false);
            }
        }
    }

    /* Print tickets if requested */
    if (pcmk__is_set(section_opts, pcmk_section_tickets)) {
        out->message(out, "ticket-list", scheduler->priv->ticket_constraints,
                     false, false, false);
    }

    /* Print negative location constraints if requested */
    if (pcmk__is_set(section_opts, pcmk_section_bans)) {
        out->message(out, "ban-list", scheduler, prefix, resources, show_opts,
                     false);
    }

    return pcmk_rc_ok;
}

#define KV_PAIR(k, v) do { \
    if (legacy) { \
        pcmk__g_strcat(s, k "=", pcmk__s(v, ""), " ", NULL); \
    } else { \
        pcmk__g_strcat(s, k "=\"", pcmk__s(v, ""), "\" ", NULL); \
    } \
} while (0)

PCMK__OUTPUT_ARGS("attribute", "const char *", "const char *", "const char *",
                  "const char *", "const char *", "bool", "bool")
static int
attribute_default(pcmk__output_t *out, va_list args)
{
    const char *scope = va_arg(args, const char *);
    const char *instance = va_arg(args, const char *);
    const char *name = va_arg(args, const char *);
    const char *value = va_arg(args, const char *);
    const char *host = va_arg(args, const char *);
    bool quiet = va_arg(args, int);
    bool legacy = va_arg(args, int);

    gchar *value_esc = NULL;
    GString *s = NULL;

    if (quiet) {
        if (value != NULL) {
            /* Quiet needs to be turned off for ->info() to do anything */
            bool was_quiet = out->is_quiet(out);

            if (was_quiet) {
                out->quiet = false;
            }

            out->info(out, "%s", value);

            out->quiet = was_quiet;
        }

        return pcmk_rc_ok;
    }

    s = g_string_sized_new(50);

    value_esc = pcmk__xml_escape(value, pcmk__xml_escape_attr_pretty);

    if (!pcmk__str_empty(scope)) {
        KV_PAIR(PCMK_XA_SCOPE, scope);
    }

    if (!pcmk__str_empty(instance)) {
        KV_PAIR(PCMK_XA_ID, instance);
    }

    KV_PAIR(PCMK_XA_NAME, name);

    if (!pcmk__str_empty(host)) {
        KV_PAIR(PCMK_XA_HOST, host);
    }

    if (legacy) {
        pcmk__g_strcat(s, PCMK_XA_VALUE "=", pcmk__s(value_esc, "(null)"),
                       NULL);
    } else {
        pcmk__g_strcat(s, PCMK_XA_VALUE "=\"", pcmk__s(value_esc, ""), "\"",
                       NULL);
    }

    out->info(out, "%s", s->str);

    g_free(value_esc);
    g_string_free(s, TRUE);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("attribute", "const char *", "const char *", "const char *",
                  "const char *", "const char *", "bool", "bool")
static int
attribute_xml(pcmk__output_t *out, va_list args)
{
    const char *scope = va_arg(args, const char *);
    const char *instance = va_arg(args, const char *);
    const char *name = va_arg(args, const char *);
    const char *value = va_arg(args, const char *);
    const char *host = va_arg(args, const char *);
    bool quiet G_GNUC_UNUSED = va_arg(args, int);
    bool legacy G_GNUC_UNUSED = va_arg(args, int);

    xmlNodePtr node = NULL;

    node = pcmk__output_create_xml_node(out, PCMK_XE_ATTRIBUTE,
                                        PCMK_XA_NAME, name,
                                        PCMK_XA_VALUE, pcmk__s(value, ""),
                                        NULL);

    if (!pcmk__str_empty(scope)) {
        pcmk__xe_set(node, PCMK_XA_SCOPE, scope);
    }

    if (!pcmk__str_empty(instance)) {
        pcmk__xe_set(node, PCMK_XA_ID, instance);
    }

    if (!pcmk__str_empty(host)) {
        pcmk__xe_set(node, PCMK_XA_HOST, host);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("rule-check", "const char *", "int", "const char *")
static int
rule_check_default(pcmk__output_t *out, va_list args)
{
    const char *rule_id = va_arg(args, const char *);
    int result = va_arg(args, int);
    const char *error = va_arg(args, const char *);

    switch (result) {
        case pcmk_rc_within_range:
            return out->info(out, "Rule %s is still in effect", rule_id);
        case pcmk_rc_ok:
            return out->info(out, "Rule %s satisfies conditions", rule_id);
        case pcmk_rc_after_range:
            return out->info(out, "Rule %s is expired", rule_id);
        case pcmk_rc_before_range:
            return out->info(out, "Rule %s has not yet taken effect", rule_id);
        case pcmk_rc_op_unsatisfied:
            return out->info(out, "Rule %s does not satisfy conditions",
                             rule_id);
        default:
            out->err(out,
                     "Could not determine whether rule %s is in effect: %s",
                     rule_id, ((error != NULL)? error : "unexpected error"));
            return pcmk_rc_ok;
    }
}

PCMK__OUTPUT_ARGS("rule-check", "const char *", "int", "const char *")
static int
rule_check_xml(pcmk__output_t *out, va_list args)
{
    const char *rule_id = va_arg(args, const char *);
    int result = va_arg(args, int);
    const char *error = va_arg(args, const char *);

    char *rc_str = pcmk__itoa(pcmk_rc2exitc(result));

    pcmk__output_create_xml_node(out, PCMK_XE_RULE_CHECK,
                                 PCMK_XA_RULE_ID, rule_id,
                                 PCMK_XA_RC, rc_str,
                                 NULL);
    free(rc_str);

    switch (result) {
        case pcmk_rc_within_range:
        case pcmk_rc_ok:
        case pcmk_rc_after_range:
        case pcmk_rc_before_range:
        case pcmk_rc_op_unsatisfied:
            return pcmk_rc_ok;
        default:
            out->err(out,
                    "Could not determine whether rule %s is in effect: %s",
                    rule_id, ((error != NULL)? error : "unexpected error"));
            return pcmk_rc_ok;
    }
}

PCMK__OUTPUT_ARGS("result-code", "int", "const char *", "const char *")
static int
result_code_none(pcmk__output_t *out, va_list args)
{
    return pcmk_rc_no_output;
}

PCMK__OUTPUT_ARGS("result-code", "int", "const char *", "const char *")
static int
result_code_text(pcmk__output_t *out, va_list args)
{
    int code = va_arg(args, int);
    const char *name = va_arg(args, const char *);
    const char *desc = va_arg(args, const char *);

    static int code_width = 0;

    if (out->is_quiet(out)) {
        /* If out->is_quiet(), don't print the code. Print name and/or desc in a
         * compact format for text output, or print nothing at all for none-type
         * output.
         */
        if ((name != NULL) && (desc != NULL)) {
            pcmk__formatted_printf(out, "%s - %s\n", name, desc);

        } else if ((name != NULL) || (desc != NULL)) {
            pcmk__formatted_printf(out, "%s\n", ((name != NULL)? name : desc));
        }
        return pcmk_rc_ok;
    }

    /* Get length of longest (most negative) standard Pacemaker return code
     * This should be longer than all the values of any other type of return
     * code.
     */
    if (code_width == 0) {
        long long most_negative = pcmk_rc_error - (long long) pcmk__n_rc + 1;

        code_width = snprintf(NULL, 0, "%lld", most_negative);
        pcmk__assert(code_width >= 0);
    }

    if ((name != NULL) && (desc != NULL)) {
        static int name_width = 0;

        if (name_width == 0) {
            // Get length of longest standard Pacemaker return code name
            for (int lpc = 0; lpc < pcmk__n_rc; lpc++) {
                int len = (int) strlen(pcmk_rc_name(pcmk_rc_error - lpc));
                name_width = QB_MAX(name_width, len);
            }
        }
        return out->info(out, "% *d: %-*s  %s", code_width, code, name_width,
                         name, desc);
    }

    if ((name != NULL) || (desc != NULL)) {
        return out->info(out, "% *d: %s", code_width, code,
                         ((name != NULL)? name : desc));
    }

    return out->info(out, "% *d", code_width, code);
}

PCMK__OUTPUT_ARGS("result-code", "int", "const char *", "const char *")
static int
result_code_xml(pcmk__output_t *out, va_list args)
{
    int code = va_arg(args, int);
    const char *name = va_arg(args, const char *);
    const char *desc = va_arg(args, const char *);

    char *code_str = pcmk__itoa(code);

    pcmk__output_create_xml_node(out, PCMK_XE_RESULT_CODE,
                                 PCMK_XA_CODE, code_str,
                                 PCMK_XA_NAME, name,
                                 PCMK_XA_DESCRIPTION, desc,
                                 NULL);
    free(code_str);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ticket-attribute", "const char *", "const char *", "const char *")
static int
ticket_attribute_default(pcmk__output_t *out, va_list args)
{
    const char *ticket_id G_GNUC_UNUSED = va_arg(args, const char *);
    const char *name G_GNUC_UNUSED = va_arg(args, const char *);
    const char *value = va_arg(args, const char *);

    out->info(out, "%s", value);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ticket-attribute", "const char *", "const char *", "const char *")
static int
ticket_attribute_xml(pcmk__output_t *out, va_list args)
{
    const char *ticket_id = va_arg(args, const char *);
    const char *name = va_arg(args, const char *);
    const char *value = va_arg(args, const char *);
    xmlNode *xml = NULL;

    /* Create:
     * <tickets>
     *   <ticket id="">
     *     <attribute name="" value="" />
     *   </ticket>
     * </tickets>
     */
    pcmk__output_xml_create_parent(out, PCMK_XE_TICKETS);

    xml = pcmk__output_xml_create_parent(out, PCMK_XE_TICKET);
    pcmk__xe_set(xml, PCMK_XA_ID, ticket_id);

    pcmk__output_create_xml_node(out, PCMK_XA_ATTRIBUTE,
                                 PCMK_XA_NAME, name,
                                 PCMK_XA_VALUE, value,
                                 NULL);
    pcmk__output_xml_pop_parent(out);
    pcmk__output_xml_pop_parent(out);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ticket-constraints", "xmlNode *")
static int
ticket_constraints_default(pcmk__output_t *out, va_list args)
{
    xmlNode *constraint_xml = va_arg(args, xmlNode *);

    /* constraint_xml can take two forms:
     *
     * <rsc_ticket id="rsc1-req-ticketA" rsc="rsc1" ticket="ticketA" ... />
     *
     * for when there's only one ticket in the CIB, or when the user asked
     * for a specific ticket (crm_ticket -c -t for instance)
     *
     * <xpath-query>
     *   <rsc_ticket id="rsc1-req-ticketA" rsc="rsc1" ticket="ticketA" ... />
     *   <rsc_ticket id="rsc1-req-ticketB" rsc="rsc2" ticket="ticketB" ... />
     * </xpath-query>
     *
     * for when there's multiple tickets in the and the user did not ask for
     * a specific one.
     *
     * In both cases, we simply output a <rsc_ticket> element for each ticket
     * in the results.
     */
    out->info(out, "Constraints XML:\n");

    if (pcmk__xe_is(constraint_xml, PCMK__XE_XPATH_QUERY)) {
        xmlNode *child = pcmk__xe_first_child(constraint_xml, NULL, NULL, NULL);

        do {
            GString *buf = g_string_sized_new(1024);

            pcmk__xml_string(child, pcmk__xml_fmt_pretty, buf, 0);
            out->output_xml(out, PCMK_XE_CONSTRAINT, buf->str);
            g_string_free(buf, TRUE);

            child = pcmk__xe_next(child, NULL);
        } while (child != NULL);
    } else {
        GString *buf = g_string_sized_new(1024);

        pcmk__xml_string(constraint_xml, pcmk__xml_fmt_pretty, buf, 0);
        out->output_xml(out, PCMK_XE_CONSTRAINT, buf->str);
        g_string_free(buf, TRUE);
    }

    return pcmk_rc_ok;
}

static int
add_ticket_element_with_constraints(xmlNode *node, void *userdata)
{
    pcmk__output_t *out = (pcmk__output_t *) userdata;
    const char *ticket_id = pcmk__xe_get(node, PCMK_XA_TICKET);
    xmlNode *xml = NULL;

    xml = pcmk__output_xml_create_parent(out, PCMK_XE_TICKET);
    pcmk__xe_set(xml, PCMK_XA_ID, ticket_id);

    pcmk__output_xml_create_parent(out, PCMK_XE_CONSTRAINTS);
    pcmk__output_xml_add_node_copy(out, node);

    /* Pop two parents so now we are back under the <tickets> element */
    pcmk__output_xml_pop_parent(out);
    pcmk__output_xml_pop_parent(out);

    return pcmk_rc_ok;
}

static int
add_resource_element(xmlNode *node, void *userdata)
{
    pcmk__output_t *out = (pcmk__output_t *) userdata;
    const char *rsc = pcmk__xe_get(node, PCMK_XA_RSC);

    pcmk__output_create_xml_node(out, PCMK_XE_RESOURCE,
                                 PCMK_XA_ID, rsc, NULL);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ticket-constraints", "xmlNode *")
static int
ticket_constraints_xml(pcmk__output_t *out, va_list args)
{
    xmlNode *constraint_xml = va_arg(args, xmlNode *);

    /* Create:
     * <tickets>
     *   <ticket id="">
     *     <constraints>
     *       <rsc_ticket />
     *     </constraints>
     *   </ticket>
     *   ...
     * </tickets>
     */
    pcmk__output_xml_create_parent(out, PCMK_XE_TICKETS);

    if (pcmk__xe_is(constraint_xml, PCMK__XE_XPATH_QUERY)) {
        /* Iterate through the list of children once to create all the
         * ticket/constraint elements.
         */
        pcmk__xe_foreach_child(constraint_xml, NULL, add_ticket_element_with_constraints, out);

        /* Put us back at the same level as where <tickets> was created. */
        pcmk__output_xml_pop_parent(out);

        /* Constraints can reference a resource ID that is defined in the XML
         * schema as an IDREF.  This requires some other element to be present
         * with an id= attribute that matches.
         *
         * Iterate through the list of children a second time to create the
         * following:
         *
         * <resources>
         *   <resource id="" />
         *   ...
         * </resources>
         */
        pcmk__output_xml_create_parent(out, PCMK_XE_RESOURCES);
        pcmk__xe_foreach_child(constraint_xml, NULL, add_resource_element, out);
        pcmk__output_xml_pop_parent(out);

    } else {
        /* Creating the output for a single constraint is much easier.  All the
         * comments in the above block apply here.
         */
        add_ticket_element_with_constraints(constraint_xml, out);
        pcmk__output_xml_pop_parent(out);

        pcmk__output_xml_create_parent(out, PCMK_XE_RESOURCES);
        add_resource_element(constraint_xml, out);
        pcmk__output_xml_pop_parent(out);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ticket-state", "xmlNode *")
static int
ticket_state_default(pcmk__output_t *out, va_list args)
{
    xmlNode *state_xml = va_arg(args, xmlNode *);

    GString *buf = g_string_sized_new(1024);

    out->info(out, "State XML:\n");
    pcmk__xml_string(state_xml, pcmk__xml_fmt_pretty, buf, 0);
    out->output_xml(out, PCMK__XE_TICKET_STATE, buf->str);

    g_string_free(buf, TRUE);
    return pcmk_rc_ok;
}

static int
add_ticket_element(xmlNode *node, void *userdata)
{
    pcmk__output_t *out = (pcmk__output_t *) userdata;
    xmlNode *ticket_node = NULL;

    ticket_node = pcmk__output_create_xml_node(out, PCMK_XE_TICKET, NULL);
    pcmk__xe_copy_attrs(ticket_node, node, pcmk__xaf_none);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ticket-state", "xmlNode *")
static int
ticket_state_xml(pcmk__output_t *out, va_list args)
{
    xmlNode *state_xml = va_arg(args, xmlNode *);

    /* Create:
     * <tickets>
     *   <ticket />
     *   ...
     * </tickets>
     */
    pcmk__output_xml_create_parent(out, PCMK_XE_TICKETS);

    if (state_xml->children != NULL) {
        /* Iterate through the list of children once to create all the
         * ticket elements.
         */
        pcmk__xe_foreach_child(state_xml, PCMK__XE_TICKET_STATE, add_ticket_element, out);

    } else {
        add_ticket_element(state_xml, out);
    }

    pcmk__output_xml_pop_parent(out);
    return pcmk_rc_ok;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "attribute", "default", attribute_default },
    { "attribute", "xml", attribute_xml },
    { "cluster-status", "default", pcmk__cluster_status_text },
    { "cluster-status", "html", cluster_status_html },
    { "cluster-status", "xml", cluster_status_xml },
    { "crmadmin-node", "default", crmadmin_node },
    { "crmadmin-node", "text", crmadmin_node_text },
    { "crmadmin-node", "xml", crmadmin_node_xml },
    { "dc", "default", dc },
    { "dc", "text", dc_text },
    { "dc", "xml", dc_xml },
    { "digests", "default", digests_text },
    { "digests", "xml", digests_xml },
    { "health", "default", health },
    { "health", "text", health_text },
    { "health", "xml", health_xml },
    { "inject-attr", "default", inject_attr },
    { "inject-attr", "xml", inject_attr_xml },
    { "inject-cluster-action", "default", inject_cluster_action },
    { "inject-cluster-action", "xml", inject_cluster_action_xml },
    { "inject-fencing-action", "default", inject_fencing_action },
    { "inject-fencing-action", "xml", inject_fencing_action_xml },
    { "inject-modify-config", "default", inject_modify_config },
    { "inject-modify-config", "xml", inject_modify_config_xml },
    { "inject-modify-node", "default", inject_modify_node },
    { "inject-modify-node", "xml", inject_modify_node_xml },
    { "inject-modify-ticket", "default", inject_modify_ticket },
    { "inject-modify-ticket", "xml", inject_modify_ticket_xml },
    { "inject-pseudo-action", "default", inject_pseudo_action },
    { "inject-pseudo-action", "xml", inject_pseudo_action_xml },
    { "inject-rsc-action", "default", inject_rsc_action },
    { "inject-rsc-action", "xml", inject_rsc_action_xml },
    { "inject-spec", "default", inject_spec },
    { "inject-spec", "xml", inject_spec_xml },
    { "locations-and-colocations", "default", locations_and_colocations },
    { "locations-and-colocations", "xml", locations_and_colocations_xml },
    { "locations-list", "default", locations_list },
    { "locations-list", "xml", locations_list_xml },
    { "node-action", "default", node_action },
    { "node-action", "xml", node_action_xml },
    { "node-info", "default", node_info_default },
    { "node-info", "xml", node_info_xml },
    { "pacemakerd-health", "default", pacemakerd_health },
    { "pacemakerd-health", "html", pacemakerd_health_html },
    { "pacemakerd-health", "text", pacemakerd_health_text },
    { "pacemakerd-health", "xml", pacemakerd_health_xml },
    { "profile", "default", profile_default, },
    { "profile", "xml", profile_xml },
    { "result-code", PCMK_VALUE_NONE, result_code_none },
    { "result-code", "text", result_code_text },
    { "result-code", "xml", result_code_xml },
    { "rsc-action", "default", rsc_action_default },
    { "rsc-action-item", "default", rsc_action_item },
    { "rsc-action-item", "xml", rsc_action_item_xml },
    { "rsc-is-colocated-with-list", "default", rsc_is_colocated_with_list },
    { "rsc-is-colocated-with-list", "xml", rsc_is_colocated_with_list_xml },
    { "rscs-colocated-with-list", "default", rscs_colocated_with_list },
    { "rscs-colocated-with-list", "xml", rscs_colocated_with_list_xml },
    { "rule-check", "default", rule_check_default },
    { "rule-check", "xml", rule_check_xml },
    { "ticket-attribute", "default", ticket_attribute_default },
    { "ticket-attribute", "xml", ticket_attribute_xml },
    { "ticket-constraints", "default", ticket_constraints_default },
    { "ticket-constraints", "xml", ticket_constraints_xml },
    { "ticket-state", "default", ticket_state_default },
    { "ticket-state", "xml", ticket_state_xml },

    { NULL, NULL, NULL }
};

void
pcmk__register_lib_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}
