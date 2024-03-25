/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/cib/internal.h>
#include <crm/pengine/internal.h>

#include <pacemaker.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

static int
build_ticket_modify_xml(cib_t *cib, const char *ticket_id, xmlNode **ticket_state_xml,
                        xmlNode **xml_top)
{
    int rc = pcmk__get_ticket_state(cib, ticket_id, ticket_state_xml);

    if (rc == pcmk_rc_ok || rc == pcmk_rc_duplicate_id) {
        /* Ticket(s) found - return their state */
        *xml_top = *ticket_state_xml;

    } else if (rc == ENXIO) {
        /* No ticket found - build the XML needed to create it */
        xmlNode *xml_obj = NULL;

        *xml_top = pcmk__xe_create(NULL, PCMK_XE_STATUS);
        xml_obj = pcmk__xe_create(*xml_top, PCMK_XE_TICKETS);
        *ticket_state_xml = pcmk__xe_create(xml_obj, PCMK__XE_TICKET_STATE);
        crm_xml_add(*ticket_state_xml, PCMK_XA_ID, ticket_id);

        rc = pcmk_rc_ok;

    } else {
        /* Some other error occurred - clean up and return */
        free_xml(*ticket_state_xml);
    }

    return rc;
}

int
pcmk__get_ticket_state(cib_t *cib, const char *ticket_id, xmlNode **state)
{
    int rc = pcmk_rc_ok;
    xmlNode *xml_search = NULL;
    char *xpath = NULL;

    CRM_ASSERT(cib!= NULL && state != NULL);
    *state = NULL;

    if (ticket_id != NULL) {
        xpath = crm_strdup_printf("/" PCMK_XE_CIB "/" PCMK_XE_STATUS "/" PCMK_XE_TICKETS
                                  "/" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"%s\"]",
                                  ticket_id);
    } else {
        xpath = crm_strdup_printf("/" PCMK_XE_CIB "/" PCMK_XE_STATUS "/" PCMK_XE_TICKETS);
    }

    rc = cib->cmds->query(cib, xpath, &xml_search,
                          cib_sync_call | cib_scope_local | cib_xpath);
    rc = pcmk_legacy2rc(rc);

    if (rc == pcmk_rc_ok) {
        crm_log_xml_debug(xml_search, "Match");

        if (xml_search->children != NULL && ticket_id != NULL) {
            rc = pcmk_rc_duplicate_id;
        }
    }

    free(xpath);

    *state = xml_search;
    return rc;
}

int
pcmk__ticket_constraints(pcmk__output_t *out, cib_t *cib, const char *ticket_id)
{
    int rc = pcmk_rc_ok;
    xmlNode *result = NULL;
    const char *xpath_base = NULL;
    char *xpath = NULL;

    CRM_ASSERT(out != NULL && cib != NULL);

    xpath_base = pcmk_cib_xpath_for(PCMK_XE_CONSTRAINTS);
    CRM_ASSERT(xpath_base != NULL);

    if (ticket_id != NULL) {
        xpath = crm_strdup_printf("%s/" PCMK_XE_RSC_TICKET "[@" PCMK_XA_TICKET "=\"%s\"]",
                                  xpath_base, ticket_id);
    } else {
        xpath = crm_strdup_printf("%s/" PCMK_XE_RSC_TICKET, xpath_base);
    }

    rc = cib->cmds->query(cib, (const char *) xpath, &result,
                          cib_sync_call | cib_scope_local | cib_xpath);
    rc = pcmk_legacy2rc(rc);

    if (result != NULL) {
        out->message(out, "ticket-constraints", result);
        free_xml(result);
    }

    free(xpath);
    return rc;
}

int
pcmk_ticket_constraints(xmlNodePtr *xml, const char *ticket_id)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;
    cib_t *cib = NULL;

    rc = pcmk__setup_output_cib_sched(&out, &cib, NULL, xml);
    if (rc != pcmk_rc_ok) {
        goto done;
    }

    rc = pcmk__ticket_constraints(out, cib, ticket_id);

done:
    if (cib != NULL) {
        cib__clean_up_connection(&cib);
    }

    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    return rc;
}

static int
delete_single_ticket(xmlNode *child, void *userdata)
{
    int rc = pcmk_rc_ok;
    cib_t *cib = (cib_t *) userdata;

    rc = cib->cmds->remove(cib, PCMK_XE_STATUS, child, cib_sync_call);
    rc = pcmk_legacy2rc(rc);

    return rc;
}

int
pcmk__ticket_delete(pcmk__output_t *out, cib_t *cib, pcmk_scheduler_t *scheduler,
                    const char *ticket_id, bool force)
{
    int rc = pcmk_rc_ok;
    xmlNode *state = NULL;

    CRM_ASSERT(cib != NULL && scheduler != NULL);

    if (ticket_id == NULL) {
        return EINVAL;
    }

    if (!force) {
        pcmk_ticket_t *ticket = g_hash_table_lookup(scheduler->tickets, ticket_id);

        if (ticket == NULL) {
            return ENXIO;
        }

        if (ticket->granted) {
            return EACCES;
        }
    }

    rc = pcmk__get_ticket_state(cib, ticket_id, &state);

    if (rc == pcmk_rc_duplicate_id) {
        out->info(out, "Multiple " PCMK__XE_TICKET_STATE "s match ticket=%s",
                  ticket_id);

    } else if (rc == ENXIO) {
        return pcmk_rc_ok;

    } else if (rc != pcmk_rc_ok) {
        return rc;
    }

    crm_log_xml_debug(state, "Delete");

    if (rc == pcmk_rc_duplicate_id) {
        rc = pcmk__xe_foreach_child(state, NULL, delete_single_ticket, cib);
    } else {
        rc = delete_single_ticket(state, cib);
    }

    if (rc == pcmk_rc_ok) {
        out->info(out, "Cleaned up %s", ticket_id);
    }

    free_xml(state);
    return rc;
}

int
pcmk_ticket_delete(xmlNodePtr *xml, const char *ticket_id, bool force)
{
    pcmk_scheduler_t *scheduler = NULL;
    pcmk__output_t *out = NULL;
    cib_t *cib = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__setup_output_cib_sched(&out, &cib, &scheduler, xml);
    if (rc != pcmk_rc_ok) {
        goto done;
    }

    rc = pcmk__ticket_delete(out, cib, scheduler, ticket_id, force);

done:
    if (cib != NULL) {
        cib__clean_up_connection(&cib);
    }

    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    pe_free_working_set(scheduler);
    return rc;
}

int
pcmk__ticket_get_attr(pcmk__output_t *out, pcmk_scheduler_t *scheduler,
                      const char *ticket_id, const char *attr_name,
                      const char *attr_default)
{
    int rc = pcmk_rc_ok;
    const char *attr_value = NULL;
    pcmk_ticket_t *ticket = NULL;

    CRM_ASSERT(out != NULL && scheduler != NULL);

    if (ticket_id == NULL || attr_name == NULL) {
        return EINVAL;
    }

    ticket = g_hash_table_lookup(scheduler->tickets, ticket_id);

    if (ticket != NULL) {
        attr_value = g_hash_table_lookup(ticket->state, attr_name);
    }

    if (attr_value != NULL) {
        out->message(out, "ticket-attribute", ticket_id, attr_name, attr_value);
    } else if (attr_default != NULL) {
        out->message(out, "ticket-attribute", ticket_id, attr_name, attr_default);
    } else {
        rc = ENXIO;
    }

    return rc;
}

int
pcmk_ticket_get_attr(xmlNodePtr *xml, const char *ticket_id,
                     const char *attr_name, const char *attr_default)
{
    pcmk_scheduler_t *scheduler = NULL;
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__setup_output_cib_sched(&out, NULL, &scheduler, xml);
    if (rc != pcmk_rc_ok) {
        goto done;
    }

    rc = pcmk__ticket_get_attr(out, scheduler, ticket_id, attr_name, attr_default);

done:
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    pe_free_working_set(scheduler);
    return rc;
}

int
pcmk__ticket_info(pcmk__output_t *out, pcmk_scheduler_t *scheduler,
                  const char *ticket_id, bool details, bool raw)
{
    int rc = pcmk_rc_ok;

    CRM_ASSERT(out != NULL && scheduler != NULL);

    if (ticket_id != NULL) {
        GHashTable *tickets = NULL;
        pcmk_ticket_t *ticket = g_hash_table_lookup(scheduler->tickets, ticket_id);

        if (ticket == NULL) {
            return ENXIO;
        }

        /* The ticket-list message expects a GHashTable, so we'll construct
         * one with just this single item.
         */
        tickets = pcmk__strkey_table(free, NULL);
        g_hash_table_insert(tickets, strdup(ticket->id), ticket);
        out->message(out, "ticket-list", tickets, false, raw, details);
        g_hash_table_destroy(tickets);

    } else {
        out->message(out, "ticket-list", scheduler->tickets, false, raw, details);
    }

    return rc;
}

int
pcmk_ticket_info(xmlNodePtr *xml, const char *ticket_id)
{
    pcmk_scheduler_t *scheduler = NULL;
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__setup_output_cib_sched(&out, NULL, &scheduler, xml);
    if (rc != pcmk_rc_ok) {
        goto done;
    }

    pe__register_messages(out);

    /* XML output (which is the only format supported by public API functions
     * due to the use of pcmk__xml_output_new above) always prints all details,
     * so just pass false for the last two arguments.
     */
    rc = pcmk__ticket_info(out, scheduler, ticket_id, false, false);

done:
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    pe_free_working_set(scheduler);
    return rc;
}

int
pcmk__ticket_remove_attr(pcmk__output_t *out, cib_t *cib, pcmk_scheduler_t *scheduler,
                         const char *ticket_id, GList *attr_delete)
{
    xmlNode *ticket_state_xml = NULL;
    xmlNode *xml_top = NULL;
    int rc = pcmk_rc_ok;

    CRM_ASSERT(out != NULL && cib != NULL && scheduler != NULL);

    if (ticket_id == NULL) {
        return EINVAL;
    }

    /* Nothing to do */
    if (attr_delete == NULL) {
        return pcmk_rc_ok;
    }

    rc = build_ticket_modify_xml(cib, ticket_id, &ticket_state_xml, &xml_top);

    if (rc == pcmk_rc_duplicate_id) {
        out->info(out, "Multiple " PCMK__XE_TICKET_STATE "s match ticket=%s", ticket_id);
    } else if (rc != pcmk_rc_ok) {
        free_xml(ticket_state_xml);
        return rc;
    }

    for (GList *list_iter = attr_delete; list_iter != NULL; list_iter = list_iter->next) {
        const char *key = list_iter->data;
        pcmk__xe_remove_attr(ticket_state_xml, key);
    }

    crm_log_xml_debug(xml_top, "Replace");
    rc = cib->cmds->replace(cib, PCMK_XE_STATUS, ticket_state_xml, cib_sync_call);
    rc = pcmk_legacy2rc(rc);

    free_xml(xml_top);
    return rc;
}

int
pcmk_ticket_remove_attr(xmlNodePtr *xml, const char *ticket_id, GList *attr_delete)
{
    pcmk_scheduler_t *scheduler = NULL;
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;
    cib_t *cib = NULL;

    rc = pcmk__setup_output_cib_sched(&out, &cib, &scheduler, xml);
    if (rc != pcmk_rc_ok) {
        goto done;
    }

    rc = pcmk__ticket_remove_attr(out, cib, scheduler, ticket_id, attr_delete);

done:
    if (cib != NULL) {
        cib__clean_up_connection(&cib);
    }

    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    pe_free_working_set(scheduler);
    return rc;
}

int
pcmk__ticket_state(pcmk__output_t *out, cib_t *cib, const char *ticket_id)
{
    xmlNode *state_xml = NULL;
    int rc = pcmk_rc_ok;

    CRM_ASSERT(out != NULL && cib != NULL);

    rc = pcmk__get_ticket_state(cib, ticket_id, &state_xml);

    if (rc == pcmk_rc_duplicate_id) {
        out->info(out, "Multiple " PCMK__XE_TICKET_STATE "s match ticket=%s",
                  ticket_id);
    }

    if (state_xml != NULL) {
        out->message(out, "ticket-state", state_xml);
        free_xml(state_xml);
    }

    return rc;
}

int
pcmk_ticket_state(xmlNodePtr *xml, const char *ticket_id)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;
    cib_t *cib = NULL;

    rc = pcmk__setup_output_cib_sched(&out, &cib, NULL, xml);
    if (rc != pcmk_rc_ok) {
        goto done;
    }

    rc = pcmk__ticket_state(out, cib, ticket_id);

done:
    if (cib != NULL) {
        cib__clean_up_connection(&cib);
    }

    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    return rc;
}
