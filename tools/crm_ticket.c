/*
 * Copyright 2012-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>

#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include <crm/common/xml.h>
#include <crm/common/ipc.h>
#include <crm/common/cmdline_internal.h>

#include <crm/cib.h>
#include <crm/cib/internal.h>
#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>

#include <pacemaker-internal.h>

GError *error = NULL;

#define SUMMARY "Perform tasks related to cluster tickets\n\n" \
                "Allows ticket attributes to be queried, modified and deleted."

struct {
    gchar *attr_default;
    gchar *attr_id;
    char *attr_name;
    char *attr_value;
    gboolean force;
    char *get_attr_name;
    gboolean quiet;
    gchar *set_name;
    char ticket_cmd;
    gchar *ticket_id;
    gchar *xml_file;
} options = {
    .ticket_cmd = 'S'
};

GList *attr_delete;
GHashTable *attr_set;
bool modified = false;
int cib_options = cib_sync_call;
static pcmk__output_t *out = NULL;

#define INDENT "                               "

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

static gboolean
attr_value_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    pcmk__str_update(&options.attr_value, optarg);

    if (!options.attr_name || !options.attr_value) {
        return TRUE;
    }

    pcmk__insert_dup(attr_set, options.attr_name, options.attr_value);
    pcmk__str_update(&options.attr_name, NULL);
    pcmk__str_update(&options.attr_value, NULL);

    modified = true;

    return TRUE;
}

static gboolean
command_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    if (pcmk__str_any_of(option_name, "--info", "-l", NULL)) {
        options.ticket_cmd = 'l';
    } else if (pcmk__str_any_of(option_name, "--details", "-L", NULL)) {
        options.ticket_cmd = 'L';
    } else if (pcmk__str_any_of(option_name, "--raw", "-w", NULL)) {
        options.ticket_cmd = 'w';
    } else if (pcmk__str_any_of(option_name, "--query-xml", "-q", NULL)) {
        options.ticket_cmd = 'q';
    } else if (pcmk__str_any_of(option_name, "--constraints", "-c", NULL)) {
        options.ticket_cmd = 'c';
    } else if (pcmk__str_any_of(option_name, "--cleanup", "-C", NULL)) {
        options.ticket_cmd = 'C';
    }

    return TRUE;
}

static gboolean
delete_attr_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    attr_delete = g_list_append(attr_delete, strdup(optarg));
    modified = true;
    return TRUE;
}

static gboolean
get_attr_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    pcmk__str_update(&options.get_attr_name, optarg);
    options.ticket_cmd = 'G';
    return TRUE;
}

static gboolean
grant_standby_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    if (pcmk__str_any_of(option_name, "--grant", "-g", NULL)) {
        pcmk__insert_dup(attr_set, PCMK__XA_GRANTED, PCMK_VALUE_TRUE);
        modified = true;
    } else if (pcmk__str_any_of(option_name, "--revoke", "-r", NULL)) {
        pcmk__insert_dup(attr_set, PCMK__XA_GRANTED, PCMK_VALUE_FALSE);
        modified = true;
    } else if (pcmk__str_any_of(option_name, "--standby", "-s", NULL)) {
        pcmk__insert_dup(attr_set, PCMK_XA_STANDBY, PCMK_VALUE_TRUE);
        modified = true;
    } else if (pcmk__str_any_of(option_name, "--activate", "-a", NULL)) {
        pcmk__insert_dup(attr_set, PCMK_XA_STANDBY, PCMK_VALUE_FALSE);
        modified = true;
    }

    return TRUE;
}

static gboolean
set_attr_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    pcmk__str_update(&options.attr_name, optarg);

    if (!options.attr_name || !options.attr_value) {
        return TRUE;
    }

    pcmk__insert_dup(attr_set, options.attr_name, options.attr_value);
    pcmk__str_update(&options.attr_name, NULL);
    pcmk__str_update(&options.attr_value, NULL);

    modified = true;

    return TRUE;
}

static GOptionEntry query_entries[] = {
    { "info", 'l', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the information of ticket(s)",
      NULL },

    { "details", 'L', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the details of ticket(s)",
      NULL },

    { "raw", 'w', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the IDs of ticket(s)",
      NULL },

    { "query-xml", 'q', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Query the XML of ticket(s)",
      NULL },

    { "constraints", 'c', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the " PCMK_XE_RSC_TICKET " constraints that apply to ticket(s)",
      NULL },

    { NULL }
};

static GOptionEntry command_entries[] = {
    { "grant", 'g', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, grant_standby_cb,
      "Grant a ticket to this cluster site",
      NULL },

    { "revoke", 'r', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, grant_standby_cb,
      "Revoke a ticket from this cluster site",
      NULL },

    { "standby", 's', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, grant_standby_cb,
      "Tell this cluster site this ticket is standby",
      NULL },

    { "activate", 'a', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, grant_standby_cb,
      "Tell this cluster site this ticket is active",
      NULL },

    { NULL }
};

static GOptionEntry advanced_entries[] = {
    { "get-attr", 'G', 0, G_OPTION_ARG_CALLBACK, get_attr_cb,
      "Display the named attribute for a ticket",
      "ATTRIBUTE" },

    { "set-attr", 'S', 0, G_OPTION_ARG_CALLBACK, set_attr_cb,
      "Set the named attribute for a ticket",
      "ATTRIBUTE" },

    { "delete-attr", 'D', 0, G_OPTION_ARG_CALLBACK, delete_attr_cb,
      "Delete the named attribute for a ticket",
      "ATTRIBUTE" },

    { "cleanup", 'C', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Delete all state of a ticket at this cluster site",
      NULL },

    { NULL}
};

static GOptionEntry addl_entries[] = {
    { "attr-value", 'v', 0, G_OPTION_ARG_CALLBACK, attr_value_cb,
      "Attribute value to use with -S",
      "VALUE" },

    { "default", 'd', 0, G_OPTION_ARG_STRING, &options.attr_default,
      "(Advanced) Default attribute value to display if none is found\n"
      INDENT "(for use with -G)",
      "VALUE" },

    { "force", 'f', 0, G_OPTION_ARG_NONE, &options.force,
      "(Advanced) Force the action to be performed",
      NULL },

    { "ticket", 't', 0, G_OPTION_ARG_STRING, &options.ticket_id,
      "Ticket ID",
      "ID" },

    { "xml-file", 'x', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &options.xml_file,
      NULL,
      NULL },

    { NULL }
};

static GOptionEntry deprecated_entries[] = {
    { "set-name", 'n', 0, G_OPTION_ARG_STRING, &options.set_name,
      "(Advanced) ID of the " PCMK_XE_INSTANCE_ATTRIBUTES " object to change",
      "ID" },

    { "nvpair", 'i', 0, G_OPTION_ARG_STRING, &options.attr_id,
      "(Advanced) ID of the nvpair object to change/delete",
      "ID" },

    { "quiet", 'Q', 0, G_OPTION_ARG_NONE, &options.quiet,
      "Print only the value on stdout",
      NULL },

    { NULL }
};

static pcmk_ticket_t *
find_ticket(gchar *ticket_id, pcmk_scheduler_t *scheduler)
{
    return g_hash_table_lookup(scheduler->tickets, ticket_id);
}

static int
find_ticket_state(cib_t * the_cib, gchar *ticket_id, xmlNode ** ticket_state_xml)
{
    int rc = pcmk_rc_ok;
    xmlNode *xml_search = NULL;

    GString *xpath = NULL;

    CRM_ASSERT(ticket_state_xml != NULL);
    *ticket_state_xml = NULL;

    xpath = g_string_sized_new(1024);
    g_string_append(xpath,
                    "/" PCMK_XE_CIB "/" PCMK_XE_STATUS "/" PCMK_XE_TICKETS);

    if (ticket_id != NULL) {
        pcmk__g_strcat(xpath,
                       "/" PCMK__XE_TICKET_STATE
                       "[@" PCMK_XA_ID "=\"", ticket_id, "\"]", NULL);
    }

    rc = the_cib->cmds->query(the_cib, (const char *) xpath->str, &xml_search,
                              cib_sync_call | cib_scope_local | cib_xpath);
    rc = pcmk_legacy2rc(rc);
    g_string_free(xpath, TRUE);

    if (rc != pcmk_rc_ok) {
        return rc;
    }

    crm_log_xml_debug(xml_search, "Match");
    if (xml_search->children != NULL) {
        if (ticket_id) {
            fprintf(stdout,
                    "Multiple " PCMK__XE_TICKET_STATE "s match ticket_id=%s\n",
                    ticket_id);
        }
        *ticket_state_xml = xml_search;
    } else {
        *ticket_state_xml = xml_search;
    }
    return rc;
}

static int
find_ticket_constraints(cib_t * the_cib, gchar *ticket_id, xmlNode ** ticket_cons_xml)
{
    int rc = pcmk_rc_ok;
    xmlNode *xml_search = NULL;

    GString *xpath = NULL;
    const char *xpath_base = NULL;

    CRM_ASSERT(ticket_cons_xml != NULL);
    *ticket_cons_xml = NULL;

    xpath_base = pcmk_cib_xpath_for(PCMK_XE_CONSTRAINTS);
    CRM_ASSERT(xpath_base != NULL);

    xpath = g_string_sized_new(1024);
    pcmk__g_strcat(xpath, xpath_base, "/" PCMK_XE_RSC_TICKET, NULL);

    if (ticket_id != NULL) {
        pcmk__g_strcat(xpath, "[@" PCMK_XA_TICKET "=\"", ticket_id, "\"]",
                       NULL);
    }

    rc = the_cib->cmds->query(the_cib, (const char *) xpath->str, &xml_search,
                              cib_sync_call | cib_scope_local | cib_xpath);
    rc = pcmk_legacy2rc(rc);
    g_string_free(xpath, TRUE);

    if (rc != pcmk_rc_ok) {
        return rc;
    }

    crm_log_xml_debug(xml_search, "Match");
    *ticket_cons_xml = xml_search;

    return rc;
}

PCMK__OUTPUT_ARGS("ticket-attribute", "gchar *", "const char *", "const char *")
static int
ticket_attribute_default(pcmk__output_t *out, va_list args)
{
    gchar *ticket_id G_GNUC_UNUSED = va_arg(args, gchar *);
    const char *name G_GNUC_UNUSED = va_arg(args, const char *);
    const char *value = va_arg(args, const char *);

    out->info(out, "%s", value);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ticket-attribute", "gchar *", "const char *", "const char *")
static int
ticket_attribute_xml(pcmk__output_t *out, va_list args)
{
    gchar *ticket_id = va_arg(args, gchar *);
    const char *name = va_arg(args, const char *);
    const char *value = va_arg(args, const char *);

    /* Create:
     * <tickets>
     *   <ticket id="">
     *     <attribute name="" value="" />
     *   </ticket>
     * </tickets>
     */
    pcmk__output_xml_create_parent(out, PCMK_XE_TICKETS, NULL);
    pcmk__output_xml_create_parent(out, PCMK_XE_TICKET,
                                   PCMK_XA_ID, ticket_id, NULL);
    pcmk__output_create_xml_node(out, PCMK_XA_ATTRIBUTE,
                                 PCMK_XA_NAME, name,
                                 PCMK_XA_VALUE, value,
                                 NULL);
    pcmk__output_xml_pop_parent(out);
    pcmk__output_xml_pop_parent(out);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ticket-constraints", "gchar *", "xmlNode *")
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
    pcmk__formatted_printf(out, "Constraints XML:\n\n");

    if (pcmk__xe_is(constraint_xml, PCMK__XE_XPATH_QUERY)) {
        xmlNode *child = pcmk__xe_first_child(constraint_xml);

        do {
            GString *buf = g_string_sized_new(1024);

            pcmk__xml_string(child, pcmk__xml_fmt_pretty, buf, 0);
            out->output_xml(out, PCMK_XE_CONSTRAINT, buf->str);
            g_string_free(buf, TRUE);

            child = pcmk__xe_next(child);
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
add_ticket_element(xmlNode *node, void *userdata)
{
    pcmk__output_t *out = (pcmk__output_t *) userdata;
    const char *ticket_id = crm_element_value(node, PCMK_XA_TICKET);

    pcmk__output_xml_create_parent(out, PCMK_XE_TICKET,
                                   PCMK_XA_ID, ticket_id, NULL);
    pcmk__output_xml_create_parent(out, PCMK_XE_CONSTRAINTS, NULL);
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
    const char *rsc = crm_element_value(node, PCMK_XA_RSC);

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
    pcmk__output_xml_create_parent(out, PCMK_XE_TICKETS, NULL);

    if (pcmk__xe_is(constraint_xml, PCMK__XE_XPATH_QUERY)) {
        /* Iterate through the list of children once to create all the
         * ticket/constraint elements.
         */
        pcmk__xe_foreach_child(constraint_xml, NULL, add_ticket_element, out);

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
        pcmk__output_xml_create_parent(out, PCMK_XE_RESOURCES, NULL);
        pcmk__xe_foreach_child(constraint_xml, NULL, add_resource_element, out);
        pcmk__output_xml_pop_parent(out);

    } else {
        /* Creating the output for a single constraint is much easier.  All the
         * comments in the above block apply here.
         */
        add_ticket_element(constraint_xml, out);
        pcmk__output_xml_pop_parent(out);

        pcmk__output_xml_create_parent(out, PCMK_XE_RESOURCES, NULL);
        add_resource_element(constraint_xml, out);
        pcmk__output_xml_pop_parent(out);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ticket-state", "gchar *", "xmlNode *")
static int
ticket_state_default(pcmk__output_t *out, va_list args)
{
    gchar *ticket_id G_GNUC_UNUSED = va_arg(args, gchar *);
    xmlNode *state_xml = va_arg(args, xmlNode *);

    GString *buf = g_string_sized_new(1024);

    pcmk__formatted_printf(out, "State XML:\n\n");
    pcmk__xml_string(state_xml, pcmk__xml_fmt_pretty, buf, 0);
    out->output_xml(out, PCMK__XE_TICKET_STATE, buf->str);

    g_string_free(buf, TRUE);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("ticket-state", "gchar *", "xmlNode *")
static int
ticket_state_xml(pcmk__output_t *out, va_list args)
{
    gchar *ticket_id = va_arg(args, gchar *);
    xmlNode *state_xml = va_arg(args, xmlNode *);

    xmlNode *ticket_node = NULL;

    /* Create:
     * <tickets>
     *   <ticket id="" ... />
     * </tickets>
     */
    pcmk__output_xml_create_parent(out, PCMK_XE_TICKETS, NULL);
    ticket_node = pcmk__output_create_xml_node(out, PCMK_XE_TICKET,
                                               PCMK_XA_ID, ticket_id,
                                               NULL);
    copy_in_properties(ticket_node, state_xml);
    pcmk__output_xml_pop_parent(out);

    return pcmk_rc_ok;
}

static int
get_ticket_state_attr(gchar *ticket_id, const char *attr_name, const char **attr_value,
                      pcmk_scheduler_t *scheduler)
{
    pcmk_ticket_t *ticket = NULL;

    CRM_ASSERT(attr_value != NULL);
    *attr_value = NULL;

    ticket = g_hash_table_lookup(scheduler->tickets, ticket_id);
    if (ticket == NULL) {
        return ENXIO;
    }

    *attr_value = g_hash_table_lookup(ticket->state, attr_name);
    if (*attr_value == NULL) {
        return ENXIO;
    }

    return pcmk_rc_ok;
}

static void
ticket_grant_warning(gchar *ticket_id)
{
    out->err(out, "This command cannot help you verify whether '%s' has "
                  "been already granted elsewhere.\n"
                  "If you really want to grant '%s' to this site now, and "
                  "you know what you are doing,\n"
                  "please specify --force.",
                  ticket_id, ticket_id);
}

static void
ticket_revoke_warning(gchar *ticket_id)
{
    out->err(out, "Revoking '%s' can trigger the specified '" PCMK_XA_LOSS_POLICY
              "'(s) relating to '%s'.\n\n"
              "You can check that with:\n"
              "crm_ticket --ticket %s --constraints\n\n"
              "Otherwise before revoking '%s', you may want to make '%s'"
              "standby with:\n"
              "crm_ticket --ticket %s --standby\n\n"
              "If you really want to revoke '%s' from this site now, and "
              "you know what you are doing,\n"
              "please specify --force.",
              ticket_id, ticket_id, ticket_id, ticket_id, ticket_id,
              ticket_id, ticket_id);
}

static bool
allow_modification(gchar *ticket_id)
{
    const char *value = NULL;
    GList *list_iter = NULL;

    if (options.force) {
        return true;
    }

    if (g_hash_table_lookup_extended(attr_set, PCMK__XA_GRANTED, NULL,
                                     (gpointer *) &value)) {
        if (crm_is_true(value)) {
            ticket_grant_warning(ticket_id);
            return false;

        } else {
            ticket_revoke_warning(ticket_id);
            return false;
        }
    }

    for(list_iter = attr_delete; list_iter; list_iter = list_iter->next) {
        const char *key = (const char *)list_iter->data;

        if (pcmk__str_eq(key, PCMK__XA_GRANTED, pcmk__str_none)) {
            ticket_revoke_warning(ticket_id);
            return false;
        }
    }

    return true;
}

static int
modify_ticket_state(gchar *ticket_id, cib_t *cib, pcmk_scheduler_t *scheduler)
{
    int rc = pcmk_rc_ok;
    xmlNode *xml_top = NULL;
    xmlNode *ticket_state_xml = NULL;
    bool found = false;

    GList *list_iter = NULL;
    GHashTableIter hash_iter;

    char *key = NULL;
    char *value = NULL;

    pcmk_ticket_t *ticket = NULL;

    rc = find_ticket_state(cib, ticket_id, &ticket_state_xml);
    if (rc == pcmk_rc_ok) {
        crm_debug("Found a match state for ticket: id=%s", ticket_id);
        xml_top = ticket_state_xml;
        found = true;

    } else if (rc != ENXIO) {
        return rc;

    } else if (g_hash_table_size(attr_set) == 0){
        return pcmk_rc_ok;

    } else {
        xmlNode *xml_obj = NULL;

        xml_top = create_xml_node(NULL, PCMK_XE_STATUS);
        xml_obj = create_xml_node(xml_top, PCMK_XE_TICKETS);
        ticket_state_xml = create_xml_node(xml_obj, PCMK__XE_TICKET_STATE);
        crm_xml_add(ticket_state_xml, PCMK_XA_ID, ticket_id);
    }

    for(list_iter = attr_delete; list_iter; list_iter = list_iter->next) {
        const char *key = (const char *)list_iter->data;
        xml_remove_prop(ticket_state_xml, key);
    }

    ticket = find_ticket(ticket_id, scheduler);

    g_hash_table_iter_init(&hash_iter, attr_set);
    while (g_hash_table_iter_next(&hash_iter, (gpointer *) & key, (gpointer *) & value)) {
        crm_xml_add(ticket_state_xml, key, value);

        if (pcmk__str_eq(key, PCMK__XA_GRANTED, pcmk__str_none)
            && (ticket == NULL || ticket->granted == FALSE)
            && crm_is_true(value)) {

            char *now = pcmk__ttoa(time(NULL));

            crm_xml_add(ticket_state_xml, PCMK_XA_LAST_GRANTED, now);
            free(now);
        }
    }

    if (found && (attr_delete != NULL)) {
        crm_log_xml_debug(xml_top, "Replace");
        rc = cib->cmds->replace(cib, PCMK_XE_STATUS, ticket_state_xml,
                                cib_options);
        rc = pcmk_legacy2rc(rc);

    } else {
        crm_log_xml_debug(xml_top, "Update");
        rc = cib->cmds->modify(cib, PCMK_XE_STATUS, xml_top, cib_options);
        rc = pcmk_legacy2rc(rc);
    }

    free_xml(xml_top);
    return rc;
}

static int
delete_ticket_state(gchar *ticket_id, cib_t * cib)
{
    xmlNode *ticket_state_xml = NULL;

    int rc = pcmk_rc_ok;

    rc = find_ticket_state(cib, ticket_id, &ticket_state_xml);

    if (rc == ENXIO) {
        return pcmk_rc_ok;

    } else if (rc != pcmk_rc_ok) {
        return rc;
    }

    crm_log_xml_debug(ticket_state_xml, "Delete");

    rc = cib->cmds->remove(cib, PCMK_XE_STATUS, ticket_state_xml, cib_options);
    rc = pcmk_legacy2rc(rc);

    if (rc == pcmk_rc_ok) {
        fprintf(stdout, "Cleaned up %s\n", ticket_id);
    }

    free_xml(ticket_state_xml);
    return rc;
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group)
{
    GOptionContext *context = NULL;

    const char *description = "Examples:\n\n"
                              "Display the info of tickets:\n\n"
                              "\tcrm_ticket --info\n\n"
                              "Display the detailed info of tickets:\n\n"
                              "\tcrm_ticket --details\n\n"
                              "Display the XML of 'ticketA':\n\n"
                              "\tcrm_ticket --ticket ticketA --query-xml\n\n"
                              "Display the " PCMK_XE_RSC_TICKET " constraints that apply to 'ticketA':\n\n"
                              "\tcrm_ticket --ticket ticketA --constraints\n\n"
                              "Grant 'ticketA' to this cluster site:\n\n"
                              "\tcrm_ticket --ticket ticketA --grant\n\n"
                              "Revoke 'ticketA' from this cluster site:\n\n"
                              "\tcrm_ticket --ticket ticketA --revoke\n\n"
                              "Make 'ticketA' standby (the cluster site will treat a granted\n"
                              "'ticketA' as 'standby', and the dependent resources will be\n"
                              "stopped or demoted gracefully without triggering loss-policies):\n\n"
                              "\tcrm_ticket --ticket ticketA --standby\n\n"
                              "Activate 'ticketA' from being standby:\n\n"
                              "\tcrm_ticket --ticket ticketA --activate\n\n"
                              "Get the value of the 'granted' attribute for 'ticketA':\n\n"
                              "\tcrm_ticket --ticket ticketA --get-attr granted\n\n"
                              "Set the value of the 'standby' attribute for 'ticketA':\n\n"
                              "\tcrm_ticket --ticket ticketA --set-attr standby --attr-value true\n\n"
                              "Delete the 'granted' attribute for 'ticketA':\n\n"
                              "\tcrm_ticket --ticket ticketA --delete-attr granted\n\n"
                              "Erase the operation history of 'ticketA' at this cluster site,\n"
                              "causing the cluster site to 'forget' the existing ticket state:\n\n"
                              "\tcrm_ticket --ticket ticketA --cleanup\n\n";

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);
    g_option_context_set_description(context, description);

    pcmk__add_arg_group(context, "queries", "Queries:",
                        "Show queries", query_entries);
    pcmk__add_arg_group(context, "commands", "Commands:",
                        "Show command options", command_entries);
    pcmk__add_arg_group(context, "advanced", "Advanced Options:",
                        "Show advanced options", advanced_entries);
    pcmk__add_arg_group(context, "additional", "Additional Options:",
                        "Show additional options", addl_entries);
    pcmk__add_arg_group(context, "deprecated", "Deprecated Options:",
                        "Show deprecated options", deprecated_entries);

    return context;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "ticket-attribute", "default", ticket_attribute_default },
    { "ticket-attribute", "xml", ticket_attribute_xml },
    { "ticket-constraints", "default", ticket_constraints_default },
    { "ticket-constraints", "xml", ticket_constraints_xml },
    { "ticket-state", "default", ticket_state_default },
    { "ticket-state", "xml", ticket_state_xml },

    { NULL, NULL, NULL }
};

int
main(int argc, char **argv)
{
    pcmk_scheduler_t *scheduler = NULL;
    xmlNode *cib_xml_copy = NULL;

    cib_t *cib_conn = NULL;
    crm_exit_t exit_code = CRM_EX_OK;
    int rc = pcmk_rc_ok;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = NULL;
    GOptionContext *context = NULL;
    gchar **processed_args = NULL;

    attr_set = pcmk__strkey_table(free, free);
    attr_delete = NULL;

    args = pcmk__new_common_args(SUMMARY);
    context = build_arg_context(args, &output_group);
    processed_args = pcmk__cmdline_preproc(argv, "dintvxCDGS");

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("crm_ticket", args->verbosity);

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error creating output format %s: %s", args->output_ty,
                    pcmk_rc_str(rc));
        goto done;
    }

    pe__register_messages(out);
    pcmk__register_messages(out, fmt_functions);

    if (args->version) {
        out->version(out, false);
        goto done;
    }

    scheduler = pe_new_working_set();
    if (scheduler == NULL) {
        rc = errno;
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Could not allocate scheduler data: %s", pcmk_rc_str(rc));
        goto done;
    }
    pcmk__set_scheduler_flags(scheduler,
                              pcmk_sched_no_counts|pcmk_sched_no_compat);

    cib_conn = cib_new();
    if (cib_conn == NULL) {
        exit_code = CRM_EX_DISCONNECT;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Could not connect to the CIB manager");
        goto done;
    }

    rc = cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);
    rc = pcmk_legacy2rc(rc);

    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Could not connect to the CIB: %s",
                    pcmk_rc_str(rc));
        goto done;
    }

    if (options.xml_file != NULL) {
        cib_xml_copy = pcmk__xml_read(options.xml_file);

    } else {
        rc = cib_conn->cmds->query(cib_conn, NULL, &cib_xml_copy, cib_scope_local | cib_sync_call);
        rc = pcmk_legacy2rc(rc);

        if (rc != pcmk_rc_ok) {
            exit_code = pcmk_rc2exitc(rc);
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Could not get local CIB: %s",
                        pcmk_rc_str(rc));
            goto done;
        }
    }

    if (!cli_config_update(&cib_xml_copy, NULL, FALSE)) {
        exit_code = CRM_EX_CONFIG;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Could not update local CIB to latest schema version");
        goto done;
    }

    scheduler->input = cib_xml_copy;
    scheduler->now = crm_time_new(NULL);

    cluster_status(scheduler);

    /* For recording the tickets that are referenced in PCMK_XE_RSC_TICKET
     * constraints but have never been granted yet.
     */
    pcmk__unpack_constraints(scheduler);

    if (options.ticket_cmd == 'l' || options.ticket_cmd == 'L' || options.ticket_cmd == 'w') {
        bool raw = false;
        bool details = false;

        if (options.ticket_cmd == 'L') {
            details = true;
        } else if (options.ticket_cmd == 'w') {
            raw = true;
        }

        if (options.ticket_id) {
            GHashTable *tickets = NULL;
            pcmk_ticket_t *ticket = find_ticket(options.ticket_id, scheduler);

            if (ticket == NULL) {
                exit_code = CRM_EX_NOSUCH;
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                            "No such ticket '%s'", options.ticket_id);
                goto done;
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

    } else if (options.ticket_cmd == 'q') {
        xmlNode *state_xml = NULL;
        rc = find_ticket_state(cib_conn, options.ticket_id, &state_xml);

        if (state_xml != NULL) {
            out->message(out, "ticket-state", options.ticket_id, state_xml);
            free_xml(state_xml);
        }

        exit_code = pcmk_rc2exitc(rc);

        if (rc != pcmk_rc_ok) {
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Could not query ticket XML: %s", pcmk_rc_str(rc));
        }

    } else if (options.ticket_cmd == 'c') {
        xmlNode *cons_xml = NULL;
        rc = find_ticket_constraints(cib_conn, options.ticket_id, &cons_xml);

        if (cons_xml != NULL) {
            out->message(out, "ticket-constraints", cons_xml);
            free_xml(cons_xml);
        }

        exit_code = pcmk_rc2exitc(rc);

        if (rc != pcmk_rc_ok) {
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Could not show ticket constraints: %s", pcmk_rc_str(rc));
        }

    } else if (options.ticket_cmd == 'G') {
        const char *value = NULL;

        if (options.ticket_id == NULL) {
            exit_code = CRM_EX_NOSUCH;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Must supply ticket ID with -t");
            goto done;
        }

        rc = get_ticket_state_attr(options.ticket_id, options.get_attr_name,
                                   &value, scheduler);
        if (rc == pcmk_rc_ok) {
            out->message(out, "ticket-attribute", options.ticket_id,
                         options.get_attr_name, value);
        } else if (rc == ENXIO && options.attr_default) {
            const char *def = options.attr_default;

            out->message(out, "ticket-attribute", options.ticket_id,
                         options.get_attr_name, def);
            rc = pcmk_rc_ok;
        }
        exit_code = pcmk_rc2exitc(rc);

    } else if (options.ticket_cmd == 'C') {
        if (options.ticket_id == NULL) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Must supply ticket ID with -t");
            goto done;
        }

        if (options.force == FALSE) {
            pcmk_ticket_t *ticket = NULL;

            ticket = find_ticket(options.ticket_id, scheduler);
            if (ticket == NULL) {
                exit_code = CRM_EX_NOSUCH;
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                            "No such ticket '%s'", options.ticket_id);
                goto done;
            }

            if (ticket->granted) {
                ticket_revoke_warning(options.ticket_id);
                exit_code = CRM_EX_INSUFFICIENT_PRIV;
                goto done;
            }
        }

        rc = delete_ticket_state(options.ticket_id, cib_conn);
        exit_code = pcmk_rc2exitc(rc);

        if (rc != pcmk_rc_ok) {
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Could not clean up ticket: %s", pcmk_rc_str(rc));
        }

    } else if (modified) {
        if (options.ticket_id == NULL) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Must supply ticket ID with -t");
            goto done;
        }

        if (options.attr_value
            && (pcmk__str_empty(options.attr_name))) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Must supply attribute name with -S for -v %s", options.attr_value);
            goto done;
        }

        if (options.attr_name
            && (pcmk__str_empty(options.attr_value))) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Must supply attribute value with -v for -S %s", options.attr_value);
            goto done;
        }

        if (!allow_modification(options.ticket_id)) {
            exit_code = CRM_EX_INSUFFICIENT_PRIV;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Ticket modification not allowed");
            goto done;
        }

        rc = modify_ticket_state(options.ticket_id, cib_conn, scheduler);
        exit_code = pcmk_rc2exitc(rc);

        if (rc != pcmk_rc_ok) {
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Could not modify ticket: %s", pcmk_rc_str(rc));
        }

    } else if (options.ticket_cmd == 'S') {
        /* Correct usage was handled in the "if (modified)" block above, so
         * this is just for reporting usage errors
         */

        if (pcmk__str_empty(options.attr_name)) {
            // We only get here if ticket_cmd was left as default
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Must supply a command");
            goto done;
        }

        if (options.ticket_id == NULL) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Must supply ticket ID with -t");
            goto done;
        }

        if (pcmk__str_empty(options.attr_value)) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Must supply value with -v for -S %s", options.attr_name);
            goto done;
        }

    } else {
        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Unknown command: %c", options.ticket_cmd);
    }

 done:
    if (attr_set) {
        g_hash_table_destroy(attr_set);
    }
    attr_set = NULL;

    if (attr_delete) {
        g_list_free_full(attr_delete, free);
    }
    attr_delete = NULL;

    pe_free_working_set(scheduler);
    scheduler = NULL;

    cib__clean_up_connection(&cib_conn);

    g_strfreev(processed_args);
    pcmk__free_arg_context(context);
    g_free(options.attr_default);
    g_free(options.attr_id);
    free(options.attr_name);
    free(options.attr_value);
    free(options.get_attr_name);
    g_free(options.set_name);
    g_free(options.ticket_id);
    g_free(options.xml_file);

    pcmk__output_and_clear_error(&error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }

    pcmk__unregister_formats();
    crm_exit(exit_code);
}
