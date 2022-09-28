/*
 * Copyright 2012-2022 the Pacemaker project contributors
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

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ipc.h>
#include <crm/common/cmdline_internal.h>

#include <crm/cib.h>
#include <crm/cib/internal.h>
#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>

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

#define INDENT "                               "

static gboolean
attr_value_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    pcmk__str_update(&options.attr_value, optarg);

    if (!options.attr_name || !options.attr_value) {
        return TRUE;
    }

    g_hash_table_insert(attr_set, strdup(options.attr_name), strdup(options.attr_value));
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
        g_hash_table_insert(attr_set, strdup("granted"), strdup("true"));
        modified = true;
    } else if (pcmk__str_any_of(option_name, "--revoke", "-r", NULL)) {
        g_hash_table_insert(attr_set, strdup("granted"), strdup("false"));
        modified = true;
    } else if (pcmk__str_any_of(option_name, "--standby", "-s", NULL)) {
        g_hash_table_insert(attr_set, strdup("standby"), strdup("true"));
        modified = true;
    } else if (pcmk__str_any_of(option_name, "--activate", "-a", NULL)) {
        g_hash_table_insert(attr_set, strdup("standby"), strdup("false"));
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

    g_hash_table_insert(attr_set, strdup(options.attr_name), strdup(options.attr_value));
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
      "Display the rsc_ticket constraints that apply to ticket(s)",
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
      "(Advanced) ID of the instance_attributes object to change",
      "ID" },

    { "nvpair", 'i', 0, G_OPTION_ARG_STRING, &options.attr_id,
      "(Advanced) ID of the nvpair object to change/delete",
      "ID" },

    { "quiet", 'Q', 0, G_OPTION_ARG_NONE, &options.quiet,
      "Print only the value on stdout",
      NULL },

    { NULL }
};

static pe_ticket_t *
find_ticket(gchar *ticket_id, pe_working_set_t * data_set)
{
    return g_hash_table_lookup(data_set->tickets, ticket_id);
}

static void
print_date(time_t time)
{
    int lpc = 0;
    char date_str[26];

    asctime_r(localtime(&time), date_str);
    for (; lpc < 26; lpc++) {
        if (date_str[lpc] == '\n') {
            date_str[lpc] = 0;
        }
    }
    fprintf(stdout, "'%s'", date_str);
}

static void
print_ticket(pe_ticket_t * ticket, bool raw, bool details)
{
    if (raw) {
        fprintf(stdout, "%s\n", ticket->id);
        return;
    }

    fprintf(stdout, "%s\t%s %s",
            ticket->id, ticket->granted ? "granted" : "revoked",
            ticket->standby ? "[standby]" : "         ");

    if (details && g_hash_table_size(ticket->state) > 0) {
        GHashTableIter iter;
        const char *name = NULL;
        const char *value = NULL;
        int lpc = 0;

        fprintf(stdout, " (");

        g_hash_table_iter_init(&iter, ticket->state);
        while (g_hash_table_iter_next(&iter, (void **)&name, (void **)&value)) {
            if (lpc > 0) {
                fprintf(stdout, ", ");
            }
            fprintf(stdout, "%s=", name);
            if (pcmk__str_any_of(name, "last-granted", "expires", NULL)) {
                long long time_ll;

                pcmk__scan_ll(value, &time_ll, 0);
                print_date((time_t) time_ll);
            } else {
                fprintf(stdout, "%s", value);
            }
            lpc++;
        }

        fprintf(stdout, ")\n");

    } else {
        if (ticket->last_granted > -1) {
            fprintf(stdout, " last-granted=");
            print_date(ticket->last_granted);
        }
        fprintf(stdout, "\n");
    }

    return;
}

static void
print_ticket_list(pe_working_set_t * data_set, bool raw, bool details)
{
    GHashTableIter iter;
    pe_ticket_t *ticket = NULL;

    g_hash_table_iter_init(&iter, data_set->tickets);

    while (g_hash_table_iter_next(&iter, NULL, (void **)&ticket)) {
        print_ticket(ticket, raw, details);
    }
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
                    "/" XML_TAG_CIB "/" XML_CIB_TAG_STATUS
                    "/" XML_CIB_TAG_TICKETS);

    if (ticket_id != NULL) {
        pcmk__g_strcat(xpath,
                       "/" XML_CIB_TAG_TICKET_STATE
                       "[@" XML_ATTR_ID "=\"", ticket_id, "\"]", NULL);
    }

    rc = the_cib->cmds->query(the_cib, (const char *) xpath->str, &xml_search,
                              cib_sync_call | cib_scope_local | cib_xpath);
    rc = pcmk_legacy2rc(rc);
    g_string_free(xpath, TRUE);

    if (rc != pcmk_rc_ok) {
        return rc;
    }

    crm_log_xml_debug(xml_search, "Match");
    if (xml_has_children(xml_search)) {
        if (ticket_id) {
            fprintf(stdout, "Multiple ticket_states match ticket_id=%s\n", ticket_id);
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

    xpath_base = pcmk_cib_xpath_for(XML_CIB_TAG_CONSTRAINTS);
    if (xpath_base == NULL) {
        crm_err(XML_CIB_TAG_CONSTRAINTS " CIB element not known (bug?)");
        return -ENOMSG;
    }

    xpath = g_string_sized_new(1024);
    pcmk__g_strcat(xpath, xpath_base, "/" XML_CONS_TAG_RSC_TICKET, NULL);

    if (ticket_id != NULL) {
        pcmk__g_strcat(xpath,
                       "[@" XML_TICKET_ATTR_TICKET "=\"", ticket_id, "\"]",
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

static int
dump_ticket_xml(cib_t * the_cib, gchar *ticket_id)
{
    int rc = pcmk_rc_ok;
    xmlNode *state_xml = NULL;

    rc = find_ticket_state(the_cib, ticket_id, &state_xml);

    if (state_xml == NULL) {
        return rc;
    }

    fprintf(stdout, "State XML:\n");
    if (state_xml) {
        char *state_xml_str = NULL;

        state_xml_str = dump_xml_formatted(state_xml);
        fprintf(stdout, "\n%s", pcmk__s(state_xml_str, "<null>\n"));
        free_xml(state_xml);
        free(state_xml_str);
    }

    return rc;
}

static int
dump_constraints(cib_t * the_cib, gchar *ticket_id)
{
    int rc = pcmk_rc_ok;
    xmlNode *cons_xml = NULL;
    char *cons_xml_str = NULL;

    rc = find_ticket_constraints(the_cib, ticket_id, &cons_xml);

    if (cons_xml == NULL) {
        return rc;
    }

    cons_xml_str = dump_xml_formatted(cons_xml);
    fprintf(stdout, "Constraints XML:\n\n%s",
            pcmk__s(cons_xml_str, "<null>\n"));
    free_xml(cons_xml);
    free(cons_xml_str);

    return rc;
}

static int
get_ticket_state_attr(gchar *ticket_id, const char *attr_name, const char **attr_value,
                      pe_working_set_t * data_set)
{
    pe_ticket_t *ticket = NULL;

    CRM_ASSERT(attr_value != NULL);
    *attr_value = NULL;

    ticket = g_hash_table_lookup(data_set->tickets, ticket_id);
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
ticket_warning(gchar *ticket_id, const char *action)
{
    GString *warning = g_string_sized_new(1024);
    const char *word = NULL;

    CRM_ASSERT(action != NULL);

    if (strcmp(action, "grant") == 0) {
        pcmk__g_strcat(warning,
                       "This command cannot help you verify whether '",
                       ticket_id,
                       "' has been already granted elsewhere.\n", NULL);
        word = "to";

    } else {
        pcmk__g_strcat(warning,
                       "Revoking '", ticket_id, "' can trigger the specified "
                       "'loss-policy'(s) relating to '", ticket_id, "'.\n\n"
                       "You can check that with:\n"
                       "crm_ticket --ticket ", ticket_id, " --constraints\n\n"
                       "Otherwise before revoking '", ticket_id, "', "
                       "you may want to make '", ticket_id, "' "
                       "standby with:\n"
                       "crm_ticket --ticket ", ticket_id, " --standby\n\n",
                       NULL);
        word = "from";
    }

    pcmk__g_strcat(warning,
                   "If you really want to ", action, " '", ticket_id, "' ",
                   word, " this site now, and you know what you are doing,\n"
                   "please specify --force.", NULL);

    fprintf(stdout, "%s\n", (const char *) warning->str);

    g_string_free(warning, TRUE);
}

static bool
allow_modification(gchar *ticket_id)
{
    const char *value = NULL;
    GList *list_iter = NULL;

    if (options.force) {
        return true;
    }

    if (g_hash_table_lookup_extended(attr_set, "granted", NULL, (gpointer *) & value)) {
        if (crm_is_true(value)) {
            ticket_warning(ticket_id, "grant");
            return false;

        } else {
            ticket_warning(ticket_id, "revoke");
            return false;
        }
    }

    for(list_iter = attr_delete; list_iter; list_iter = list_iter->next) {
        const char *key = (const char *)list_iter->data;

        if (pcmk__str_eq(key, "granted", pcmk__str_casei)) {
            ticket_warning(ticket_id, "revoke");
            return false;
        }
    }

    return true;
}

static int
modify_ticket_state(gchar * ticket_id, cib_t * cib, pe_working_set_t * data_set)
{
    int rc = pcmk_rc_ok;
    xmlNode *xml_top = NULL;
    xmlNode *ticket_state_xml = NULL;
    bool found = false;

    GList *list_iter = NULL;
    GHashTableIter hash_iter;

    char *key = NULL;
    char *value = NULL;

    pe_ticket_t *ticket = NULL;

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

        xml_top = create_xml_node(NULL, XML_CIB_TAG_STATUS);
        xml_obj = create_xml_node(xml_top, XML_CIB_TAG_TICKETS);
        ticket_state_xml = create_xml_node(xml_obj, XML_CIB_TAG_TICKET_STATE);
        crm_xml_add(ticket_state_xml, XML_ATTR_ID, ticket_id);
    }

    for(list_iter = attr_delete; list_iter; list_iter = list_iter->next) {
        const char *key = (const char *)list_iter->data;
        xml_remove_prop(ticket_state_xml, key);
    }

    ticket = find_ticket(ticket_id, data_set);

    g_hash_table_iter_init(&hash_iter, attr_set);
    while (g_hash_table_iter_next(&hash_iter, (gpointer *) & key, (gpointer *) & value)) {
        crm_xml_add(ticket_state_xml, key, value);

        if (pcmk__str_eq(key, "granted", pcmk__str_casei)
            && (ticket == NULL || ticket->granted == FALSE)
            && crm_is_true(value)) {

            char *now = pcmk__ttoa(time(NULL));

            crm_xml_add(ticket_state_xml, "last-granted", now);
            free(now);
        }
    }

    if (found && (attr_delete != NULL)) {
        crm_log_xml_debug(xml_top, "Replace");
        rc = cib->cmds->replace(cib, XML_CIB_TAG_STATUS, ticket_state_xml, cib_options);
        rc = pcmk_legacy2rc(rc);

    } else {
        crm_log_xml_debug(xml_top, "Update");
        rc = cib->cmds->modify(cib, XML_CIB_TAG_STATUS, xml_top, cib_options);
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

    rc = cib->cmds->remove(cib, XML_CIB_TAG_STATUS, ticket_state_xml, cib_options);
    rc = pcmk_legacy2rc(rc);

    if (rc == pcmk_rc_ok) {
        fprintf(stdout, "Cleaned up %s\n", ticket_id);
    }

    free_xml(ticket_state_xml);
    return rc;
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args) {
    GOptionContext *context = NULL;

    const char *description = "Examples:\n\n"
                              "Display the info of tickets:\n\n"
                              "\tcrm_ticket --info\n\n"
                              "Display the detailed info of tickets:\n\n"
                              "\tcrm_ticket --details\n\n"
                              "Display the XML of 'ticketA':\n\n"
                              "\tcrm_ticket --ticket ticketA --query-xml\n\n"
                              "Display the rsc_ticket constraints that apply to 'ticketA':\n\n"
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

    context = pcmk__build_arg_context(args, NULL, NULL, NULL);
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

int
main(int argc, char **argv)
{
    pe_working_set_t *data_set = NULL;
    xmlNode *cib_xml_copy = NULL;

    cib_t *cib_conn = NULL;
    crm_exit_t exit_code = CRM_EX_OK;
    int rc = pcmk_rc_ok;

    pcmk__common_args_t *args = NULL;
    GOptionContext *context = NULL;
    gchar **processed_args = NULL;

    attr_set = pcmk__strkey_table(free, free);
    attr_delete = NULL;

    args = pcmk__new_common_args(SUMMARY);
    context = build_arg_context(args);
    processed_args = pcmk__cmdline_preproc(argv, "dintvxCDGS");

    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("crm_ticket", args->verbosity);

    if (args->version) {
        g_strfreev(processed_args);
        pcmk__free_arg_context(context);
        /* FIXME:  When crm_ticket is converted to use formatted output, this can go. */
        pcmk__cli_help('v', CRM_EX_OK);
    }

    data_set = pe_new_working_set();
    if (data_set == NULL) {
        crm_perror(LOG_CRIT, "Could not allocate working set");
        exit_code = CRM_EX_OSERR;
        goto done;
    }
    pe__set_working_set_flags(data_set, pe_flag_no_counts|pe_flag_no_compat);

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
        cib_xml_copy = filename2xml(options.xml_file);

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

    data_set->input = cib_xml_copy;
    data_set->now = crm_time_new(NULL);

    cluster_status(data_set);

    /* For recording the tickets that are referenced in rsc_ticket constraints
     * but have never been granted yet. */
    pcmk__unpack_constraints(data_set);

    if (options.ticket_cmd == 'l' || options.ticket_cmd == 'L' || options.ticket_cmd == 'w') {
        bool raw = false;
        bool details = false;

        if (options.ticket_cmd == 'L') {
            details = true;
        } else if (options.ticket_cmd == 'w') {
            raw = true;
        }

        if (options.ticket_id) {
            pe_ticket_t *ticket = find_ticket(options.ticket_id, data_set);

            if (ticket == NULL) {
                exit_code = CRM_EX_NOSUCH;
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                            "No such ticket '%s'", options.ticket_id);
                goto done;
            }
            print_ticket(ticket, raw, details);

        } else {
            print_ticket_list(data_set, raw, details);
        }

    } else if (options.ticket_cmd == 'q') {
        rc = dump_ticket_xml(cib_conn, options.ticket_id);
        exit_code = pcmk_rc2exitc(rc);

        if (rc != pcmk_rc_ok) {
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Could not query ticket XML: %s", pcmk_rc_str(rc));
        }

    } else if (options.ticket_cmd == 'c') {
        rc = dump_constraints(cib_conn, options.ticket_id);
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

        rc = get_ticket_state_attr(options.ticket_id, options.get_attr_name, &value, data_set);
        if (rc == pcmk_rc_ok) {
            fprintf(stdout, "%s\n", value);
        } else if (rc == ENXIO && options.attr_default) {
            fprintf(stdout, "%s\n", options.attr_default);
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
            pe_ticket_t *ticket = NULL;

            ticket = find_ticket(options.ticket_id, data_set);
            if (ticket == NULL) {
                exit_code = CRM_EX_NOSUCH;
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                            "No such ticket '%s'", options.ticket_id);
                goto done;
            }

            if (ticket->granted) {
                ticket_warning(options.ticket_id, "revoke");
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

        rc = modify_ticket_state(options.ticket_id, cib_conn, data_set);
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

    pe_free_working_set(data_set);
    data_set = NULL;

    cib__clean_up_connection(&cib_conn);

    if (rc == pcmk_rc_no_quorum) {
        g_set_error(&error, PCMK__RC_ERROR, rc, "Use --force to ignore quorum");
    }

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

    pcmk__output_and_clear_error(error, NULL);

    crm_exit(exit_code);
}
