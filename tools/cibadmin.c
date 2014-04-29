
/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
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

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ipc.h>
#include <crm/cib/internal.h>

int exit_code = pcmk_ok;
int message_timer_id = -1;
int message_timeout_ms = 30;

GMainLoop *mainloop = NULL;

const char *host = NULL;
void usage(const char *cmd, int exit_status);
int do_init(void);
int do_work(xmlNode * input, int command_options, xmlNode ** output);

gboolean admin_message_timeout(gpointer data);
void cib_connection_destroy(gpointer user_data);
void cibadmin_op_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data);

int command_options = 0;
const char *cib_user = NULL;
const char *cib_action = NULL;

typedef struct str_list_s {
    int num_items;
    char *value;
    struct str_list_s *next;
} str_list_t;

char *obj_type = NULL;
char *status = NULL;
char *migrate_from = NULL;
char *migrate_res = NULL;
char *subtype = NULL;
char *reset = NULL;

int request_id = 0;
int operation_status = 0;
cib_t *the_cib = NULL;
gboolean force_flag = FALSE;
gboolean quiet = FALSE;
int bump_log_num = 0;

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    {"help",    0, 0, '?', "\tThis text"},
    {"version", 0, 0, '$', "\tVersion information"  },
    {"verbose", 0, 0, 'V', "\tIncrease debug output\n"},

    {"-spacer-",    0, 0, '-', "Commands:"},
    {"upgrade",     0, 0, 'u', "\tUpgrade the configuration to the latest syntax"},
    {"query",       0, 0, 'Q', "\tQuery the contents of the CIB"},
    {"erase",       0, 0, 'E', "\tErase the contents of the whole CIB"},
    {"bump",        0, 0, 'B', "\tIncrease the CIB's epoch value by 1"},
    {"create",      0, 0, 'C', "\tCreate an object in the CIB.  Will fail if the object already exists."},
    {"modify",      0, 0, 'M', "\tFind the object somewhere in the CIB's XML tree and update it.  Fails if the object does not exist unless -c is specified"},
    {"patch",	    0, 0, 'P', "\tSupply an update in the form of an xml diff (See also: crm_diff)"},
    {"replace",     0, 0, 'R', "\tRecursivly replace an object in the CIB"},
    {"delete",      0, 0, 'D', "\tDelete the first object matching the supplied criteria, Eg. <op id=\"rsc1_op1\" name=\"monitor\"/>"},
    {"-spacer-",    0, 0, '-', "\n\tThe tagname and all attributes must match in order for the element to be deleted\n"},
    {"delete-all",  0, 0, 'd', "When used with --xpath, remove all matching objects in the configuration instead of just the first one"},
    {"empty",       0, 0, 'a', "\tOutput an empty CIB"},
    {"md5-sum",	    0, 0, '5', "\tCalculate the on-disk CIB digest"},
    {"md5-sum-versioned",  0, 0, '6', "Calculate an on-the-wire versioned CIB digest"},
    {"blank",       0, 0, '-', NULL, 1},

    {"-spacer-",1, 0, '-', "\nAdditional options:"},
    {"force",	    0, 0, 'f'},
    {"timeout",	    1, 0, 't', "Time (in seconds) to wait before declaring the operation failed"},
    {"user",	    1, 0, 'U', "Run the command with permissions of the named user (valid only for the root and "CRM_DAEMON_USER" accounts)"},
    {"sync-call",   0, 0, 's', "Wait for call to complete before returning"},
    {"local",	    0, 0, 'l', "\tCommand takes effect locally.  Should only be used for queries"},
    {"allow-create",0, 0, 'c', "(Advanced) Allow the target of a --modify,-M operation to be created if they do not exist"},
    {"no-children", 0, 0, 'n', "(Advanced) When querying an object, do not return include its children in the result\n"},
    {"no-bcast",    0, 0, 'b', NULL, 1},

    {"-spacer-",    0, 0, '-', "Data:"},
    {"xml-text",    1, 0, 'X', "Retrieve XML from the supplied string"},
    {"xml-file",    1, 0, 'x', "Retrieve XML from the named file"},
    {"xml-pipe",    0, 0, 'p', "Retrieve XML from stdin\n"},

    {"scope",       1, 0, 'o', "Limit the scope of the operation to a specific section of the CIB."},
    {"-spacer-",    0, 0, '-', "\tValid values are: nodes, resources, constraints, crm_config, rsc_defaults, op_defaults, status"},

    {"xpath",       1, 0, 'A', "A valid XPath to use instead of --scope,-o"},
    {"node-path",   0, 0, 'e',  "When performing XPath queries, return the address of any matches found."},
    {"-spacer-",    0, 0, '-', " Eg: /cib/configuration/resources/master[@id='ms_RH1_SCS']/primitive[@id='prm_RH1_SCS']", pcmk_option_paragraph},
    {"node",	    1, 0, 'N', "(Advanced) Send command to the specified host\n"},
    {"-space-",	    0, 0, '!', NULL, 1},

    {"-spacer-",    0, 0, '-', "\nExamples:\n"},
    {"-spacer-",    0, 0, '-', "Query the configuration from the local node:", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --query --local", pcmk_option_example},

    {"-spacer-",    0, 0, '-', "Query the just the cluster options configuration:", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --query --scope crm_config", pcmk_option_example},

    {"-spacer-",    0, 0, '-', "Query all 'target-role' settings:", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --query --xpath \"//nvpair[@name='target-role']\"", pcmk_option_example},

    {"-spacer-",    0, 0, '-', "Remove all 'is-managed' settings:", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --delete-all --xpath \"//nvpair[@name='is-managed']\"", pcmk_option_example},

    {"-spacer-",    0, 0, '-', "Remove the resource named 'old':", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --delete --xml-text '<primitive id=\"old\"/>'", pcmk_option_example},

    {"-spacer-",    0, 0, '-', "Remove all resources from the configuration:", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --replace --scope resources --xml-text '<resources/>'", pcmk_option_example},

    {"-spacer-",    0, 0, '-', "Replace the complete configuration with the contents of $HOME/pacemaker.xml:", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --replace --xml-file $HOME/pacemaker.xml", pcmk_option_example},

    {"-spacer-",    0, 0, '-', "Replace the constraints section of the configuration with the contents of $HOME/constraints.xml:", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --replace --scope constraints --xml-file $HOME/constraints.xml", pcmk_option_example},

    {"-spacer-",    0, 0, '-', "Increase the configuration version to prevent old configurations from being loaded accidentally:", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --modify --xml-text '<cib admin_epoch=\"admin_epoch++\"/>'", pcmk_option_example},

    {"-spacer-",    0, 0, '-', "Edit the configuration with your favorite $EDITOR:", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --query > $HOME/local.xml", pcmk_option_example},
    {"-spacer-",    0, 0, '-', " $EDITOR $HOME/local.xml", pcmk_option_example},
    {"-spacer-",    0, 0, '-', " cibadmin --replace --xml-file $HOME/local.xml", pcmk_option_example},

    {"-spacer-",    0, 0, '-', "SEE ALSO:"},
    {"-spacer-",    0, 0, '-', " crm(8), pcs(8), crm_shadow(8)"},

    /* Legacy options */
    {"host",	     1, 0, 'h', NULL, 1},

    {0, 0, 0, 0}
};
/* *INDENT-ON* */

static void
print_xml_output(xmlNode * xml)
{
    char *buffer;

    if (!xml) {
        return;
    } else if (xml->type != XML_ELEMENT_NODE) {
        return;
    }

    if (command_options & cib_xpath_address) {
        const char *id = crm_element_value(xml, XML_ATTR_ID);

        if (safe_str_eq((const char *)xml->name, "xpath-query")) {
            xmlNode *child = NULL;

            for (child = xml->children; child; child = child->next) {
                print_xml_output(child);
            }

        } else {
            printf("%s\n", id);
        }

    } else {
        buffer = dump_xml_formatted(xml);
        fprintf(stdout, "%s", crm_str(buffer));
        free(buffer);
    }
}

int
main(int argc, char **argv)
{
    int argerr = 0;
    int flag;
    const char *source = NULL;
    char *admin_input_xml = NULL;
    char *admin_input_file = NULL;
    gboolean dangerous_cmd = FALSE;
    gboolean admin_input_stdin = FALSE;
    xmlNode *output = NULL;
    xmlNode *input = NULL;

    int option_index = 0;

    crm_xml_init(); /* Sets buffer allocation strategy */
    crm_system_name = strdup("cibadmin");
    crm_set_options(NULL, "command [options] [data]", long_options,
                    "Provides direct access to the cluster configuration."
                    "\n\nAllows the configuration, or sections of it, to be queried, modified, replaced and deleted."
                    "\n\nWhere necessary, XML data will be obtained using the -X, -x, or -p options\n");

    if (argc < 2) {
        crm_help('?', EX_USAGE);
    }

    while (1) {
        flag = crm_get_option(argc, argv, &option_index);
        if (flag == -1)
            break;

        switch (flag) {
            case 't':
                message_timeout_ms = atoi(optarg);
                if (message_timeout_ms < 1) {
                    message_timeout_ms = 30;
                }
                break;
            case 'A':
                obj_type = strdup(optarg);
                command_options |= cib_xpath;
                break;
            case 'e':
                command_options |= cib_xpath_address;
                break;
            case 'u':
                cib_action = CIB_OP_UPGRADE;
                dangerous_cmd = TRUE;
                break;
            case 'E':
                cib_action = CIB_OP_ERASE;
                dangerous_cmd = TRUE;
                break;
            case 'Q':
                cib_action = CIB_OP_QUERY;
                quiet = TRUE;
                break;
            case 'P':
                cib_action = CIB_OP_APPLY_DIFF;
                break;
            case 'U':
                cib_user = optarg;
                break;
            case 'M':
                cib_action = CIB_OP_MODIFY;
                break;
            case 'R':
                cib_action = CIB_OP_REPLACE;
                break;
            case 'C':
                cib_action = CIB_OP_CREATE;
                break;
            case 'D':
                cib_action = CIB_OP_DELETE;
                break;
            case '5':
                cib_action = "md5-sum";
                break;
            case '6':
                cib_action = "md5-sum-versioned";
                break;
            case 'c':
                command_options |= cib_can_create;
                break;
            case 'n':
                command_options |= cib_no_children;
                break;
            case 'B':
                cib_action = CIB_OP_BUMP;
                break;
            case 'V':
                command_options = command_options | cib_verbose;
                bump_log_num++;
                break;
            case '?':
            case '$':
            case '!':
                crm_help(flag, EX_OK);
                break;
            case 'o':
                crm_trace("Option %c => %s", flag, optarg);
                obj_type = strdup(optarg);
                break;
            case 'X':
                crm_trace("Option %c => %s", flag, optarg);
                admin_input_xml = strdup(optarg);
                break;
            case 'x':
                crm_trace("Option %c => %s", flag, optarg);
                admin_input_file = strdup(optarg);
                break;
            case 'p':
                admin_input_stdin = TRUE;
                break;
            case 'N':
            case 'h':
                host = strdup(optarg);
                break;
            case 'l':
                command_options |= cib_scope_local;
                break;
            case 'd':
                cib_action = CIB_OP_DELETE;
                command_options |= cib_multiple;
                dangerous_cmd = TRUE;
                break;
            case 'b':
                dangerous_cmd = TRUE;
                command_options |= cib_inhibit_bcast;
                command_options |= cib_scope_local;
                break;
            case 's':
                command_options |= cib_sync_call;
                break;
            case 'f':
                force_flag = TRUE;
                command_options |= cib_quorum_override;
                break;
            case 'a':
                output = createEmptyCib(1);
                if (optind < argc) {
                    crm_xml_add(output, XML_ATTR_VALIDATION, argv[optind]);
                }
                admin_input_xml = dump_xml_formatted(output);
                fprintf(stdout, "%s\n", crm_str(admin_input_xml));
                goto bail;
                break;
            default:
                printf("Argument code 0%o (%c)" " is not (?yet?) supported\n", flag, flag);
                ++argerr;
                break;
        }
    }

    if (bump_log_num > 0) {
        quiet = FALSE;
    }
    crm_log_init(NULL, LOG_CRIT, FALSE, FALSE, argc, argv, quiet);
    while (bump_log_num > 0) {
        crm_bump_log_level(argc, argv);
        bump_log_num--;
    }

    if (optind < argc) {
        printf("non-option ARGV-elements: ");
        while (optind < argc)
            printf("%s ", argv[optind++]);
        printf("\n");
        crm_help('?', EX_USAGE);
    }

    if (optind > argc || cib_action == NULL) {
        ++argerr;
    }

    if (argerr) {
        crm_help('?', EX_USAGE);
    }

    if (dangerous_cmd && force_flag == FALSE) {
        fprintf(stderr, "The supplied command is considered dangerous."
                "  To prevent accidental destruction of the cluster,"
                " the --force flag is required in order to proceed.\n");
        fflush(stderr);
        exit_code = -EINVAL;
        goto bail;
    }

    if (admin_input_file != NULL) {
        input = filename2xml(admin_input_file);
        source = admin_input_file;

    } else if (admin_input_xml != NULL) {
        source = "input string";
        input = string2xml(admin_input_xml);

    } else if (admin_input_stdin) {
        source = "STDIN";
        input = stdin2xml();
    }

    if (input != NULL) {
        crm_log_xml_debug(input, "[admin input]");

    } else if (source) {
        fprintf(stderr, "Couldn't parse input from %s.\n", source);
        exit_code = -EINVAL;
        goto bail;
    }

    if (safe_str_eq(cib_action, "md5-sum")) {
        char *digest = NULL;

        if (input == NULL) {
            fprintf(stderr, "Please supply XML to process with -X, -x or -p\n");
            exit_code = -EINVAL;
            goto bail;
        }

        digest = calculate_on_disk_digest(input);
        fprintf(stderr, "Digest: ");
        fprintf(stdout, "%s\n", crm_str(digest));
        free(digest);
        goto bail;

    } else if (safe_str_eq(cib_action, "md5-sum-versioned")) {
        char *digest = NULL;
        const char *version = NULL;

        if (input == NULL) {
            fprintf(stderr, "Please supply XML to process with -X, -x or -p\n");
            exit_code = -EINVAL;
            goto bail;
        }

        version = crm_element_value(input, XML_ATTR_CRM_VERSION);
        digest = calculate_xml_versioned_digest(input, FALSE, TRUE, version);
        fprintf(stderr, "Versioned (%s) digest: ", version);
        fprintf(stdout, "%s\n", crm_str(digest));
        free(digest);
        goto bail;
    }

    exit_code = do_init();
    if (exit_code != pcmk_ok) {
        crm_err("Init failed, could not perform requested operations");
        fprintf(stderr, "Init failed, could not perform requested operations\n");
        return crm_exit(-exit_code);
    }

    exit_code = do_work(input, command_options, &output);
    if (exit_code > 0) {
        /* wait for the reply by creating a mainloop and running it until
         * the callbacks are invoked...
         */
        request_id = exit_code;

        the_cib->cmds->register_callback(the_cib, request_id, message_timeout_ms, FALSE, NULL,
                                         "cibadmin_op_callback", cibadmin_op_callback);

        mainloop = g_main_new(FALSE);

        crm_trace("%s waiting for reply from the local CIB", crm_system_name);

        crm_info("Starting mainloop");
        g_main_run(mainloop);

    } else if (exit_code < 0) {
        crm_err("Call failed: %s", pcmk_strerror(exit_code));
        fprintf(stderr, "Call failed: %s\n", pcmk_strerror(exit_code));
        operation_status = exit_code;

        if (exit_code == -pcmk_err_schema_validation) {
            if (crm_str_eq(cib_action, CIB_OP_UPGRADE, TRUE)) {
                xmlNode *obj = NULL;
                int version = 0, rc = 0;

                rc = the_cib->cmds->query(the_cib, NULL, &obj, command_options);
                if (rc == pcmk_ok) {
                    update_validation(&obj, &version, 0, TRUE, FALSE);
                }

            } else if (output) {
                validate_xml_verbose(output);
            }
        }
    }

    if (output != NULL) {
        print_xml_output(output);
        free_xml(output);
    }

    crm_trace("%s exiting normally", crm_system_name);

    free_xml(input);
    free(admin_input_xml);
    free(admin_input_file);
    flag = the_cib->cmds->signoff(the_cib);
    cib_delete(the_cib);

    if(exit_code == pcmk_ok) {
        exit_code = flag;
    }
  bail:
    return crm_exit(exit_code);
}

int
do_work(xmlNode * input, int call_options, xmlNode ** output)
{
    /* construct the request */
    the_cib->call_timeout = message_timeout_ms;
    if (strcasecmp(CIB_OP_REPLACE, cib_action) == 0
        && safe_str_eq(crm_element_name(input), XML_TAG_CIB)) {
        xmlNode *status = get_object_root(XML_CIB_TAG_STATUS, input);

        if (status == NULL) {
            create_xml_node(input, XML_CIB_TAG_STATUS);
        }
    }

    if (cib_action != NULL) {
        crm_trace("Passing \"%s\" to variant_op...", cib_action);
        return cib_internal_op(the_cib, cib_action, host, obj_type, input, output, call_options, cib_user);

    } else {
        crm_err("You must specify an operation");
    }
    return -EINVAL;
}

int
do_init(void)
{
    int rc = pcmk_ok;

    the_cib = cib_new();
    rc = the_cib->cmds->signon(the_cib, crm_system_name, cib_command);
    if (rc != pcmk_ok) {
        crm_err("Signon to CIB failed: %s", pcmk_strerror(rc));
        fprintf(stderr, "Signon to CIB failed: %s\n", pcmk_strerror(rc));
    }

    return rc;
}

void
cib_connection_destroy(gpointer user_data)
{
    crm_err("Connection to the CIB terminated... exiting");
    g_main_quit(mainloop);
    return;
}

void
cibadmin_op_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    exit_code = rc;

    if (rc != 0) {
        crm_warn("Call %s failed (%d): %s", cib_action, rc, pcmk_strerror(rc));
        fprintf(stderr, "Call %s failed (%d): %s\n", cib_action, rc, pcmk_strerror(rc));
        print_xml_output(output);

    } else if (safe_str_eq(cib_action, CIB_OP_QUERY) && output == NULL) {
        crm_err("Output expected in query response");
        crm_log_xml_err(msg, "no output");

    } else if (output == NULL) {
        crm_info("Call passed");

    } else {
        crm_info("Call passed");
        print_xml_output(output);
    }

    if (call_id == request_id) {
        g_main_quit(mainloop);

    } else {
        crm_info("Message was not the response we were looking for (%d vs. %d", call_id,
                 request_id);
    }
}
