/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <stdio.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ipc.h>
#include <crm/cib/internal.h>

#include <pacemaker-internal.h>

enum cibadmin_section_type {
    cibadmin_section_all = 0,
    cibadmin_section_scope,
    cibadmin_section_xpath,
};

static int request_id = 0;
static int bump_log_num = 0;

static const char *cib_user = NULL;

static cib_t *the_cib = NULL;
static GMainLoop *mainloop = NULL;
static crm_exit_t exit_code = CRM_EX_OK;

static struct {
    const char *cib_action;
    int cmd_options;
    enum cibadmin_section_type section_type;
    char *cib_section;
    gint message_timeout_sec;
    enum pcmk__acl_render_how acl_render_mode;
    gchar *dest_node;
    gchar *input_file;
    gchar *input_xml;
    gboolean input_stdin;
    bool delete_all;
    gboolean allow_create;
    gboolean force;
    gboolean get_node_path;
    gboolean local;
    gboolean no_children;
    gboolean sync_call;

    //! \deprecated
    gboolean no_bcast;
} options;

int do_init(void);
static int do_work(xmlNode *input, xmlNode **output);
void cibadmin_op_callback(xmlNode *msg, int call_id, int rc, xmlNode *output,
                          void *user_data);

static pcmk__cli_option_t long_options[] = {
    // long option, argument type, storage, short option, description, flags
    {
        "help", no_argument, NULL, '?',
        "\tThis text", pcmk__option_default
    },
    {
        "version", no_argument, NULL, '$',
        "\tVersion information", pcmk__option_default
    },
    {
        "verbose", no_argument, NULL, 'V',
        "\tIncrease debug output\n", pcmk__option_default
    },

    {
        "-spacer-", no_argument, NULL, '-',
        "Commands:", pcmk__option_default
    },
    {
        "upgrade", no_argument, NULL, 'u',
        "\tUpgrade the configuration to the latest syntax", pcmk__option_default
    },
    {
        "query", no_argument, NULL, 'Q',
        "\tQuery the contents of the CIB", pcmk__option_default
    },
    {
        "erase", no_argument, NULL, 'E',
        "\tErase the contents of the whole CIB", pcmk__option_default
    },
    {
        "bump", no_argument, NULL, 'B',
        "\tIncrease the CIB's epoch value by 1", pcmk__option_default
    },
    {
        "create", no_argument, NULL, 'C',
        "\tCreate an object in the CIB (will fail if object already exists)",
        pcmk__option_default
    },
    {
        "modify", no_argument, NULL, 'M',
        "\tFind object somewhere in CIB's XML tree and update it "
            "(fails if object does not exist unless -c is also specified)",
        pcmk__option_default
    },
    {
        "patch", no_argument, NULL, 'P',
        "\tSupply an update in the form of an XML diff (see crm_diff(8))",
        pcmk__option_default
    },
    {
        "replace", no_argument, NULL, 'R',
        "\tRecursively replace an object in the CIB", pcmk__option_default
    },
    {
        "delete", no_argument, NULL, 'D',
        "\tDelete first object matching supplied criteria "
            "(for example, <op id=\"rsc1_op1\" name=\"monitor\"/>)",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\n\tThe XML element name and all attributes must match "
            "in order for the element to be deleted.\n",
        pcmk__option_default
    },
    {
        "delete-all", no_argument, NULL, 'd',
        "When used with --xpath, remove all matching objects in the "
            "configuration instead of just the first one",
        pcmk__option_default
    },
    {
        "empty", no_argument, NULL, 'a',
        "\tOutput an empty CIB", pcmk__option_default
    },
    {
        "md5-sum", no_argument, NULL, '5',
        "\tCalculate the on-disk CIB digest", pcmk__option_default
    },
    {
        "md5-sum-versioned", no_argument, NULL, '6',
        "Calculate an on-the-wire versioned CIB digest", pcmk__option_default
    },
    {
        "show-access", optional_argument, NULL, 'S',
        "Whether to use syntax highlighting for ACLs "
            "(with -Q/--query and -U/--user)",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\n\tThat amounts to one of \"color\" (default for terminal),"
            " \"text\" (otherwise), \"namespace\", or \"auto\""
            " (per former defaults).",
        pcmk__option_default
    },
    {
        "blank", no_argument, NULL, '-',
        NULL, pcmk__option_hidden
    },

    {
        "-spacer-", required_argument, NULL, '-',
        "\nAdditional options:", pcmk__option_default
    },
    {
        "force", no_argument, NULL, 'f',
        NULL, pcmk__option_default
    },
    {
        "timeout", required_argument, NULL, 't',
        "Time (in seconds) to wait before declaring the operation failed",
        pcmk__option_default
    },
    {
        "user", required_argument, NULL, 'U',
        "Run the command with permissions of the named user (valid only for "
            "the root and " CRM_DAEMON_USER " accounts)",
        pcmk__option_default
    },
    {
        "sync-call", no_argument, NULL, 's',
        "Wait for call to complete before returning", pcmk__option_default
    },
    {
        "local", no_argument, NULL, 'l',
        "\tCommand takes effect locally (should be used only for queries)",
        pcmk__option_default
    },
    {
        "allow-create", no_argument, NULL, 'c',
        "(Advanced) Allow target of --modify/-M to be created "
            "if it does not exist",
        pcmk__option_default
    },
    {
        "no-children", no_argument, NULL, 'n',
        "(Advanced) When querying an object, do not include its children "
            "in the result",
        pcmk__option_default
    },
    {
        "no-bcast", no_argument, NULL, 'b',
        NULL, pcmk__option_hidden
    },

    {
        "-spacer-", no_argument, NULL, '-',
        "\nData:", pcmk__option_default
    },
    {
        "xml-text", required_argument, NULL, 'X',
        "Retrieve XML from the supplied string", pcmk__option_default
    },
    {
        "xml-file", required_argument, NULL, 'x',
        "Retrieve XML from the named file", pcmk__option_default
    },
    {
        "xml-pipe", no_argument, NULL, 'p',
        "Retrieve XML from stdin\n", pcmk__option_default
    },

    {
        "scope", required_argument, NULL, 'o',
        "Limit scope of operation to specific section of CIB",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\tValid values: configuration, nodes, resources, constraints, "
            "crm_config, rsc_defaults, op_defaults, acls, fencing-topology, "
            "tags, alerts",
        pcmk__option_default
    },

    {
        "xpath", required_argument, NULL, 'A',
        "A valid XPath to use instead of --scope/-o", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\n\tIf both --scope/-o and --xpath/-a are specified, the last one to "
        "appear takes effect\n",
        pcmk__option_default
    },
    {
        "node-path", no_argument, NULL, 'e',
        "When performing XPath queries, return path of any matches found",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\t(for example, \"/cib/configuration/resources/clone[@id='ms_RH1_SCS']"
            "/primitive[@id='prm_RH1_SCS']\")",
        pcmk__option_paragraph
    },
    {
        "node", required_argument, NULL, 'N',
        "(Advanced) Send command to the specified host", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '!',
        NULL, pcmk__option_hidden
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\n\nExamples:\n", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Query the configuration from the local node:", pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " cibadmin --query --local", pcmk__option_example
    },

    {
        "-spacer-", no_argument, NULL, '-',
        "Query just the cluster options configuration:", pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " cibadmin --query --scope crm_config", pcmk__option_example
    },

    {
        "-spacer-", no_argument, NULL, '-',
        "Query all 'target-role' settings:", pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " cibadmin --query --xpath \"//nvpair[@name='target-role']\"",
        pcmk__option_example
    },

    {
        "-spacer-", no_argument, NULL, '-',
        "Remove all 'is-managed' settings:", pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " cibadmin --delete-all --xpath \"//nvpair[@name='is-managed']\"",
        pcmk__option_example
    },

    {
        "-spacer-", no_argument, NULL, '-',
        "Remove the resource named 'old':", pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " cibadmin --delete --xml-text '<primitive id=\"old\"/>'",
        pcmk__option_example
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Remove all resources from the configuration:", pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " cibadmin --replace --scope resources --xml-text '<resources/>'",
        pcmk__option_example
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Replace complete configuration with contents of $HOME/pacemaker.xml:",
        pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " cibadmin --replace --xml-file $HOME/pacemaker.xml",
        pcmk__option_example
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Replace constraints section of configuration with contents of "
            "$HOME/constraints.xml:",
        pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " cibadmin --replace --scope constraints --xml-file "
            "$HOME/constraints.xml",
        pcmk__option_example
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Increase configuration version to prevent old configurations from "
            "being loaded accidentally:",
        pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " cibadmin --modify --xml-text '<cib admin_epoch=\"admin_epoch++\"/>'",
        pcmk__option_example
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Edit the configuration with your favorite $EDITOR:",
        pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " cibadmin --query > $HOME/local.xml", pcmk__option_example
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " $EDITOR $HOME/local.xml", pcmk__option_example
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " cibadmin --replace --xml-file $HOME/local.xml", pcmk__option_example
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Assuming terminal, render configuration in color (green for writable, blue for readable, red for denied) to visualize permissions for user tony:",
        pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " cibadmin --show-access=color --query --user tony | less -r",
        pcmk__option_example
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "SEE ALSO:", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " crm(8), pcs(8), crm_shadow(8), crm_diff(8)", pcmk__option_default
    },
    {
        "host", required_argument, NULL, 'h',
        "deprecated", pcmk__option_hidden
    },
    { 0, 0, 0, 0 }
};

static void
print_xml_output(xmlNode * xml)
{
    char *buffer;

    if (!xml) {
        return;
    } else if (xml->type != XML_ELEMENT_NODE) {
        return;
    }

    if (pcmk_is_set(options.cmd_options, cib_xpath_address)) {
        const char *id = crm_element_value(xml, XML_ATTR_ID);

        if (pcmk__str_eq((const char *)xml->name, "xpath-query", pcmk__str_casei)) {
            xmlNode *child = NULL;

            for (child = xml->children; child; child = child->next) {
                print_xml_output(child);
            }

        } else if (id) {
            printf("%s\n", id);
        }

    } else {
        buffer = dump_xml_formatted(xml);
        fprintf(stdout, "%s", pcmk__s(buffer, "<null>\n"));
        free(buffer);
    }
}

// Upgrade requested but already at latest schema
static void
report_schema_unchanged(void)
{
    const char *err = pcmk_rc_str(pcmk_rc_schema_unchanged);

    crm_info("Upgrade unnecessary: %s\n", err);
    printf("Upgrade unnecessary: %s\n", err);
    exit_code = CRM_EX_OK;
}

int
main(int argc, char **argv)
{
    int argerr = 0;
    int rc = pcmk_ok;
    int flag;
    const char *source = NULL;
    gboolean dangerous_cmd = FALSE;
    xmlNode *output = NULL;
    xmlNode *input = NULL;
    const char *acl_cred = NULL;

    int option_index = 0;

    pcmk__cli_init_logging("cibadmin", 0);
    set_crm_log_level(LOG_CRIT);
    pcmk__set_cli_options(NULL, "<command> [options]", long_options,
                          "query and edit the Pacemaker configuration");

    if (argc < 2) {
        pcmk__cli_help('?', CRM_EX_USAGE);
    }

    while (1) {
        flag = pcmk__next_cli_option(argc, argv, &option_index, NULL);
        if (flag == -1)
            break;

        switch (flag) {
            case 't':
                options.message_timeout_sec = (gint) atoi(optarg);
                break;
            case 'A':
                options.section_type = cibadmin_section_xpath;
                pcmk__str_update(&options.cib_section, optarg);
                break;
            case 'e':
                options.get_node_path = TRUE;
                break;
            case 'u':
                options.cib_action = PCMK__CIB_REQUEST_UPGRADE;
                dangerous_cmd = TRUE;
                break;
            case 'E':
                options.cib_action = PCMK__CIB_REQUEST_ERASE;
                dangerous_cmd = TRUE;
                break;
            case 'S':
                if (pcmk__str_eq(optarg, "auto", pcmk__str_null_matches)) {
                    options.acl_render_mode = pcmk__acl_render_default;

                } else if (strcmp(optarg, "namespace") == 0) {
                    options.acl_render_mode = pcmk__acl_render_namespace;

                } else if (strcmp(optarg, "text") == 0) {
                    options.acl_render_mode = pcmk__acl_render_text;

                } else if (strcmp(optarg, "color") == 0) {
                    options.acl_render_mode = pcmk__acl_render_color;

                } else {
                    fprintf(stderr,
                            "Unrecognized value for --show-access: '%s'\n",
                            optarg);
                    ++argerr;
                }
                break;
            case 'Q':
                options.cib_action = PCMK__CIB_REQUEST_QUERY;
                break;
            case 'P':
                options.cib_action = PCMK__CIB_REQUEST_APPLY_PATCH;
                break;
            case 'U':
                cib_user = optarg;
                break;
            case 'M':
                options.cib_action = PCMK__CIB_REQUEST_MODIFY;
                break;
            case 'R':
                options.cib_action = PCMK__CIB_REQUEST_REPLACE;
                break;
            case 'C':
                options.cib_action = PCMK__CIB_REQUEST_CREATE;
                break;
            case 'D':
                options.cib_action = PCMK__CIB_REQUEST_DELETE;
                options.delete_all = false;
                break;
            case '5':
                options.cib_action = "md5-sum";
                break;
            case '6':
                options.cib_action = "md5-sum-versioned";
                break;
            case 'c':
                options.allow_create = TRUE;
                break;
            case 'n':
                options.no_children = TRUE;
                break;
            case 'B':
                options.cib_action = PCMK__CIB_REQUEST_BUMP;
                break;
            case 'V':
                bump_log_num++;
                break;
            case '?':
            case '$':
            case '!':
                pcmk__cli_help(flag, CRM_EX_OK);
                break;
            case 'o':
                options.section_type = cibadmin_section_scope;
                pcmk__str_update(&options.cib_section, optarg);
                break;
            case 'X':
                g_free(options.input_xml);
                options.input_xml = g_strdup(optarg);
                break;
            case 'x':
                g_free(options.input_file);
                options.input_file = g_strdup(optarg);
                break;
            case 'p':
                options.input_stdin = TRUE;
                break;
            case 'N':
            case 'h':
                g_free(options.dest_node);
                options.dest_node = g_strdup(optarg);
                break;
            case 'l':
                options.local = TRUE;
                break;
            case 'd':
                options.cib_action = PCMK__CIB_REQUEST_DELETE;
                options.delete_all = true;
                dangerous_cmd = TRUE;
                break;
            case 'b':
                options.no_bcast = TRUE;
                dangerous_cmd = TRUE;
                break;
            case 's':
                options.sync_call = TRUE;
                break;
            case 'f':
                options.force = TRUE;
                break;
            case 'a':
                output = createEmptyCib(1);
                if (optind < argc) {
                    crm_xml_add(output, XML_ATTR_VALIDATION, argv[optind]);
                }
                g_free(options.input_xml);
                options.input_xml = dump_xml_formatted(output);
                fprintf(stdout, "%s", pcmk__s(options.input_xml, "<null>\n"));
                goto done;
            default:
                printf("Argument code 0%o (%c)" " is not (?yet?) supported\n", flag, flag);
                ++argerr;
                break;
        }
    }

    if (bump_log_num > 0) {
        cib__set_call_options(options.cmd_options, crm_system_name,
                              cib_verbose);
    }

    while (bump_log_num > 0) {
        crm_bump_log_level(argc, argv);
        bump_log_num--;
    }

    if (optind < argc) {
        printf("non-option ARGV-elements: ");
        while (optind < argc)
            printf("%s ", argv[optind++]);
        printf("\n");
        pcmk__cli_help('?', CRM_EX_USAGE);
    }

    if ((optind > argc) || (options.cib_action == NULL)) {
        ++argerr;
    }

    if (argerr) {
        pcmk__cli_help('?', CRM_EX_USAGE);
    }

    if (options.delete_all
        && (strcmp(options.cib_action, PCMK__CIB_REQUEST_DELETE) != 0)) {
        // --delete-all was replaced by some other action besides --delete
        options.delete_all = false;
    }

    if (dangerous_cmd && !options.force) {
        exit_code = CRM_EX_UNSAFE;
        fprintf(stderr, "The supplied command is considered dangerous."
                "  To prevent accidental destruction of the cluster,"
                " the --force flag is required in order to proceed.\n");
        fflush(stderr);
        goto done;
    }

    if (options.message_timeout_sec < 1) {
        // Set default timeout
        options.message_timeout_sec = 30;
    }

    if (options.section_type == cibadmin_section_xpath) {
        // Enable getting section by XPath
        cib__set_call_options(options.cmd_options, crm_system_name,
                              cib_xpath);
    }

    if (options.allow_create) {
        // Allow target of --modify/-M to be created if it does not exist
        cib__set_call_options(options.cmd_options, crm_system_name,
                              cib_can_create);
    }

    if (options.delete_all) {
        // With cibadmin_section_xpath, remove all matching objects
        cib__set_call_options(options.cmd_options, crm_system_name,
                              cib_multiple);
    }

    if (options.force) {
        // Perform the action even without quorum
        cib__set_call_options(options.cmd_options, crm_system_name,
                              cib_quorum_override);
    }

    if (options.get_node_path) {
        /* Enable getting node path of XPath query matches.
         * Meaningful only if options.section_type == cibadmin_section_xpath.
         */
        cib__set_call_options(options.cmd_options, crm_system_name,
                              cib_xpath_address);
    }

    if (options.local) {
        // Configure command to take effect only locally
        cib__set_call_options(options.cmd_options, crm_system_name,
                              cib_scope_local);
    }

    // @COMPAT: Deprecated option
    if (options.no_bcast) {
        // Configure command to take effect only locally and not to broadcast
        cib__set_call_options(options.cmd_options, crm_system_name,
                              cib_inhibit_bcast|cib_scope_local);
    }

    if (options.no_children) {
        // When querying an object, don't include its children in the result
        cib__set_call_options(options.cmd_options, crm_system_name,
                              cib_no_children);
    }

    if (options.sync_call
        || (options.acl_render_mode != pcmk__acl_render_none)) {
        /* Wait for call to complete before returning.
         *
         * The ACL render modes work only with sync calls due to differences in
         * output handling between sync/async. It shouldn't matter to the user
         * whether the call is synchronous; for a CIB query, we have to wait for
         * the result in order to display it in any case.
         */
        cib__set_call_options(options.cmd_options, crm_system_name,
                              cib_sync_call);
    }

    if (options.input_file != NULL) {
        input = filename2xml(options.input_file);
        source = options.input_file;

    } else if (options.input_xml != NULL) {
        input = string2xml(options.input_xml);
        source = "input string";

    } else if (options.input_stdin) {
        source = "STDIN";
        input = stdin2xml();

    } else if (options.acl_render_mode != pcmk__acl_render_none) {
        char *username = pcmk__uid2username(geteuid());
        bool required = pcmk_acl_required(username);

        free(username);

        if (required) {
            if (options.force) {
                fprintf(stderr, "The supplied command can provide skewed"
                                 " result since it is run under user that also"
                                 " gets guarded per ACLs on their own right."
                                 " Continuing since --force flag was"
                                 " provided.\n");

            } else {
                exit_code = CRM_EX_UNSAFE;
                fprintf(stderr, "The supplied command can provide skewed"
                                 " result since it is run under user that also"
                                 " gets guarded per ACLs in their own right."
                                 " To accept the risk of such a possible"
                                 " distortion (without even knowing it at this"
                                 " time), use the --force flag.\n");
                goto done;
            }
        }

        if (cib_user == NULL) {
            exit_code = CRM_EX_USAGE;
            fprintf(stderr,
                    "The supplied command requires -U user specified.\n");
            goto done;
        }

        /* we already stopped/warned ACL-controlled users about consequences */
        acl_cred = cib_user;
        cib_user = NULL;
    }

    if (input != NULL) {
        crm_log_xml_debug(input, "[admin input]");

    } else if (source != NULL) {
        exit_code = CRM_EX_CONFIG;
        fprintf(stderr, "Couldn't parse input from %s.\n", source);
        goto done;
    }

    if (strcmp(options.cib_action, "md5-sum") == 0) {
        char *digest = NULL;

        if (input == NULL) {
            exit_code = CRM_EX_USAGE;
            fprintf(stderr, "Please supply XML to process with -X, -x or -p\n");
            goto done;
        }

        digest = calculate_on_disk_digest(input);
        fprintf(stderr, "Digest: ");
        fprintf(stdout, "%s\n", pcmk__s(digest, "<null>"));
        free(digest);
        goto done;

    } else if (strcmp(options.cib_action, "md5-sum-versioned") == 0) {
        char *digest = NULL;
        const char *version = NULL;

        if (input == NULL) {
            exit_code = CRM_EX_USAGE;
            fprintf(stderr, "Please supply XML to process with -X, -x or -p\n");
            goto done;
        }

        version = crm_element_value(input, XML_ATTR_CRM_VERSION);
        digest = calculate_xml_versioned_digest(input, FALSE, TRUE, version);
        fprintf(stderr, "Versioned (%s) digest: ", version);
        fprintf(stdout, "%s\n", pcmk__s(digest, "<null>"));
        free(digest);
        goto done;
    }

    rc = do_init();
    if (rc != pcmk_ok) {
        rc = pcmk_legacy2rc(rc);
        exit_code = pcmk_rc2exitc(rc);

        crm_err("Init failed, could not perform requested operations: %s",
                pcmk_rc_str(rc));
        fprintf(stderr,
                "Init failed, could not perform requested operations: %s\n",
                pcmk_rc_str(rc));
        goto done;
    }

    rc = do_work(input, &output);
    if (rc > 0) {
        /* wait for the reply by creating a mainloop and running it until
         * the callbacks are invoked...
         */
        request_id = rc;

        the_cib->cmds->register_callback(the_cib, request_id,
                                         options.message_timeout_sec, FALSE,
                                         NULL, "cibadmin_op_callback",
                                         cibadmin_op_callback);

        mainloop = g_main_loop_new(NULL, FALSE);

        crm_trace("%s waiting for reply from the local CIB", crm_system_name);

        crm_info("Starting mainloop");
        g_main_loop_run(mainloop);

    } else if ((rc == -pcmk_err_schema_unchanged)
               && (strcmp(options.cib_action,
                          PCMK__CIB_REQUEST_UPGRADE) == 0)) {
        report_schema_unchanged();

    } else if (rc < 0) {
        rc = pcmk_legacy2rc(rc);
        crm_err("Call failed: %s", pcmk_rc_str(rc));
        fprintf(stderr, "Call failed: %s\n", pcmk_rc_str(rc));

        if (rc == pcmk_rc_schema_validation) {
            if (strcmp(options.cib_action, PCMK__CIB_REQUEST_UPGRADE) == 0) {
                xmlNode *obj = NULL;
                int version = 0;

                if (the_cib->cmds->query(the_cib, NULL, &obj,
                                         options.cmd_options) == pcmk_ok) {
                    update_validation(&obj, &version, 0, TRUE, FALSE);
                }

            } else if (output) {
                validate_xml_verbose(output);
            }
        }
        exit_code = pcmk_rc2exitc(rc);
    }

    if ((output != NULL)
        && (options.acl_render_mode != pcmk__acl_render_none)) {

        xmlDoc *acl_evaled_doc;
        rc = pcmk__acl_annotate_permissions(acl_cred, output->doc, &acl_evaled_doc);
        if (rc == pcmk_rc_ok) {
            xmlChar *rendered = NULL;

            rc = pcmk__acl_evaled_render(acl_evaled_doc,
                                         options.acl_render_mode, &rendered);
            if (rc != pcmk_rc_ok) {
                exit_code = CRM_EX_CONFIG;
                fprintf(stderr, "Could not render evaluated access: %s\n",
                        pcmk_rc_str(rc));
                goto done;
            }
            printf("%s\n", (char *) rendered);
            free(rendered);

        } else {
            exit_code = CRM_EX_CONFIG;
            fprintf(stderr,
                    "Could not evaluate access per request (%s, error: %s)\n",
                    acl_cred, pcmk_rc_str(rc));
            goto done;
        }

    } else if (output != NULL) {
        print_xml_output(output);
    }

    crm_trace("%s exiting normally", crm_system_name);

done:
    g_free(options.dest_node);
    g_free(options.input_file);
    g_free(options.input_xml);
    free(options.cib_section);
    free_xml(input);
    free_xml(output);

    rc = cib__clean_up_connection(&the_cib);
    if (exit_code == CRM_EX_OK) {
        exit_code = pcmk_rc2exitc(rc);
    }

    crm_exit(exit_code);
}

static int
do_work(xmlNode *input, xmlNode **output)
{
    /* construct the request */
    the_cib->call_timeout = options.message_timeout_sec;
    if ((strcmp(options.cib_action, PCMK__CIB_REQUEST_REPLACE) == 0)
        && pcmk__str_eq(crm_element_name(input), XML_TAG_CIB, pcmk__str_casei)) {
        xmlNode *status = pcmk_find_cib_element(input, XML_CIB_TAG_STATUS);

        if (status == NULL) {
            create_xml_node(input, XML_CIB_TAG_STATUS);
        }
    }

    crm_trace("Passing \"%s\" to variant_op...", options.cib_action);
    return cib_internal_op(the_cib, options.cib_action, options.dest_node,
                           options.cib_section, input, output,
                           options.cmd_options, cib_user);
}

int
do_init(void)
{
    int rc = pcmk_ok;

    the_cib = cib_new();
    rc = the_cib->cmds->signon(the_cib, crm_system_name, cib_command);
    if (rc != pcmk_ok) {
        crm_err("Could not connect to the CIB: %s", pcmk_strerror(rc));
        fprintf(stderr, "Could not connect to the CIB: %s\n",
                pcmk_strerror(rc));
    }

    return rc;
}

void
cibadmin_op_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    rc = pcmk_legacy2rc(rc);
    exit_code = pcmk_rc2exitc(rc);

    if (rc == pcmk_rc_schema_unchanged) {
        report_schema_unchanged();

    } else if (rc != pcmk_rc_ok) {
        crm_warn("Call %s failed: %s " CRM_XS " rc=%d",
                 options.cib_action, pcmk_rc_str(rc), rc);
        fprintf(stderr, "Call %s failed: %s\n",
                options.cib_action, pcmk_rc_str(rc));
        print_xml_output(output);

    } else if ((strcmp(options.cib_action, PCMK__CIB_REQUEST_QUERY) == 0)
               && (output == NULL)) {
        crm_err("Query returned no output");
        crm_log_xml_err(msg, "no output");

    } else if (output == NULL) {
        crm_info("Call passed");

    } else {
        crm_info("Call passed");
        print_xml_output(output);
    }

    if (call_id == request_id) {
        g_main_loop_quit(mainloop);

    } else {
        crm_info("Message was not the response we were looking for (%d vs. %d)",
                 call_id, request_id);
    }
}
