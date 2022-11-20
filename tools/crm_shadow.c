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
#include <unistd.h>

#include <sys/param.h>
#include <crm/crm.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <crm/common/ipc.h>

#include <crm/cib.h>
#include <crm/cib/internal.h>

static int command_options = cib_sync_call;
static cib_t *real_cib = NULL;
static int force_flag = 0;
static int batch_flag = 0;

static char *
get_shadow_prompt(const char *name)
{
    return crm_strdup_printf("shadow[%.40s] # ", name);
}

static void
shadow_setup(char *name, gboolean do_switch)
{
    const char *prompt = getenv("PS1");
    const char *shell = getenv("SHELL");
    char *new_prompt = get_shadow_prompt(name);

    printf("Setting up shadow instance\n");

    if (pcmk__str_eq(new_prompt, prompt, pcmk__str_casei)) {
        /* nothing to do */
        goto done;

    } else if (batch_flag == FALSE && shell != NULL) {
        setenv("PS1", new_prompt, 1);
        setenv("CIB_shadow", name, 1);
        printf("Type Ctrl-D to exit the crm_shadow shell\n");

        if (strstr(shell, "bash")) {
            execl(shell, shell, "--norc", "--noprofile", NULL);
        } else {
            execl(shell, shell, NULL);
        }

    } else if (do_switch) {
        printf("To switch to the named shadow instance, paste the following into your shell:\n");

    } else {
        printf
            ("A new shadow instance was created.  To begin using it paste the following into your shell:\n");
    }
    printf("  CIB_shadow=%s ; export CIB_shadow\n", name);

  done:
    free(new_prompt);
}

static void
shadow_teardown(char *name)
{
    const char *prompt = getenv("PS1");
    char *our_prompt = get_shadow_prompt(name);

    if (prompt != NULL && strstr(prompt, our_prompt)) {
        printf("Now type Ctrl-D to exit the crm_shadow shell\n");

    } else {
        printf
            ("Please remember to unset the CIB_shadow variable by pasting the following into your shell:\n");
        printf("  unset CIB_shadow\n");
    }
    free(our_prompt);
}

static pcmk__cli_option_t long_options[] = {
    // long option, argument type, storage, short option, description, flags
    {
        "help", no_argument, NULL, '?',
        "\t\tThis text", pcmk__option_default
    },
    {
        "version", no_argument, NULL, '$',
        "\t\tVersion information", pcmk__option_default
    },
    {
        "verbose", no_argument, NULL, 'V',
        "\t\tIncrease debug output", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nQueries:", pcmk__option_default
    },
    {
        "which", no_argument, NULL, 'w',
        "\t\tIndicate the active shadow copy", pcmk__option_default
    },
    {
        "display", no_argument, NULL, 'p',
        "\t\tDisplay the contents of the active shadow copy",
        pcmk__option_default
    },
    {
        "edit", no_argument, NULL, 'E',
        "\t\tEdit the contents of the active shadow copy with your "
            "favorite $EDITOR",
        pcmk__option_default
    },
    {
        "diff", no_argument, NULL, 'd',
        "\t\tDisplay the changes in the active shadow copy\n",
        pcmk__option_default
    },
    {
        "file", no_argument, NULL, 'F',
        "\t\tDisplay the location of the active shadow copy file\n",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nCommands:", pcmk__option_default
    },
    {
        "create", required_argument, NULL, 'c',
        "\tCreate the named shadow copy of the active cluster configuration",
        pcmk__option_default
    },
    {
        "create-empty", required_argument, NULL, 'e',
        "Create the named shadow copy with an empty cluster configuration. "
            "Optional: --validate-with",
        pcmk__option_default
    },
    {
        "commit", required_argument, NULL, 'C',
        "\tUpload the contents of the named shadow copy to the cluster",
        pcmk__option_default
    },
    {
        "delete", required_argument, NULL, 'D',
        "\tDelete the contents of the named shadow copy", pcmk__option_default
    },
    {
        "reset", required_argument, NULL, 'r',
        "\tRecreate named shadow copy from the active cluster configuration",
        pcmk__option_default
    },
    {
        "switch", required_argument, NULL, 's',
        "\t(Advanced) Switch to the named shadow copy", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nAdditional Options:", pcmk__option_default
    },
    {
        "force", no_argument, NULL, 'f',
        "\t\t(Advanced) Force the action to be performed", pcmk__option_default
    },
    {
        "batch", no_argument, NULL, 'b',
        "\t\t(Advanced) Don't spawn a new shell", pcmk__option_default
    },
    {
        "all", no_argument, NULL, 'a',
        "\t\t(Advanced) Upload entire CIB, including status, with --commit",
        pcmk__option_default
    },
    {
        "validate-with", required_argument, NULL, 'v',
        "(Advanced) Create an older configuration version", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nExamples:", pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Create a blank shadow configuration:", pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " crm_shadow --create-empty myShadow", pcmk__option_example
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Create a shadow configuration from the running cluster:",
        pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " crm_shadow --create myShadow", pcmk__option_example
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Display the current shadow configuration:", pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " crm_shadow --display", pcmk__option_example
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Discard the current shadow configuration (named myShadow):",
        pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " crm_shadow --delete myShadow --force", pcmk__option_example
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Upload current shadow configuration (named myShadow) "
            "to running cluster:",
        pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " crm_shadow --commit myShadow", pcmk__option_example
    },
    { 0, 0, 0, 0 }
};

int
main(int argc, char **argv)
{
    int rc = pcmk_ok;
    int flag;
    int argerr = 0;
    crm_exit_t exit_code = CRM_EX_OK;
    static int command = '?';
    const char *validation = NULL;
    char *shadow = NULL;
    char *shadow_file = NULL;
    gboolean full_upload = FALSE;
    gboolean dangerous_cmd = FALSE;
    struct stat buf;
    int option_index = 0;

    pcmk__cli_init_logging("crm_shadow", 0);
    pcmk__set_cli_options(NULL, "<query>|<command> [options]", long_options,
                          "perform Pacemaker configuration changes in a sandbox"
                          "\n\nThis command sets up an environment in which "
                          "configuration tools (cibadmin,\ncrm_resource, "
                          "etc.) work offline instead of against a live "
                          "cluster, allowing\nchanges to be previewed and "
                          "tested for side-effects.\n");

    if (argc < 2) {
        pcmk__cli_help('?', CRM_EX_USAGE);
    }

    while (1) {
        flag = pcmk__next_cli_option(argc, argv, &option_index, NULL);
        if (flag == -1 || flag == 0)
            break;

        switch (flag) {
            case 'a':
                full_upload = TRUE;
                break;
            case 'd':
            case 'E':
            case 'p':
            case 'w':
            case 'F':
                command = flag;
                pcmk__str_update(&shadow, getenv("CIB_shadow"));
                if (shadow == NULL) {
                    fprintf(stderr, "No active shadow configuration defined\n");
                    exit_code = CRM_EX_NOSUCH;
                    goto done;
                }
                break;
            case 'v':
                validation = optarg;
                break;
            case 'e':
            case 'c':
            case 's':
            case 'r':
                command = flag;
                pcmk__str_update(&shadow, optarg);
                break;
            case 'C':
            case 'D':
                command = flag;
                dangerous_cmd = TRUE;
                pcmk__str_update(&shadow, optarg);
                break;
            case 'V':
                command_options = command_options | cib_verbose;
                crm_bump_log_level(argc, argv);
                break;
            case '$':
            case '?':
                pcmk__cli_help(flag, CRM_EX_OK);
                goto done;
            case 'f':
                cib__set_call_options(command_options, crm_system_name,
                                      cib_quorum_override);
                force_flag = 1;
                break;
            case 'b':
                batch_flag = 1;
                break;
            default:
                printf("Argument code 0%o (%c)" " is not (?yet?) supported\n", flag, flag);
                ++argerr;
                break;
        }
    }

    if (optind < argc) {
        printf("non-option ARGV-elements: ");
        while (optind < argc)
            printf("%s ", argv[optind++]);
        printf("\n");
        pcmk__cli_help('?', CRM_EX_USAGE);
    }

    if (optind > argc) {
        ++argerr;
    }

    // '?' here means no command was set and "-?" was not passed explicitly
    if ((argerr > 0) || (command == '?')) {
        pcmk__cli_help('?', CRM_EX_USAGE);
    }

    // If we reach this point, shadow is non-NULL

    if (command == 'w') {
        // Which shadow instance is active?
        fprintf(stdout, "%s\n", shadow);
        goto done;
    }

    if ((command != 's') && (command != 'c')) {
        const char *local = getenv("CIB_shadow");

        if (local != NULL && !pcmk__str_eq(local, shadow, pcmk__str_casei) && force_flag == FALSE) {
            fprintf(stderr,
                    "The supplied shadow instance (%s) is not the same as the active one (%s).\n"
                    "  To prevent accidental destruction of the cluster,"
                    " the --force flag is required in order to proceed.\n", shadow, local);
            fflush(stderr);
            exit_code = CRM_EX_USAGE;
            goto done;
        }
    }

    if (dangerous_cmd && force_flag == FALSE) {
        fprintf(stderr, "The supplied command is considered dangerous."
                "  To prevent accidental destruction of the cluster,"
                " the --force flag is required in order to proceed.\n");
        fflush(stderr);
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    shadow_file = get_shadow_file(shadow);
    if (command == 'D') {
        /* delete the file */
        if ((unlink(shadow_file) < 0) && (errno != ENOENT)) {
            exit_code = pcmk_rc2exitc(errno);
            fprintf(stderr, "Could not remove shadow instance '%s': %s\n",
                    shadow, strerror(errno));
        }
        shadow_teardown(shadow);
        goto done;

    } else if (command == 'F') {
        printf("%s\n", shadow_file);
        goto done;
    }

    if (command == 'd' || command == 'r' || command == 'c' || command == 'C') {
        real_cib = cib_new_no_shadow();
        rc = real_cib->cmds->signon(real_cib, crm_system_name, cib_command);
        if (rc != pcmk_ok) {
            rc = pcmk_legacy2rc(rc);
            fprintf(stderr, "Could not connect to CIB: %s\n", pcmk_rc_str(rc));
            exit_code = pcmk_rc2exitc(rc);
            goto done;
        }
    }

    // File existence check
    rc = stat(shadow_file, &buf);
    if (command == 'e' || command == 'c') {
        if (rc == 0 && force_flag == FALSE) {
            fprintf(stderr, "A shadow instance '%s' already exists.\n"
                    "  To prevent accidental destruction of the cluster,"
                    " the --force flag is required in order to proceed.\n", shadow);
            exit_code = CRM_EX_CANTCREAT;
            goto done;
        }
    } else if (rc < 0) {
        fprintf(stderr, "Could not access shadow instance '%s': %s\n", shadow, strerror(errno));
        exit_code = CRM_EX_NOSUCH;
        goto done;
    }

    if (command == 'c' || command == 'e' || command == 'r') {
        xmlNode *output = NULL;

        /* create a shadow instance based on the current cluster config */
        if (command == 'c' || command == 'r') {
            rc = real_cib->cmds->query(real_cib, NULL, &output, command_options);
            if (rc != pcmk_ok) {
                rc = pcmk_legacy2rc(rc);
                fprintf(stderr, "Could not connect to the CIB manager: %s\n",
                        pcmk_rc_str(rc));
                exit_code = pcmk_rc2exitc(rc);
                goto done;
            }

        } else {
            output = createEmptyCib(0);
            if(validation) {
                crm_xml_add(output, XML_ATTR_VALIDATION, validation);
            }
            printf("Created new %s configuration\n",
                   crm_element_value(output, XML_ATTR_VALIDATION));
        }

        rc = write_xml_file(output, shadow_file, FALSE);
        free_xml(output);

        if (rc < 0) {
            rc = pcmk_legacy2rc(rc);
            fprintf(stderr, "Could not %s the shadow instance '%s': %s\n",
                    command == 'r' ? "reset" : "create",
                    shadow, pcmk_rc_str(rc));
            exit_code = pcmk_rc2exitc(rc);
            goto done;
        }
        shadow_setup(shadow, FALSE);

    } else if (command == 'E') {
        char *editor = getenv("EDITOR");

        if (editor == NULL) {
            fprintf(stderr, "No value for EDITOR defined\n");
            exit_code = CRM_EX_NOT_CONFIGURED;
            goto done;
        }

        execlp(editor, "--", shadow_file, NULL);
        fprintf(stderr, "Could not invoke EDITOR (%s %s): %s\n",
                editor, shadow_file, strerror(errno));
        exit_code = CRM_EX_OSFILE;
        goto done;

    } else if (command == 's') {
        shadow_setup(shadow, TRUE);
        goto done;

    } else if (command == 'p') {
        /* display the current contents */
        char *output_s = NULL;
        xmlNode *output = filename2xml(shadow_file);

        output_s = dump_xml_formatted(output);
        printf("%s", output_s);

        free(output_s);
        free_xml(output);

    } else if (command == 'd') {
        /* diff against cluster */
        xmlNode *diff = NULL;
        xmlNode *old_config = NULL;
        xmlNode *new_config = filename2xml(shadow_file);

        rc = real_cib->cmds->query(real_cib, NULL, &old_config, command_options);

        if (rc != pcmk_ok) {
            rc = pcmk_legacy2rc(rc);
            fprintf(stderr, "Could not query the CIB: %s\n", pcmk_rc_str(rc));
            exit_code = pcmk_rc2exitc(rc);
            goto done;
        }

        xml_track_changes(new_config, NULL, new_config, FALSE);
        xml_calculate_changes(old_config, new_config);

        diff = xml_create_patchset(0, old_config, new_config, NULL, FALSE);

        xml_log_changes(LOG_INFO, __func__, new_config);
        xml_accept_changes(new_config);

        if (diff != NULL) {
            xml_log_patchset(LOG_STDOUT, "  ", diff);
            exit_code = CRM_EX_ERROR;
        }
        goto done;

    } else if (command == 'C') {
        /* commit to the cluster */
        xmlNode *input = filename2xml(shadow_file);
        xmlNode *section_xml = input;
        const char *section = NULL;

        if (!full_upload) {
            section = XML_CIB_TAG_CONFIGURATION;
            section_xml = first_named_child(input, section);
        }
        rc = real_cib->cmds->replace(real_cib, section, section_xml,
                                     command_options);
        if (rc != pcmk_ok) {
            rc = pcmk_legacy2rc(rc);
            fprintf(stderr, "Could not commit shadow instance '%s' to the CIB: %s\n",
                    shadow, pcmk_rc_str(rc));
            exit_code = pcmk_rc2exitc(rc);
        }
        shadow_teardown(shadow);
        free_xml(input);
    }
  done:
    free(shadow_file);
    free(shadow);
    crm_exit(exit_code);
}
