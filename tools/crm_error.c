/*
 * Copyright 2012-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/crm.h>

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
        "\tIncrease debug output", pcmk__option_default
    },
    {
        "name", no_argument, NULL, 'n',
        "\tShow error's name with its description (useful for looking for "
            "sources of the error in source code)",
        pcmk__option_default
    },
    {
        "list", no_argument, NULL, 'l',
        "\tShow all known errors", pcmk__option_default
    },
    {
        "exit", no_argument, NULL, 'X',
        "\tInterpret as exit code rather than legacy function return value",
        pcmk__option_default
    },
    {
        "rc", no_argument, NULL, 'r',
        "\tInterpret as return code rather than legacy function return value",
        pcmk__option_default
    },
    { 0, 0, 0, 0 }
};

static bool as_exit_code = false;
static bool as_rc = false;

static void
get_strings(int rc, const char **name, const char **str)
{
    if (as_exit_code) {
        *str = crm_exit_str((crm_exit_t) rc);
        *name = crm_exit_name(rc);
    } else if (as_rc) {
        *str = pcmk_rc_str(rc);
        *name = pcmk_rc_name(rc);
    } else {
        *str = pcmk_strerror(rc);
        *name = pcmk_errorname(rc);
    }
}

int
main(int argc, char **argv)
{
    int rc = 0;
    int lpc = 0;
    int flag = 0;
    int option_index = 0;

    bool do_list = FALSE;
    bool with_name = FALSE;

    const char *name = NULL;
    const char *desc = NULL;

    crm_log_cli_init("crm_error");
    pcmk__set_cli_options(NULL, "[options] -- <rc> [...]", long_options,
                          "display name or description of a Pacemaker "
                          "error code");

    while (flag >= 0) {
        flag = pcmk__next_cli_option(argc, argv, &option_index, NULL);
        switch (flag) {
            case -1:
                break;
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case '$':
            case '?':
                pcmk__cli_help(flag, CRM_EX_OK);
                break;
            case 'n':
                with_name = TRUE;
                break;
            case 'l':
                do_list = TRUE;
                break;
            case 'r':
                as_rc = true;
                break;
            case 'X':
                as_exit_code = TRUE;
                break;
            default:
                pcmk__cli_help(flag, CRM_EX_OK);
                break;
        }
    }

    if(do_list) {
        int start, end, width;

        // 256 is a hacky magic number that "should" be enough
        if (as_rc) {
            start = pcmk_rc_error - 256;
            end = PCMK_CUSTOM_OFFSET;
            width = 4;
        } else {
            start = 0;
            end = 256;
            width = 3;
        }

        for (rc = start; rc < end; rc++) {
            if (rc == (pcmk_rc_error + 1)) {
                // Values in between are reserved for callers, no use iterating
                rc = pcmk_rc_ok;
            }
            get_strings(rc, &name, &desc);
            if (!name || !strcmp(name, "Unknown") || !strcmp(name, "CRM_EX_UNKNOWN")) {
                // Undefined
            } else if(with_name) {
                printf("% .*d: %-26s  %s\n", width, rc, name, desc);
            } else {
                printf("% .*d: %s\n", width, rc, desc);
            }
        }

    } else {
        for (lpc = optind; lpc < argc; lpc++) {
            rc = crm_atoi(argv[lpc], NULL);
            get_strings(rc, &name, &desc);
            if (with_name) {
                printf("%s - %s\n", name, desc);
            } else {
                printf("%s\n", desc);
            }
        }
    }
    return CRM_EX_OK;
}
