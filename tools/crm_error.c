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

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",       0, 0, '?', "\tThis text"},
    {"version",    0, 0, '$', "\tVersion information"  },
    {"verbose",    0, 0, 'V', "\tIncrease debug output"},

    {"name",    0, 0, 'n', "\tShow the error's name with its description."
     "\n\t\t\tUseful for looking for sources of the error in source code"},

    {"list",    0, 0, 'l', "\tShow all known errors."},
    {"exit",    0, 0, 'X', "\tInterpret as exit code rather than legacy function return value"},
    {"rc",      0, 0, 'r', "\tInterpret as return code rather than legacy function return value"},

    {0, 0, 0, 0}
};
/* *INDENT-ON* */

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
    crm_set_options(NULL, "[options] -- <rc> [...]", long_options,
                    "Tool for displaying the textual name or description of a reported error code");

    while (flag >= 0) {
        flag = crm_get_option(argc, argv, &option_index);
        switch (flag) {
            case -1:
                break;
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case '$':
            case '?':
                crm_help(flag, CRM_EX_OK);
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
                crm_help(flag, CRM_EX_OK);
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
