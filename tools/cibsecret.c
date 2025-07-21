/*
 * Copyright 2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>           // umask, S_IRGRP, S_IROTH, ...

#include <glib.h>

#include <crm/common/internal.h>
#include <crm/common/results.h>

#define SUMMARY "cibsecret - manage sensitive information in Pacemaker CIB"

static gchar **remainder = NULL;
static gboolean no_cib = FALSE;

static GOptionEntry entries[] = {
    { "no-cib", 'C', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &no_cib,
      "Don't read or write the CIB",
      NULL },

    { G_OPTION_REMAINING, 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING_ARRAY, &remainder,
      NULL,
      NULL },

    { NULL }
};

struct subcommand_entry {
    const char *name;
    int args;
    const char *usage;
    bool requires_cib;
    /* The shell version of cibsecret exited with a wide variety of error codes
     * for all sorts of situations.  Our standard Pacemaker return codes don't
     * really line up with what it was doing - either we don't have a code with
     * the right name, or we have one that doesn't map to the right exit code,
     * etc.
     *
     * For backwards compatibility, the subcommand handler functions will
     * return a standard Pacemaker so other functions here know what to do, but
     * it will also take exit_code as an out parameter for the subcommands to
     * set and for us to exit with.
     */
    int (*handler)(pcmk__output_t *out, crm_exit_t *exit_code);
};

static int
subcommand_check(pcmk__output_t *out, crm_exit_t *exit_code)
{
    return pcmk_rc_ok;
}

static int
subcommand_delete(pcmk__output_t *out, crm_exit_t *exit_code)
{
    return pcmk_rc_ok;
}

static int
subcommand_get(pcmk__output_t *out, crm_exit_t *exit_code)
{
    return pcmk_rc_ok;
}

/* The previous shell implementation of cibsecret allowed passing the value
 * to set (what would be remainder[3] here) via stdin, which we do not support
 * here at the moment.
 */
static int
subcommand_set(pcmk__output_t *out, crm_exit_t *exit_code)
{
    return pcmk_rc_ok;
}

static int
subcommand_stash(pcmk__output_t *out, crm_exit_t *exit_code)
{
    return pcmk_rc_ok;
}

static int
subcommand_sync(pcmk__output_t *out, crm_exit_t *exit_code)
{
    return pcmk_rc_ok;
}

static int
subcommand_unstash(pcmk__output_t *out, crm_exit_t *exit_code)
{
    return pcmk_rc_ok;
}

static struct subcommand_entry subcommand_table[] = {
    { "check", 2, "check <resource-id> <resource-parameter>", false,
      subcommand_check },
    { "delete", 2, "delete <resource-id> <resource-parameter>", false,
      subcommand_delete },
    { "get", 2, "get <resource-id> <resource-parameter>", false,
      subcommand_get },
    { "set", 3, "set <resource-id> <resource-parameter> <value>", false,
      subcommand_set },
    { "stash", 2, "stash <resource-id> <resource-parameter>", true,
      subcommand_stash },
    { "sync", 0, "sync", false, subcommand_sync },
    { "unstash", 2, "unstash <resource-id> <resource-parameter>", true,
      subcommand_unstash },
    { NULL },
};

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    const char *desc = NULL;
    GOptionContext *context = NULL;

    desc = "This command manages sensitive resource parameter values that should not be\n"
           "stored directly in Pacemaker's Cluster Information Base (CIB). Such values\n"
           "are handled by storing a special string directly in the CIB that tells\n"
           "Pacemaker to look in a separate, protected file for the actual value.\n\n"

           "The secret files are not encrypted, but protected by file system permissions\n"
           "such that only root can read or modify them.\n\n"

           "Since the secret files are stored locally, they must be synchronized across all\n"
           "cluster nodes. This command handles the synchronization using (in order of\n"
           "preference) pssh, pdsh, or ssh, so one of those must be installed. Before\n"
           "synchronizing, this command will ping the cluster nodes to determine which are\n"
           "alive, using fping if it is installed, otherwise the ping command. Installing\n"
           "fping is strongly recommended for better performance.\n\n"

           "Commands and their parameters:\n\n"
           "check <resource-id> <resource-parameter>\n"
           "\tVerify that the locally stored value of a sensitive resource parameter\n"
           "\tmatches its locally stored MD5 hash.\n\n"
           "delete <resource-id> <resource-parameter>\n"
           "\tRemove a sensitive resource parameter value.\n\n"
           "get <resource-id> <resource-parameter>\n"
           "\tDisplay the locally stored value of a sensitive resource parameter.\n\n"
           "set <resource-id> <resource-parameter> <value>\n"
           "\tSet the value of a sensitive resource parameter.\n\n"
           "stash <resource-id> <resource-parameter>\n"
           "\tMake a non-sensitive resource parameter that is already in the CIB\n"
           "\tsensitive (move its value to a locally stored and protected file).\n"
           "\tThis may not be used with -C.\n\n"
           "sync\n"
           "\tCopy all locally stored secrets to all other nodes.\n\n"
           "unstash <resource-id> <resource-parameter>\n"
           "\tMake a sensitive resource parameter that is already in the CIB\n"
           "\tnon-sensitive (move its value from the locally stored file to the CIB).\n"
           "\tThis may not be used with -C.\n\n\n"

           "Known limitations:\n\n"

           "This command can only be run from full cluster nodes (not Pacemaker Remote\n"
           "nodes).\n\n"

           "Changes are not atomic, so the cluster may use different values while a\n"
           "change is in progress. To avoid problems, it is recommended to put the\n"
           "cluster in maintenance mode when making changes with this command.\n\n"

           "Changes in secret values do not trigger an agent reload or restart of the\n"
           "affected resource, since they do not change the CIB. If a response is\n"
           "desired before the next cluster recheck interval, any CIB change (such as\n"
           "setting a node attribute) will trigger it.\n\n"

           "If any node is down when changes to secrets are made, or a new node is\n"
           "later added to the cluster, it may have different values when it joins the\n"
           "cluster, before 'cibsecret sync' is run. To avoid this, it is recommended to\n"
           "run the sync command (from another node) before starting Pacemaker on the\n"
           "node.\n\n"

           "Examples:\n\n"

           "# cibsecret set ipmi_node1 passwd SecreT_PASS\n\n"
           "# cibsecret get ipmi_node1 passwd\n\n"
           "# cibsecret check ipmi_node1 passwd\n\n"
           "# cibsecret stash ipmi_node2 passwd\n\n"
           "# cibsecret sync\n";

    context = pcmk__build_arg_context(args, "text (default), xml", group,
                                      "<subcommand> [options]");
    g_option_context_set_description(context, desc);
    pcmk__add_main_args(context, entries);
    return context;
}

int
main(int argc, char **argv)
{
    crm_exit_t exit_code = CRM_EX_OK;
    int rc = pcmk_rc_ok;

    pcmk__output_t *out = NULL;

    GError *error = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, NULL);
    GOptionContext *context = build_arg_context(args, &output_group);

    struct subcommand_entry cmd;

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("cibsecret", args->verbosity);

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error creating output format %s: %s", args->output_ty,
                    pcmk_rc_str(rc));
        goto done;
    }

    if (args->version) {
        out->version(out);
        goto done;
    }

    /* No subcommand was given */
    if ((remainder == NULL) || (g_strv_length(remainder) == 0)) {
        gchar *help = g_option_context_get_help(context, TRUE, NULL);

        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Must specify a command option\n\n%s", help);
        g_free(help);
        goto done;
    }

    /* Traverse the subcommand table looking for a match. */
    for (int i = 0; i < PCMK__NELEM(subcommand_table); i++) {
        cmd = subcommand_table[i];

        if (!pcmk__str_eq(remainder[0], cmd.name, pcmk__str_none)) {
            continue;
        }

        /* We found a match.  Check that enough arguments were given and
         * display a usage message if not.  The "+ 1" is because the table
         * entry lists how many arguments the subcommand takes, which does not
         * include the subcommand itself.
         */
        if (g_strv_length(remainder) != cmd.args + 1) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Usage: %s",
                        cmd.usage);
            goto done;
        }

        /* We've found the subcommand handler and it's used correctly. */
        break;
    }

    /* If we didn't find a match, a valid subcommand wasn't given. */
    if (cmd.name == NULL) {
        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Invalid subcommand given; valid subcommands: "
                    "check, delete, get, set, stash, sync, unstash");
        goto done;
    }

    /* Set a default umask so files we create are only accessible by the
     * cluster user.
     */
    umask(S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH);

    /* Call the subcommand handler.  If the handler fails, it will have already
     * set exit_code to the reason why so there's no need to worry with
     * additional error checking here at the moment.
     */
    if (cmd.requires_cib && no_cib) {
        out->err(out, "No access to Pacemaker, %s not supported", cmd.name);
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    cmd.handler(out, &exit_code);

 done:
    g_strfreev(processed_args);
    g_strfreev(remainder);
    pcmk__free_arg_context(context);

    pcmk__output_and_clear_error(&error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }
    pcmk__unregister_formats();
    crm_exit(exit_code);
}
