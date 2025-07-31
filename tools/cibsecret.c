/*
 * Copyright 2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <glib.h>
#include <libxml/parser.h>

#include <crm/cib/internal.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/internal.h>
#include <crm/common/logging_internal.h>
#include <crm/common/output_internal.h>
#include <crm/common/results.h>
#include <crm/common/results_internal.h>
#include <crm/common/xml.h>
#include <crm/common/xpath_internal.h>
#include <pacemaker.h>
#include <pacemaker-internal.h>

#define SUMMARY "cibsecret - manage sensitive information in Pacemaker CIB"

#define LRM_MAGIC "lrm://"

static gchar **remainder = NULL;
static gboolean no_cib = FALSE;

static GOptionEntry entries[] = {
    { "no-cib", 'C', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &no_cib,
      NULL,
      NULL },

    { G_OPTION_REMAINING, 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING_ARRAY, &remainder,
      NULL,
      NULL },

    { NULL }
};

typedef int (*rsh_fn_t)(pcmk__output_t *out, GList *nodes, const char *cmdline);
typedef int (*rcp_fn_t)(pcmk__output_t *out, GList *nodes, const char *to,
                        const char *from);

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
    int (*handler)(pcmk__output_t *out, rsh_fn_t rsh_fn, rcp_fn_t rcp_fn,
                   crm_exit_t *exit_code);
};

static int
run_cmdline(pcmk__output_t *out, const char *cmdline, char **standard_out)
{
    int rc = pcmk_rc_ok;
    gboolean success = FALSE;
    GError *error = NULL;
    gchar *sout = NULL;
    gchar *serr = NULL;
    gint status;

    success = g_spawn_command_line_sync(cmdline, &sout, &serr, &status, &error);
    if (!success) {
        out->err(out, "%s", error->message);
        out->err(out, "%s\n%s", sout, serr);
        rc = pcmk_rc_error;
        goto done;
    }

    success = g_spawn_check_exit_status(status, &error);
    if (!success) {
        out->err(out, "%s",  error->message);
        out->err(out, "%s\n%s", sout, serr);
        rc = pcmk_rc_error;
    }

done:
    if (standard_out != NULL) {
        *standard_out = strdup(sout);
    }

    g_free(sout);
    g_free(serr);

    if (error != NULL) {
        g_error_free(error);
    }

    return rc;
}

static int
pssh(pcmk__output_t *out, GList *nodes, const char *cmdline)
{
    int rc = pcmk_rc_ok;
    char *s = NULL;
    GString *hosts = g_string_sized_new(64);

    for (GList *node = nodes; node != NULL; node = node->next) {
        pcmk__add_separated_word(&hosts, 64, node->data, " ");
    }

    s = crm_strdup_printf("pssh -i -H \"%s\" -x StrictHostKeyChecking=no -- \"%s\"",
                          hosts->str, cmdline);
    rc = run_cmdline(out, s, NULL);

    free(s);
    g_string_free(hosts, TRUE);
    return rc;
}

static int
pdsh(pcmk__output_t *out, GList *nodes, const char *cmdline)
{
    int rc = pcmk_rc_ok;
    char *s = NULL;
    GString *hosts = g_string_sized_new(64);

    for (GList *node = nodes; node != NULL; node = node->next) {
        pcmk__add_separated_word(&hosts, 64, node->data, ",");
    }

    s = crm_strdup_printf("pdsh -w \"%s\" -- \"%s\"", hosts->str, cmdline);
    setenv("PDSH_SSH_ARGS_APPEND", "\"-o StrictHostKeyChecking=no\"", 1);
    rc = run_cmdline(out, s, NULL);
    unsetenv("PDSH_SSH_ARGS_APPEND");

    free(s);
    g_string_free(hosts, TRUE);
    return rc;
}

static int
ssh(pcmk__output_t *out, GList *nodes, const char *cmdline)
{
    int rc = pcmk_rc_ok;

    for (GList *node = nodes; node != NULL; node = node->next) {
        int this_rc = pcmk_rc_ok;
        char *s = crm_strdup_printf("ssh -o StrictHostKeyChecking=no \"%s\" -- \"%s\"",
                                    (char *) node->data, cmdline);

        this_rc = run_cmdline(out, s, NULL);
        if (this_rc != pcmk_rc_ok) {
            rc = this_rc;
        }

        free(s);
    }

    return rc;
}

static int
pscp(pcmk__output_t *out, GList *nodes, const char *to, const char *from)
{
    int rc = pcmk_rc_ok;
    char *s = NULL;
    GString *hosts = g_string_sized_new(64);

    for (GList *node = nodes; node != NULL; node = node->next) {
        pcmk__add_separated_word(&hosts, 64, node->data, " ");
    }

    s = crm_strdup_printf("pscp -H \"%s\" -x \"-pr\" -x StrictHostKeyChecking=no -- \"%s\" \"%s\"",
                          hosts->str, from, to);
    rc = run_cmdline(out, s, NULL);

    free(s);
    g_string_free(hosts, TRUE);
    return rc;
}

static int
pdcp(pcmk__output_t *out, GList *nodes, const char *to, const char *from)
{
    int rc = pcmk_rc_ok;
    char *s = NULL;
    GString *hosts = g_string_sized_new(64);

    for (GList *node = nodes; node != NULL; node = node->next) {
        pcmk__add_separated_word(&hosts, 64, node->data, ",");
    }

    s = crm_strdup_printf("pdcp -pr -w \"%s\" -- \"%s\" \"%s\"", hosts->str,
                          from, to);
    setenv("PDSH_SSH_ARGS_APPEND", "\"-o StrictHostKeyChecking=no\"", 1);
    rc = run_cmdline(out, s, NULL);
    unsetenv("PDSH_SSH_ARGS_APPEND");

    free(s);
    g_string_free(hosts, TRUE);
    return rc;
}

static int
scp(pcmk__output_t *out, GList *nodes, const char *to, const char *from)
{
    int rc = pcmk_rc_ok;

    for (GList *node = nodes; node != NULL; node = node->next) {
        int this_rc = pcmk_rc_ok;
        char *s = crm_strdup_printf("scp -pqr -o StrictHostKeyChecking=no \"%s\" \"%s:%s\"",
                                    from, (const char *) node->data, to);

        this_rc = run_cmdline(out, s, NULL);
        if (this_rc != pcmk_rc_ok) {
            rc = this_rc;

        }

        free(s);
    }

    return rc;
}

static bool
host_reachable(pcmk__output_t *out, const char *uname)
{
    char *cmdline = NULL;
    int rc = pcmk_rc_ok;

    if (g_find_program_in_path("fping") && geteuid() == 0) {
        cmdline = crm_strdup_printf("fping %s", uname);
    } else {
        cmdline = crm_strdup_printf("ping -c 2 -q %s", uname);
    }

    rc = run_cmdline(out, cmdline, NULL);
    free(cmdline);
    return rc == pcmk_rc_ok;
}

struct node_data {
    pcmk__output_t *out;
    const char *local_node;
    const char *field;
    GList *nodes;
};

static void
node_iter_helper(xmlNode *result, void *user_data)
{
    struct node_data *data = user_data;
    const char *uname = crm_element_value(result, PCMK_XA_UNAME);
    const char *id = crm_element_value(result, data->field);
    const char *name = pcmk__s(uname, id);

    /* Filter out the local node */
    if (pcmk__str_eq(name, data->local_node, pcmk__str_null_matches)) {
        return;
    }

    /* Filter out nodes that aren't pingable, but warn the user */
    if (!host_reachable(data->out, name)) {
        data->out->info(data->out, "Node %s is down - you'll need to update it"
                        "with `cibsecret sync` later", name);
        return;
    }

    data->nodes = g_list_append(data->nodes, g_strdup(name));
}

static GList *
get_live_peers(pcmk__output_t *out)
{
    int rc = pcmk_rc_ok;
    char *local_name = NULL;
    xmlNode *xml_node = NULL;
    GList *retval = NULL;

    struct node_data nd = {
        .nodes = NULL
    };

    /* Get the local node name. */
    rc = pcmk__query_node_name(out, 0, &local_name, 0);
    if (rc != pcmk_rc_ok) {
        out->err(out, "Could not get local node name");
        goto done;
    }

    nd.local_node = local_name;
    nd.out = out;

    /* Get a list of all node names, filtering out the local node as well
     * as those that don't respond to pings.
     */
    rc = cib__signon_query(out, NULL, &xml_node);
    if (rc != pcmk_rc_ok) {
        out->err(out, "Could not get list of cluster nodes");
        goto done;
    }

    nd.field = PCMK_XA_ID;
    pcmk__xpath_foreach_result(xml_node->doc, PCMK__XP_MEMBER_NODE_CONFIG,
                               node_iter_helper, &nd);
    nd.field = PCMK_XA_VALUE;
    pcmk__xpath_foreach_result(xml_node->doc, PCMK__XP_GUEST_NODE_CONFIG,
                               node_iter_helper, &nd);
    nd.field = PCMK_XA_ID;
    pcmk__xpath_foreach_result(xml_node->doc, PCMK__XP_REMOTE_NODE_CONFIG,
                               node_iter_helper, &nd);

done:
    free(local_name);
    free(xml_node);

    retval = g_list_copy(nd.nodes);
    g_list_free(nd.nodes);
    return retval;
}

static int
sync_one_file(pcmk__output_t *out, rsh_fn_t rsh_fn, rcp_fn_t rcp_fn,
              const char *path)
{
    int rc = pcmk_rc_ok;
    gchar *dirname = NULL;
    GList *peers = get_live_peers(out);
    GString *peer_str = NULL;
    char *cmdline = NULL;

    if (peers == NULL) {
        return ENOTCONN;
    }

    peer_str = g_string_sized_new(64);
    for (GList *node = peers; node != NULL; node = node->next) {
        pcmk__add_separated_word(&peer_str, 64, node->data, " ");
    }

    if (pcmk__str_eq(remainder[1], "delete", pcmk__str_none)) {
        out->info(out, "Deleting %s from %s ...", path, peer_str->str);
    } else {
        out->info(out, "Syncing %s to %s ...", path, peer_str->str);
    }

    dirname = g_path_get_dirname(path);

    cmdline = crm_strdup_printf("mkdir -p %s", dirname);
    rc = rsh_fn(out, peers, cmdline);
    if (rc != pcmk_rc_ok) {
        goto done;
    }

    if (g_file_test(path, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR)) {
        char *sign_path = NULL;

        rc = rcp_fn(out, peers, dirname, path);
        if (rc != pcmk_rc_ok) {
            goto done;
        }

        sign_path = crm_strdup_printf("%s.sign", path);
        rc = rcp_fn(out, peers, dirname, sign_path);
        free(sign_path);

        if (rc != pcmk_rc_ok) {
            goto done;
        }
    } else {
        free(cmdline);
        cmdline = crm_strdup_printf("rm -f %s %s.sign", path, path);
        rc = rsh_fn(out, peers, cmdline);

        if (rc != pcmk_rc_ok) {
            goto done;
        }
    }

done:
    free(cmdline);
    g_free(dirname);
    g_string_free(peer_str, TRUE);
    g_list_free_full(peers, g_free);
    return pcmk_rc_ok;
}

static int
check_cib_rsc(pcmk__output_t *out, const char *rsc)
{
    int rc = pcmk_rc_ok;
    char *cmdline = NULL;

    if (no_cib) {
        return true;
    }

    cmdline = crm_strdup_printf("crm_resource -r %s -W", rsc);
    rc = run_cmdline(out, cmdline, NULL);

    free(cmdline);
    return rc;
}

static bool
is_secret(const char *s)
{
    if (no_cib) {
        /* Assume that the secret is in the CIB if we can't connect */
        return true;
    }

    return pcmk__str_eq(s, LRM_MAGIC, pcmk__str_none);
}

static char *
get_cib_param(pcmk__output_t *out, const char *rsc, const char *param)
{
    int rc = pcmk_rc_ok;
    char *cmdline = NULL;
    char *standard_out = NULL;
    char *retval = NULL;
    char *xpath = NULL;
    xmlNode *xml = NULL;
    xmlNode *node = NULL;
    xmlChar *content = NULL;

    if (no_cib) {
        return NULL;
    }

    cmdline = crm_strdup_printf("crm_resource -r %s -g %s --output-as=xml", rsc, param);
    rc = run_cmdline(out, cmdline, &standard_out);

    if (rc != pcmk_rc_ok) {
        goto done;
    }

    xml = pcmk__xml_parse(standard_out);

    if (xml == NULL) {
        goto done;
    }

    xpath = crm_strdup_printf("//item[@name='%s']", param);
    node = pcmk__xpath_find_one(xml->doc, xpath, LOG_DEBUG);

    if (node == NULL) {
        goto done;
    }

    content = xmlNodeGetContent(node);

    if (content != NULL) {
        retval = strdup((char *) content);
        xmlFree(content);
    }

done:
    free(cmdline);
    free(standard_out);
    free(xpath);
    pcmk__xml_free(xml);
    return retval;
}

static int
remove_cib_param(pcmk__output_t *out, const char *rsc, const char *param)
{
    int rc = pcmk_rc_ok;
    char *cmdline = NULL;

    if (no_cib) {
        return rc;
    }

    cmdline = crm_strdup_printf("crm_resource -r %s -d %s", rsc, param);
    rc = run_cmdline(out, cmdline, NULL);
    free(cmdline);
    return rc;
}

static int
set_cib_param(pcmk__output_t *out, const char *rsc, const char *param,
              const char *value)
{
    int rc = pcmk_rc_ok;
    char *cmdline = NULL;

    if (no_cib) {
        return rc;
    }

    cmdline = crm_strdup_printf("crm_resource -r %s -p %s -v %s", rsc, param,
                                value);
    rc = run_cmdline(out, cmdline, NULL);
    free(cmdline);
    return rc;
}

static char *
local_files_get(const char *rsc, const char *param)
{
    char *lf_file = NULL;
    gchar *contents = NULL;

    lf_file = crm_strdup_printf(PCMK__CIB_SECRETS_DIR "/%s/%s", rsc, param);
    if (g_file_get_contents(lf_file, &contents, NULL, NULL)) {
        char *retval = strdup(contents);

        g_free(contents);
        free(lf_file);
        return retval;
    }

    free(lf_file);
    return NULL;
}

static char *
local_files_getsum(const char *rsc, const char *param)
{
    char *lf_file = NULL;
    gchar *contents = NULL;

    lf_file = crm_strdup_printf(PCMK__CIB_SECRETS_DIR "/%s/%s.sign", rsc, param);
    if (g_file_get_contents(lf_file, &contents, NULL, NULL)) {
        char *retval = strdup(contents);

        g_free(contents);
        free(lf_file);
        return retval;
    }

    free(lf_file);
    return NULL;
}

static int
local_files_remove(pcmk__output_t *out, rsh_fn_t rsh_fn, rcp_fn_t rcp_fn,
                   const char *rsc, const char *param)
{
    int rc = pcmk_rc_ok;
    char *lf_file = NULL;
    char *cmdline = NULL;

    lf_file = crm_strdup_printf(PCMK__CIB_SECRETS_DIR "/%s/%s", rsc, param);

    cmdline = crm_strdup_printf("rm -f %s %s.sign", lf_file, lf_file);
    rc = run_cmdline(out, cmdline, NULL);

    if (rc != pcmk_rc_ok) {
        goto done;
    }

    rc = sync_one_file(out, rsh_fn, rcp_fn, lf_file);

done:
    free(lf_file);
    free(cmdline);
    return rc;
}

static int
local_files_set(pcmk__output_t *out, rsh_fn_t rsh_fn, rcp_fn_t rcp_fn,
                const char *rsc, const char *param, const char *value)
{
    char *lf_dir = NULL;
    char *lf_file = NULL;
    char *sign_file = NULL;
    char *calc_sum = NULL;
    int rc = pcmk_rc_ok;

    lf_dir = crm_strdup_printf(PCMK__CIB_SECRETS_DIR "/%s", rsc);

    if (g_mkdir_with_parents(lf_dir, 0700) != 0) {
        rc = errno;
        goto done;
    }

    lf_file = crm_strdup_printf("%s/%s", lf_dir, param);
    if (!g_file_set_contents(lf_file, value, -1, NULL)) {
        rc = EIO;
        goto done;
    }

    sign_file = crm_strdup_printf("%s/%s.sign", lf_dir, param);
    calc_sum = crm_md5sum(value);
    if (!g_file_set_contents(sign_file, calc_sum, -1, NULL)) {
        rc = EIO;
        goto done;
    }

    rc = sync_one_file(out, rsh_fn, rcp_fn, lf_file);

done:
    free(calc_sum);
    free(sign_file);
    free(lf_dir);
    free(lf_file);
    return rc;
}

static int
subcommand_check(pcmk__output_t *out, rsh_fn_t rsh_fn, rcp_fn_t rcp_fn,
                 crm_exit_t *exit_code)
{
    int rc = pcmk_rc_ok;
    const char *rsc = remainder[1];
    const char *param = remainder[2];
    char *value = NULL;
    char *calc_sum = NULL;
    char *local_sum = NULL;
    char *local_value = NULL;

    if (check_cib_rsc(out, rsc) != pcmk_rc_ok) {
        *exit_code = CRM_EX_NOSUCH;
        rc = ENODEV;
        goto done;
    }

    value = get_cib_param(out, rsc, param);
    if (value == NULL || !is_secret(value)) {
        out->err(out, "Resource %s parameter %s not set as secret, nothing to check",
                 rsc, param);
        *exit_code = CRM_EX_CONFIG;
        rc = EINVAL;
        goto done;
    }

    local_sum = local_files_getsum(rsc, param);
    if (local_sum == NULL) {
        out->err(out, "No checksum for resource %s parameter %s", rsc, param);
        *exit_code = CRM_EX_OSFILE;
        rc = ENOENT;
        goto done;
    }

    local_value = local_files_get(rsc, param);
    if (local_value != NULL) {
        calc_sum = crm_md5sum(local_value);
    }

    if (local_value == NULL || !pcmk__str_eq(calc_sum, local_sum, pcmk__str_none)) {
        out->err(out, "Checksum mismatch for resource %s parameter %s", rsc, param);
        *exit_code = CRM_EX_DIGEST;
        rc = EINVAL;
        goto done;
    }

done:
    free(local_sum);
    free(local_value);
    free(calc_sum);
    free(value);
    return rc;
}

static int
subcommand_delete(pcmk__output_t *out, rsh_fn_t rsh_fn, rcp_fn_t rcp_fn,
                  crm_exit_t *exit_code)
{
    int rc = pcmk_rc_ok;
    const char *rsc = remainder[1];
    const char *param = remainder[2];

    if (check_cib_rsc(out, rsc) != pcmk_rc_ok) {
        *exit_code = CRM_EX_NOSUCH;
        rc = ENODEV;
        goto done;
    }

    rc = local_files_remove(out, rsh_fn, rcp_fn, rsc, param);
    if (rc != pcmk_rc_ok) {
        goto done;
    }

    rc = remove_cib_param(out, rsc, param);

done:
    return rc;
}

static int
subcommand_get(pcmk__output_t *out, rsh_fn_t rsh_fn, rcp_fn_t rcp_fn,
               crm_exit_t *exit_code)
{
    int rc = subcommand_check(out, rsh_fn, rcp_fn, exit_code);
    char *value = NULL;
    const char *rsc = remainder[1];
    const char *param = remainder[2];

    if (rc != pcmk_rc_ok) {
        return rc;
    }

    /* value should not be NULL since we ran subcommand_check first. */
    value = local_files_get(rsc, param);
    out->info(out, "%s\n", value);

    free(value);
    return pcmk_rc_ok;
}

static int
subcommand_set(pcmk__output_t *out, rsh_fn_t rsh_fn, rcp_fn_t rcp_fn,
               crm_exit_t *exit_code)
{
    int rc = pcmk_rc_ok;
    const char *rsc = remainder[1];
    const char *param = remainder[2];
    const char *value = remainder[3];
    char *current = NULL;

    if (check_cib_rsc(out, rsc) != pcmk_rc_ok) {
        *exit_code = CRM_EX_NOSUCH;
        rc = ENODEV;
        goto done;
    }

    current = get_cib_param(out, rsc, param);
    if (!pcmk__str_empty(current) && !pcmk__str_any_of(current, LRM_MAGIC, value, NULL)) {
        out->err(out, "CIB value <%s> different for %s rsc parameter %s; please "
                 "delete it first", current, rsc, param);
        *exit_code = CRM_EX_CONFIG;
        rc = EINVAL;
        goto done;
    }

    rc = local_files_set(out, rsh_fn, rcp_fn, rsc, param, value);
    if (rc != pcmk_rc_ok) {
        goto done;
    }

    rc = set_cib_param(out, rsc, param, LRM_MAGIC);

done:
    free(current);
    return rc;
}

static int
subcommand_stash(pcmk__output_t *out, rsh_fn_t rsh_fn, rcp_fn_t rcp_fn,
                 crm_exit_t *exit_code)
{
    int rc = pcmk_rc_ok;
    const char *rsc = remainder[1];
    const char *param = remainder[2];
    char *value = NULL;

    if (check_cib_rsc(out, rsc) != pcmk_rc_ok) {
        *exit_code = CRM_EX_NOSUCH;
        rc = ENODEV;
        goto done;
    }

    value = get_cib_param(out, rsc, param);
    if (value == NULL || is_secret(value)) {
        if (value == NULL) {
            out->err(out, "Nothing to stash for resource %s parameter %s", rsc,
                     param);
        } else {
            out->err(out, "Resource %s parameter %s already set as secret", rsc,
                     param);
        }

        *exit_code = CRM_EX_CONFIG;
        rc = EINVAL;
        goto done;
    }

    remainder = g_realloc(remainder, sizeof(gchar *) * 5);
    remainder[3] = g_strdup(value);
    remainder[4] = NULL;

    rc = subcommand_set(out, rsh_fn, rcp_fn, exit_code);

done:
    free(value);
    return rc;
}

/* The shell-based cibsecret.in had this comment for the sync subcommand:
 *
 * # TODO: this procedure should be replaced with csync2
 * # provided that csync2 has already been configured
 */
static int
subcommand_sync(pcmk__output_t *out, rsh_fn_t rsh_fn, rcp_fn_t rcp_fn,
                crm_exit_t *exit_code)
{
    int rc = pcmk_rc_ok;
    GString *peer_str = NULL;
    gchar *dirname = NULL;
    char *cmdline = NULL;
    GList *peers = get_live_peers(out);

    if (peers == NULL) {
        /* pcmk_rc_node_unknown / CRM_EX_NOHOST might be better here. */
        *exit_code = CRM_EX_UNAVAILABLE;
        return ENOTCONN;
    }

    peer_str = g_string_sized_new(64);
    for (GList *node = peers; node != NULL; node = node->next) {
        pcmk__add_separated_word(&peer_str, 64, node->data, " ");
    }

    out->info(out, "Syncing %s to %s ...", PCMK__CIB_SECRETS_DIR, peer_str->str);
    g_string_free(peer_str, TRUE);

    dirname = g_path_get_dirname(PCMK__CIB_SECRETS_DIR);

    rc = rsh_fn(out, peers, "rm -rf " PCMK__CIB_SECRETS_DIR);
    if (rc != pcmk_rc_ok) {
        *exit_code = CRM_EX_ERROR;
        goto done;
    }

    cmdline = crm_strdup_printf("mkdir -p %s", dirname);
    rc = rsh_fn(out, peers, cmdline);
    free(cmdline);

    if (rc != pcmk_rc_ok) {
        *exit_code = CRM_EX_ERROR;
        goto done;
    }

    rc = rcp_fn(out, peers, dirname, PCMK__CIB_SECRETS_DIR);

    if (rc != pcmk_rc_ok) {
        *exit_code = CRM_EX_ERROR;
    }

done:
    g_list_free_full(peers, g_free);
    g_free(dirname);
    return rc;
}

static int
subcommand_unstash(pcmk__output_t *out, rsh_fn_t rsh_fn, rcp_fn_t rcp_fn,
                   crm_exit_t *exit_code)
{
    int rc = pcmk_rc_ok;
    const char *rsc = remainder[1];
    const char *param = remainder[2];
    char *local_value = NULL;
    char *cib_value = NULL;

    local_value = local_files_get(rsc, param);
    if (local_value == NULL) {
        out->err(out, "Nothing to unstash for resource %s parameter %s",
                 rsc, param);
        *exit_code = CRM_EX_NOSUCH;
        rc = EINVAL;
        goto done;
    }

    if (check_cib_rsc(out, rsc) != pcmk_rc_ok) {
        *exit_code = CRM_EX_NOSUCH;
        rc = ENODEV;
        goto done;
    }

    cib_value = get_cib_param(out, rsc, param);
    if (!is_secret(cib_value)) {
        out->info(out, "Resource %s parameter %s is not set as secret, but we "
                  "have a local value so proceeding anyway", rsc, param);
    }

    rc = local_files_remove(out, rsh_fn, rcp_fn, rsc, param);
    if (rc != pcmk_rc_ok) {
        goto done;
    }

    rc = set_cib_param(out, rsc, param, local_value);

done:
    free(cib_value);
    free(local_value);
    return rc;
}

static struct subcommand_entry subcommand_table[] = {
    { "check", 2, "check <resource-id> <resource-parameter>", false,
      subcommand_check },
    { "delete", 2, "delete <resource-id> <resource-parameter>", false,
      subcommand_delete },
    { "get", 2, "get <resource-id> <resource-parameter>", false,
      subcommand_get },
    { "set", 3, "set <resource-id> <resource-parameter> <value>", true,
      subcommand_set },
    { "stash", 2, "stash <resource-id> <resource-parameter>", true,
      subcommand_stash },
    { "sync", 0, "sync", false, subcommand_sync },
    { "unstash", 2, "unstash <resource-id> <resource-parameter>", true,
      subcommand_unstash },
    { NULL },
};

static int
check_environment(pcmk__output_t *out, rsh_fn_t *rsh_fn, rcp_fn_t *rcp_fn,
                  GError **error)
{
    gchar *path = NULL;

    path = g_find_program_in_path("pssh");
    if (path != NULL) {
        g_free(path);
        *rsh_fn = pssh;
        *rcp_fn = pscp;
        return pcmk_rc_ok;
    }

    path = g_find_program_in_path("pdsh");
    if (path != NULL) {
        g_free(path);
        *rsh_fn = pdsh;
        *rcp_fn = pdcp;
        return pcmk_rc_ok;
    }

    path = g_find_program_in_path("ssh");
    if (path != NULL) {
        g_free(path);
        *rsh_fn = ssh;
        *rcp_fn = scp;
        return pcmk_rc_ok;
    }

    out->err(out, "Please install one of pssh, pdsh, or ssh");
    return pcmk_rc_error;
}

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
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
           "set <resource-id> <resource-parameter> [<value>]\n"
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

    context = pcmk__build_arg_context(args, "text (default)", group,
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
    rsh_fn_t rsh_fn;
    rcp_fn_t rcp_fn;

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
    if (remainder == NULL || g_strv_length(remainder) == 0) {
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

    /* Check that we have the tools necessary to manage secrets */
    if (check_environment(out, &rsh_fn, &rcp_fn, &error) != pcmk_rc_ok) {
        exit_code = CRM_EX_NOT_INSTALLED;
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

    cmd.handler(out, rsh_fn, rcp_fn, &exit_code);

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
