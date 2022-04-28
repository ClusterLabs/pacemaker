/*
 * Copyright 2019-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/cib.h>
#include <crm/cib/internal.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/output_internal.h>
#include <crm/common/iso8601.h>
#include <crm/msg_xml.h>
#include <crm/pengine/rules_internal.h>
#include <crm/pengine/status.h>
#include <pacemaker-internal.h>

#include <sys/stat.h>

#define SUMMARY "evaluate rules from the Pacemaker configuration"

GError *error = NULL;

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

enum crm_rule_mode {
    crm_rule_mode_none,
    crm_rule_mode_check
};

struct {
    char *date;
    char *input_xml;
    enum crm_rule_mode mode;
    gchar **rules;
} options = {
    .mode = crm_rule_mode_none
};

static int crm_rule_check(pcmk__output_t *out, pe_working_set_t *data_set,
                          const char *rule_id, crm_time_t *effective_date);

static gboolean mode_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);

static GOptionEntry mode_entries[] = {
    { "check", 'c', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, mode_cb,
      "Check whether a rule is in effect",
      NULL },

    { NULL }
};

static GOptionEntry data_entries[] = {
    { "xml-text", 'X', 0, G_OPTION_ARG_STRING, &options.input_xml,
      "Use argument for XML (or stdin if '-')",
      NULL },

    { NULL }
};

static GOptionEntry addl_entries[] = {
    { "date", 'd', 0, G_OPTION_ARG_STRING, &options.date,
      "Whether the rule is in effect on a given date",
      NULL },
    { "rule", 'r', 0, G_OPTION_ARG_STRING_ARRAY, &options.rules,
      "The ID of the rule to check (may be specified multiple times)",
      NULL },

    { NULL }
};

static gboolean
mode_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (strcmp(option_name, "c")) {
        options.mode = crm_rule_mode_check;
    }

    return TRUE;
}

/*!
 * \internal
 * \brief Evaluate a date expression for a specific time
 *
 * \param[in]  time_expr    date_expression XML
 * \param[in]  now          Time for which to evaluate expression
 * \param[out] next_change  If not NULL, set to when evaluation will change
 *
 * \return Standard Pacemaker return code
 */
static int
eval_date_expression(xmlNode *expr, crm_time_t *now, crm_time_t *next_change)
{
    pe_rule_eval_data_t rule_data = {
        .node_hash = NULL,
        .role = RSC_ROLE_UNKNOWN,
        .now = now,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    return pe__eval_date_expr(expr, &rule_data, next_change);
}

PCMK__OUTPUT_ARGS("rule-check", "const char *", "int")
static int
rule_check_default(pcmk__output_t *out, va_list args)
{
    const char *rule_id = va_arg(args, const char *);
    int result = va_arg(args, int);

    if (result == pcmk_rc_within_range) {
        out->info(out, "Rule %s is still in effect", rule_id);
    } else if (result == pcmk_rc_ok) {
        out->info(out, "Rule %s satisfies conditions", rule_id);
    } else if (result == pcmk_rc_after_range) {
        out->info(out, "Rule %s is expired", rule_id);
    } else if (result == pcmk_rc_before_range) {
        out->info(out, "Rule %s has not yet taken effect", rule_id);
    } else if (result == pcmk_rc_op_unsatisfied) {
        out->info(out, "Rule %s does not satisfy conditions", rule_id);
    } else {
        out->info(out, "Could not determine whether rule %s is expired", rule_id);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("rule-check", "const char *", "int")
static int
rule_check_xml(pcmk__output_t *out, va_list args)
{
    const char *rule_id = va_arg(args, const char *);
    int result = va_arg(args, int);

    char *rc_str = pcmk__itoa(pcmk_rc2exitc(result));

    pcmk__output_create_xml_node(out, "rule-check",
                                 "rule-id", rule_id,
                                 "rc", rc_str,
                                 NULL);

    free(rc_str);

    return pcmk_rc_ok;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "rule-check", "default", rule_check_default },
    { "rule-check", "xml", rule_check_xml },

    { NULL, NULL, NULL }
};

static int
crm_rule_check(pcmk__output_t *out, pe_working_set_t *data_set, const char *rule_id,
               crm_time_t *effective_date)
{
    xmlNode *cib_constraints = NULL;
    xmlNode *match = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    char *xpath = NULL;
    int rc = pcmk_rc_ok;
    int max = 0;

    /* Rules are under the constraints node in the XML, so first find that. */
    cib_constraints = pcmk_find_cib_element(data_set->input,
                                            XML_CIB_TAG_CONSTRAINTS);

    /* Get all rules matching the given ID which are also simple enough for us to check.
     * For the moment, these rules must only have a single date_expression child and:
     * - Do not have a date_spec operation, or
     * - Have a date_spec operation that contains years= but does not contain moon=.
     *
     * We do this in steps to provide better error messages.  First, check that there's
     * any rule with the given ID.
     */
    xpath = crm_strdup_printf("//rule[@id='%s']", rule_id);
    xpathObj = xpath_search(cib_constraints, xpath);
    max = numXpathResults(xpathObj);

    if (max == 0) {
        rc = ENXIO;
        g_set_error(&error, PCMK__RC_ERROR, rc, "No rule found with ID=%s", rule_id);
        goto done;
    } else if (max > 1) {
        rc = ENXIO;
        g_set_error(&error, PCMK__RC_ERROR, rc, "More than one rule with ID=%s found", rule_id);
        goto done;
    }

    free(xpath);
    freeXpathObject(xpathObj);

    /* Next, make sure it has exactly one date_expression. */
    xpath = crm_strdup_printf("//rule[@id='%s']//date_expression", rule_id);
    xpathObj = xpath_search(cib_constraints, xpath);
    max = numXpathResults(xpathObj);

    if (max != 1) {
        rc = EOPNOTSUPP;
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "Can't check rule %s because it does not have exactly one date_expression", rule_id);
        goto done;
    }

    free(xpath);
    freeXpathObject(xpathObj);

    /* Then, check that it's something we actually support. */
    xpath = crm_strdup_printf("//rule[@id='%s']//date_expression[@operation!='date_spec']", rule_id);
    xpathObj = xpath_search(cib_constraints, xpath);
    max = numXpathResults(xpathObj);

    if (max == 0) {
        free(xpath);
        freeXpathObject(xpathObj);

        xpath = crm_strdup_printf("//rule[@id='%s']//date_expression[@operation='date_spec' and date_spec/@years and not(date_spec/@moon)]",
                                  rule_id);
        xpathObj = xpath_search(cib_constraints, xpath);
        max = numXpathResults(xpathObj);

        if (max == 0) {
            rc = ENXIO;
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        "Rule either must not use date_spec, or use date_spec with years= but not moon=");
            goto done;
        }
    }

    match = getXpathResult(xpathObj, 0);

    /* We should have ensured both of these pass with the xpath query above, but
     * double checking can't hurt.
     */
    CRM_ASSERT(match != NULL);
    CRM_ASSERT(find_expression_type(match) == time_expr);

    rc = eval_date_expression(match, effective_date, NULL);
    out->message(out, "rule-check", rule_id, rc);

done:
    free(xpath);
    freeXpathObject(xpathObj);
    return rc;
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);

    pcmk__add_arg_group(context, "modes", "Modes (mutually exclusive):",
                        "Show modes of operation", mode_entries);
    pcmk__add_arg_group(context, "data", "Data:",
                        "Show data options", data_entries);
    pcmk__add_arg_group(context, "additional", "Additional Options:",
                        "Show additional options", addl_entries);
    return context;
}

int
main(int argc, char **argv)
{
    pe_working_set_t *data_set = NULL;

    crm_time_t *rule_date = NULL;
    xmlNode *input = NULL;

    int rc = pcmk_rc_ok;
    crm_exit_t exit_code = CRM_EX_OK;

    pcmk__output_t *out = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    GOptionContext *context = build_arg_context(args, &output_group);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "drX");

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("crm_rule", args->verbosity);

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    pcmk__register_messages(out, fmt_functions);

    if (args->version) {
        out->version(out, false);
        goto done;
    }

    /* Check command line arguments before opening a connection to
     * the CIB manager or doing anything else important.
     */
    switch(options.mode) {
        case crm_rule_mode_check:
            if (options.rules == NULL) {
                exit_code = CRM_EX_USAGE;
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "--check requires use of --rule=");
                goto done;
            }

            break;

        default:
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "No mode operation given");
            goto done;
            break;
    }

    /* Set up some defaults. */
    rule_date = crm_time_new(options.date);
    if (rule_date == NULL) {
        exit_code = CRM_EX_DATAERR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "No --date given and can't determine current date");
        goto done;
    }

    /* Where does the XML come from?  If one of various command line options were
     * given, use those.  Otherwise, connect to the CIB and use that.
     */
    if (pcmk__str_eq(options.input_xml, "-", pcmk__str_casei)) {
        input = stdin2xml();

        if (input == NULL) {
            exit_code = CRM_EX_DATAERR;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Couldn't parse input from STDIN\n");
            goto done;
        }
    } else if (options.input_xml != NULL) {
        input = string2xml(options.input_xml);

        if (input == NULL) {
            exit_code = CRM_EX_DATAERR;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Couldn't parse input string: %s\n", options.input_xml);
            goto done;
        }
    } else {
        rc = cib__signon_query(NULL, &input);

        if (rc != pcmk_rc_ok) {
            exit_code = pcmk_rc2exitc(rc);
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "CIB query failed: %s", pcmk_rc_str(rc));
            goto done;
        }
    }

    /* Populate the working set instance */
    data_set = pe_new_working_set();
    if (data_set == NULL) {
        exit_code = pcmk_rc2exitc(ENOMEM);
        goto done;
    }
    pe__set_working_set_flags(data_set, pe_flag_no_counts|pe_flag_no_compat);

    data_set->input = input;
    data_set->now = rule_date;

    /* Unpack everything. */
    cluster_status(data_set);

    /* Now do whichever operation mode was asked for.  There's only one at the
     * moment so this looks a little silly, but I expect there will be more
     * modes in the future.
     */
    switch(options.mode) {
        case crm_rule_mode_check:
            for (char **s = options.rules; *s != NULL; s++) {
                int last_rc = crm_rule_check(out, data_set, *s, rule_date);

                if (last_rc != pcmk_rc_ok) {
                    rc = last_rc;
                }
            }

            exit_code = pcmk_rc2exitc(rc);
            break;

        default:
            break;
    }

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);
    pe_free_working_set(data_set);

    pcmk__output_and_clear_error(error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }

    return crm_exit(exit_code);
}
