/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <crm_internal.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>

void
pcmk__cli_help(char cmd)
{
    if (cmd == 'v' || cmd == '$') {
        printf("Pacemaker %s\n", PACEMAKER_VERSION);
        printf("Written by Andrew Beekhof and "
               "the Pacemaker project contributors\n");

    } else if (cmd == '!') {
        printf("Pacemaker %s (Build: %s): %s\n", PACEMAKER_VERSION, BUILD_VERSION, CRM_FEATURES);
    }

    crm_exit(CRM_EX_OK);
    while(1); // above does not return
}


/*
 * Environment variable option handling
 */

/*!
 * \internal
 * \brief Get the value of a Pacemaker environment variable option
 *
 * If an environment variable option is set, with either a PCMK_ or (for
 * backward compatibility) HA_ prefix, log and return the value.
 *
 * \param[in] option  Environment variable name (without prefix)
 *
 * \return Value of environment variable option, or NULL in case of
 *         option name too long or value not found
 */
const char *
pcmk__env_option(const char *option)
{
    const char *const prefixes[] = {"PCMK_", "HA_"};
    char env_name[NAME_MAX];
    const char *value = NULL;

    CRM_CHECK(!pcmk__str_empty(option), return NULL);

    for (int i = 0; i < PCMK__NELEM(prefixes); i++) {
        int rv = snprintf(env_name, NAME_MAX, "%s%s", prefixes[i], option);

        if (rv < 0) {
            crm_err("Failed to write %s%s to buffer: %s", prefixes[i], option,
                    strerror(errno));
            return NULL;
        }

        if (rv >= sizeof(env_name)) {
            crm_trace("\"%s%s\" is too long", prefixes[i], option);
            continue;
        }

        value = getenv(env_name);
        if (value != NULL) {
            crm_trace("Found %s = %s", env_name, value);
            return value;
        }
    }

    crm_trace("Nothing found for %s", option);
    return NULL;
}

/*!
 * \brief Set or unset a Pacemaker environment variable option
 *
 * Set an environment variable option with a \c "PCMK_" prefix and optionally
 * an \c "HA_" prefix for backward compatibility.
 *
 * \param[in] option  Environment variable name (without prefix)
 * \param[in] value   New value (or NULL to unset)
 * \param[in] compat  If false and \p value is not \c NULL, set only
 *                    \c "PCMK_<option>"; otherwise, set (or unset) both
 *                    \c "PCMK_<option>" and \c "HA_<option>"
 *
 * \note \p compat is ignored when \p value is \c NULL. A \c NULL \p value
 *       means we're unsetting \p option. \c pcmk__get_env_option() checks for
 *       both prefixes, so we want to clear them both.
 */
void
pcmk__set_env_option(const char *option, const char *value, bool compat)
{
    // @COMPAT Drop support for "HA_" options eventually
    const char *const prefixes[] = {"PCMK_", "HA_"};
    char env_name[NAME_MAX];

    CRM_CHECK(!pcmk__str_empty(option) && (strchr(option, '=') == NULL),
              return);

    for (int i = 0; i < PCMK__NELEM(prefixes); i++) {
        int rv = snprintf(env_name, NAME_MAX, "%s%s", prefixes[i], option);

        if (rv < 0) {
            crm_err("Failed to write %s%s to buffer: %s", prefixes[i], option,
                    strerror(errno));
            return;
        }

        if (rv >= sizeof(env_name)) {
            crm_trace("\"%s%s\" is too long", prefixes[i], option);
            continue;
        }

        if (value != NULL) {
            crm_trace("Setting %s to %s", env_name, value);
            rv = setenv(env_name, value, 1);
        } else {
            crm_trace("Unsetting %s", env_name);
            rv = unsetenv(env_name);
        }

        if (rv < 0) {
            crm_err("Failed to %sset %s: %s", (value != NULL)? "" : "un",
                    env_name, strerror(errno));
        }

        if (!compat && (value != NULL)) {
            // For set, don't proceed to HA_<option> unless compat is enabled
            break;
        }
    }
}

/*!
 * \internal
 * \brief Check whether Pacemaker environment variable option is enabled
 *
 * Given a Pacemaker environment variable option that can either be boolean
 * or a list of daemon names, return true if the option is enabled for a given
 * daemon.
 *
 * \param[in] daemon   Daemon name (can be NULL)
 * \param[in] option   Pacemaker environment variable name
 *
 * \return true if variable is enabled for daemon, otherwise false
 */
bool
pcmk__env_option_enabled(const char *daemon, const char *option)
{
    const char *value = pcmk__env_option(option);

    return (value != NULL)
        && (crm_is_true(value)
            || ((daemon != NULL) && (strstr(value, daemon) != NULL)));
}


/*
 * Cluster option handling
 */

/*!
 * \internal
 * \brief Check whether a string represents a valid interval specification
 *
 * \param[in] value  String to validate
 *
 * \return \c true if \p value is a valid interval specification, or \c false
 *         otherwise
 */
bool
pcmk__valid_interval_spec(const char *value)
{
    return pcmk_parse_interval_spec(value, NULL) == pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Check whether a string represents a valid boolean value
 *
 * \param[in] value  String to validate
 *
 * \return \c true if \p value is a valid boolean value, or \c false otherwise
 */
bool
pcmk__valid_boolean(const char *value)
{
    return crm_str_to_boolean(value, NULL) == 1;
}

/*!
 * \internal
 * \brief Check whether a string represents a valid integer
 *
 * Valid values include \c INFINITY, \c -INFINITY, and all 64-bit integers.
 *
 * \param[in] value  String to validate
 *
 * \return \c true if \p value is a valid integer, or \c false otherwise
 */
bool
pcmk__valid_int(const char *value)
{
    return (value != NULL)
           && (pcmk_str_is_infinity(value)
               || pcmk_str_is_minus_infinity(value)
               || (pcmk__scan_ll(value, NULL, 0LL) == pcmk_rc_ok));
}

/*!
 * \internal
 * \brief Check whether a string represents a valid positive integer
 *
 * Valid values include \c INFINITY and all 64-bit positive integers.
 *
 * \param[in] value  String to validate
 *
 * \return \c true if \p value is a valid positive integer, or \c false
 *         otherwise
 */
bool
pcmk__valid_positive_int(const char *value)
{
    long long num = 0LL;

    return pcmk_str_is_infinity(value)
           || ((pcmk__scan_ll(value, &num, 0LL) == pcmk_rc_ok)
               && (num > 0));
}

/*!
 * \internal
 * \brief Check whether a string represents a valid
 *        \c PCMK__OPT_NO_QUORUM_POLICY value
 *
 * \param[in] value  String to validate
 *
 * \return \c true if \p value is a valid \c PCMK__OPT_NO_QUORUM_POLICY value,
 *         or \c false otherwise
 */
bool
pcmk__valid_no_quorum_policy(const char *value)
{
    return pcmk__strcase_any_of(value,
                                "stop", "freeze", "ignore", "demote", "suicide",
                                NULL);
}

/*!
 * \internal
 * \brief Check whether a string represents a valid percentage
 *
 * Valid values include long integers, with an optional trailing string
 * beginning with '%'.
 *
 * \param[in] value  String to validate
 *
 * \return \c true if \p value is a valid percentage value, or \c false
 *         otherwise
 */
bool
pcmk__valid_percentage(const char *value)
{
    char *end = NULL;
    float number = strtof(value, &end);

    return ((end == NULL) || (end[0] == '%')) && (number >= 0);
}

/*!
 * \internal
 * \brief Check whether a string represents a valid script
 *
 * Valid values include \c /dev/null and paths of executable regular files
 *
 * \param[in] value  String to validate
 *
 * \return \c true if \p value is a valid script, or \c false otherwise
 */
bool
pcmk__valid_script(const char *value)
{
    struct stat st;

    if (pcmk__str_eq(value, "/dev/null", pcmk__str_none)) {
        return true;
    }

    if (stat(value, &st) != 0) {
        crm_err("Script %s does not exist", value);
        return false;
    }

    if (S_ISREG(st.st_mode) == 0) {
        crm_err("Script %s is not a regular file", value);
        return false;
    }

    if ((st.st_mode & (S_IXUSR | S_IXGRP)) == 0) {
        crm_err("Script %s is not executable", value);
        return false;
    }

    return true;
}

/*!
 * \internal
 * \brief Check a table of configured options for a particular option
 *
 * \param[in,out] options    Name/value pairs for configured options
 * \param[in]     validate   If not NULL, validator function for option value
 * \param[in]     name       Option name to look for
 * \param[in]     old_name   Alternative option name to look for
 * \param[in]     def_value  Default to use if option not configured
 *
 * \return Option value (from supplied options table or default value)
 */
static const char *
cluster_option_value(GHashTable *options, bool (*validate)(const char *),
                     const char *name, const char *old_name,
                     const char *def_value)
{
    const char *value = NULL;
    char *new_value = NULL;

    CRM_ASSERT(name != NULL);

    if (options) {
        value = g_hash_table_lookup(options, name);

        if ((value == NULL) && old_name) {
            value = g_hash_table_lookup(options, old_name);
            if (value != NULL) {
                pcmk__config_warn("Support for legacy name '%s' for cluster "
                                  "option '%s' is deprecated and will be "
                                  "removed in a future release",
                                  old_name, name);

                // Inserting copy with current name ensures we only warn once
                new_value = strdup(value);
                g_hash_table_insert(options, strdup(name), new_value);
                value = new_value;
            }
        }

        if (value && validate && (validate(value) == FALSE)) {
            pcmk__config_err("Using default value for cluster option '%s' "
                             "because '%s' is invalid", name, value);
            value = NULL;
        }

        if (value) {
            return value;
        }
    }

    // No value found, use default
    value = def_value;

    if (value == NULL) {
        crm_trace("No value or default provided for cluster option '%s'",
                  name);
        return NULL;
    }

    if (validate) {
        CRM_CHECK(validate(value) != FALSE,
                  crm_err("Bug: default value for cluster option '%s' is invalid", name);
                  return NULL);
    }

    crm_trace("Using default value '%s' for cluster option '%s'",
              value, name);
    if (options) {
        new_value = strdup(value);
        g_hash_table_insert(options, strdup(name), new_value);
        value = new_value;
    }
    return value;
}

/*!
 * \internal
 * \brief Get the value of a cluster option
 *
 * \param[in,out] options      Name/value pairs for configured options
 * \param[in]     option_list  Possible cluster options
 * \param[in]     len          Length of \p option_list
 * \param[in]     name         (Primary) option name to look for
 *
 * \return Option value
 */
const char *
pcmk__cluster_option(GHashTable *options,
                     const pcmk__cluster_option_t *option_list,
                     int len, const char *name)
{
    const char *value = NULL;

    for (int lpc = 0; lpc < len; lpc++) {
        if (pcmk__str_eq(name, option_list[lpc].name, pcmk__str_casei)) {
            value = cluster_option_value(options, option_list[lpc].is_valid,
                                         option_list[lpc].name,
                                         option_list[lpc].alt_name,
                                         option_list[lpc].default_value);
            return value;
        }
    }
    CRM_CHECK(FALSE, crm_err("Bug: looking for unknown option '%s'", name));
    return NULL;
}

/*!
 * \internal
 * \brief Add a description element to a meta-data string
 *
 * \param[in,out] s       Meta-data string to add to
 * \param[in]     tag     Name of element to add (\c PCMK_XE_LONGDESC or
 *                        \c PCMK_XE_SHORTDESC)
 * \param[in]     desc    Textual description to add
 * \param[in]     values  If not \p NULL, the allowed values for the parameter
 * \param[in]     spaces  If not \p NULL, spaces to insert at the beginning of
 *                        each line
 */
static void
add_desc(GString *s, const char *tag, const char *desc, const char *values,
         const char *spaces)
{
    char *escaped_en = crm_xml_escape(desc);

    if (spaces != NULL) {
        g_string_append(s, spaces);
    }
    pcmk__g_strcat(s, "<", tag, " " PCMK_XA_LANG "=\"en\">", escaped_en, NULL);

    if (values != NULL) {
        // Append a period if desc doesn't end in "." or ".)"
        if (!pcmk__str_empty(escaped_en)
            && (s->str[s->len - 1] != '.')
            && ((s->str[s->len - 2] != '.') || (s->str[s->len - 1] != ')'))) {

            g_string_append_c(s, '.');
        }
        pcmk__g_strcat(s, " Allowed values: ", values, NULL);
        g_string_append_c(s, '.');
    }
    pcmk__g_strcat(s, "</", tag, ">\n", NULL);

#ifdef ENABLE_NLS
    {
        static const char *locale = NULL;

        char *localized = crm_xml_escape(_(desc));

        if (strcmp(escaped_en, localized) != 0) {
            if (locale == NULL) {
                locale = strtok(setlocale(LC_ALL, NULL), "_");
            }

            if (spaces != NULL) {
                g_string_append(s, spaces);
            }
            pcmk__g_strcat(s,
                           "<", tag, " " PCMK_XA_LANG "=\"", locale, "\">",
                           localized, NULL);

            if (values != NULL) {
                pcmk__g_strcat(s, _("  Allowed values: "), _(values), NULL);
            }
            pcmk__g_strcat(s, "</", tag, ">\n", NULL);
        }
        free(localized);
    }
#endif

    free(escaped_en);
}

gchar *
pcmk__format_option_metadata(const char *name, const char *desc_short,
                             const char *desc_long,
                             pcmk__cluster_option_t *option_list, int len)
{
    /* big enough to hold "pacemaker-schedulerd metadata" output */
    GString *s = g_string_sized_new(13000);

    pcmk__g_strcat(s,
                   "<?xml " PCMK_XA_VERSION "=\"1.0\"?>\n"
                   "<" PCMK_XE_RESOURCE_AGENT " "
                       PCMK_XA_NAME "=\"", name, "\" "
                       PCMK_XA_VERSION "=\"" PACEMAKER_VERSION "\">\n"

                   "  <" PCMK_XE_VERSION ">" PCMK_OCF_VERSION
                     "</" PCMK_XE_VERSION ">\n", NULL);

    add_desc(s, PCMK_XE_LONGDESC, desc_long, NULL, "  ");
    add_desc(s, PCMK_XE_SHORTDESC, desc_short, NULL, "  ");

    g_string_append(s, "  <" PCMK_XE_PARAMETERS ">\n");

    for (int lpc = 0; lpc < len; lpc++) {
        const char *opt_name = option_list[lpc].name;
        const char *opt_type = option_list[lpc].type;
        const char *opt_values = option_list[lpc].values;
        const char *opt_default = option_list[lpc].default_value;
        const char *opt_desc_short = option_list[lpc].description_short;
        const char *opt_desc_long = option_list[lpc].description_long;

        // The standard requires long and short parameter descriptions
        CRM_ASSERT((opt_desc_short != NULL) || (opt_desc_long != NULL));

        if (opt_desc_short == NULL) {
            opt_desc_short = opt_desc_long;
        } else if (opt_desc_long == NULL) {
            opt_desc_long = opt_desc_short;
        }

        // The standard requires a parameter type
        CRM_ASSERT(opt_type != NULL);

        pcmk__g_strcat(s,
                       "    <" PCMK_XE_PARAMETER " "
                               PCMK_XA_NAME "=\"", opt_name, "\">\n", NULL);

        add_desc(s, PCMK_XE_LONGDESC, opt_desc_long, opt_values, "      ");
        add_desc(s, PCMK_XE_SHORTDESC, opt_desc_short, NULL, "      ");

        pcmk__g_strcat(s, "      <content type=\"", opt_type, "\"", NULL);
        if (opt_default != NULL) {
            pcmk__g_strcat(s, " default=\"", opt_default, "\"", NULL);
        }

        if ((opt_values != NULL) && (strcmp(opt_type, "select") == 0)) {
            char *str = strdup(opt_values);
            const char *delim = ", ";
            char *ptr = strtok(str, delim);

            g_string_append(s, ">\n");

            while (ptr != NULL) {
                pcmk__g_strcat(s, "        <option value=\"", ptr, "\" />\n",
                               NULL);
                ptr = strtok(NULL, delim);
            }
            g_string_append_printf(s, "      </content>\n");
            free(str);

        } else {
            g_string_append(s, "/>\n");
        }

        g_string_append(s, "    </" PCMK_XE_PARAMETER ">\n");
    }
    g_string_append(s,
                    "  </" PCMK_XE_PARAMETERS ">\n"
                    "</" PCMK_XE_RESOURCE_AGENT ">\n");

    return g_string_free(s, FALSE);
}

void
pcmk__validate_cluster_options(GHashTable *options,
                               pcmk__cluster_option_t *option_list, int len)
{
    for (int lpc = 0; lpc < len; lpc++) {
        cluster_option_value(options, option_list[lpc].is_valid,
                             option_list[lpc].name,
                             option_list[lpc].alt_name,
                             option_list[lpc].default_value);
    }
}
